#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later

import typing
import enum
import time
import select
import socket
import configparser
import socketserver
import base64
import json
import os
import threading

import users
import peers


class RelayCapture:
    """Gravar o que passa entre os dois consoles, quando o operador pedir.

    O relay é um cano: cada lado manda bytes, o outro recebe. Ninguém aqui
    interpreta nada disso, e esta classe também não -- ela guarda o que
    passou, na ordem em que passou, com a hora de cada pedaço. Interpretar é
    problema de quem for converter depois (a ideia que motivou isto é virar
    replay do Pokémon Stadium 2 / Kin Gin), e essa conversão não existe
    ainda. Gravar cru é o que permite escrevê-la sem precisar de outra
    partida.

    Desligado por padrão, e isso não é timidez: o arquivo é a partida de
    DUAS pessoas, não do operador. Ligar é uma decisão de quem administra, e
    quem ligar deve saber que está guardando conversa de terceiros.

    Um arquivo por conexão, não um por partida. Cada handler do relay só vê
    UMA direção -- o que o console dele mandou -- porque é ele que lê desse
    socket. Juntar as duas metades num arquivo só exigiria dois threads
    escrevendo no mesmo lugar, com trava, para ganhar nada: cada registro
    leva hora absoluta, então o conversor intercala as duas metades por
    tempo, depois, sem pressa e sem trava.

    JSON Lines com o dado em base64. Cresce cerca de um terço sobre o
    binário e vale: uma troca de partida é pequena, e quem for escrever o
    conversor lê o arquivo com a biblioteca padrão de qualquer linguagem, em
    vez de descobrir um formato quadro a quadro que eu teria inventado.
    """

    def __init__(self, filename: str = ""):
        config = configparser.ConfigParser()
        if filename:
            config.read(filename)
        section = config["capture"] if "capture" in config else {}

        # O arquivo é o padrão; o painel do REON pode ligar por cima, e é
        # ele que o dono usa ("modo torneio"). Ver active().
        self.enabled = str(section.get("enabled", "no")).strip().lower() \
            in ("1", "yes", "true", "on")
        self.directory = str(section.get("directory", "captures")).strip()
        # Teto por sessão. Sem ele, um cliente que despeje dados sem parar
        # enche o disco do servidor -- e o disco cheio derruba o relay para
        # todo mundo, não só a gravação.
        try:
            self.max_bytes = int(section.get("max_bytes", 1 << 20))
        except (TypeError, ValueError):
            self.max_bytes = 1 << 20
        if self.max_bytes < 0:
            self.max_bytes = 0

    # Ligado AGORA, e não no arranque.
    #
    # O interruptor do painel é consultado a cada sessão, de propósito: o
    # dono liga o modo torneio no site e a próxima partida já grava, sem
    # reiniciar o relay e sem cortar partida de quem está jogando. Guardar o
    # valor do arranque seria repetir o erro que deixou o relay-policy dias
    # recusando correio com uma senha velha na memória.
    #
    # O config.ini continua valendo quando não há como perguntar ao painel
    # (sem banco do REON, sem a tabela, consulta falhando): é o padrão, não
    # um empate. Ligado no arquivo grava mesmo que o painel diga o contrário
    # -- quem tem acesso ao arquivo é o operador da máquina.
    def active(self, users_db=None) -> bool:
        if self.enabled:
            return True
        if users_db is None:
            return False
        return users_db.setting(SETTING_CAPTURE) == "1"

    def describe(self) -> str:
        teto = ("%d bytes" % self.max_bytes) if self.max_bytes else "sem teto"
        if self.enabled:
            return "on -> %s (max %s por sessão)" % (self.directory, teto)
        return ("off no arquivo; o painel pode ligar (%s) -> %s (max %s "
                "por sessão)" % (SETTING_CAPTURE, self.directory, teto))


class CaptureSession:
    """Um arquivo, uma conexão. Nada aqui pode derrubar o relay.

    Toda falha de disco é engolida depois de uma linha no log: gravar é
    recurso auxiliar, e uma partida entre duas pessoas não pode acabar
    porque o diretório de captura ficou cheio ou sem permissão.
    """

    _lock = threading.Lock()

    def __init__(self, capture: RelayCapture, log, role: str,
                 my_number: str, pair_number: str, device_id: str,
                 ligado: bool = False):
        self._log = log
        self._file = None
        self._written = 0
        self._max = capture.max_bytes
        self._truncated = False
        self._start = time.time()

        if not ligado:
            return

        try:
            # exist_ok: dois consoles ligando ao mesmo tempo criam o
            # diretório na mesma fração de segundo.
            os.makedirs(capture.directory, exist_ok=True)
            # O nome já diz o par e o papel, para as duas metades de uma
            # partida serem óbvias numa listagem por ordem alfabética.
            nome = "%s-%s-%s-%s.jsonl" % (
                time.strftime("%Y%m%dT%H%M%S", time.gmtime(self._start)),
                self._sane(my_number), self._sane(pair_number), role)
            caminho = os.path.join(capture.directory, nome)
            # O lock é só para não haver duas aberturas do mesmo nome no
            # mesmo segundo; a escrita em si é de um thread só.
            with CaptureSession._lock:
                self._file = open(caminho, "x", encoding="utf-8")
            self._emit({
                "type": "start",
                "time": self._start,
                "role": role,
                "number": my_number,
                "pair_number": pair_number,
                "device_id": device_id,
                # Quem for converter precisa saber o que este arquivo NÃO é:
                # é uma direção só, e o relay não interpretou nada.
                "note": "one direction only: bytes this console sent. "
                        "Merge with the peer file by absolute time.",
            })
            self._log("Capture: gravando em", caminho)
        except OSError as e:
            self._file = None
            self._log("Capture: indisponível:", e)

    @staticmethod
    def _sane(value: str) -> str:
        return "".join(c for c in str(value) if c.isalnum()) or "unknown"

    def _emit(self, obj) -> None:
        if self._file is None:
            return
        try:
            self._file.write(json.dumps(obj) + "\n")
            self._file.flush()
        except OSError as e:
            self._log("Capture: escrita falhou:", e)
            self.close("write-error")

    def data(self, payload: bytes) -> None:
        if self._file is None:
            return

        # O corte é dito UMA vez, e é dito sempre -- inclusive quando o teto
        # é atingido exatamente no fim de um pedaço, que é o caso em que a
        # primeira versão disto cortava calada. Arquivo truncado em silêncio
        # faria alguém depurar uma partida que nunca terminou.
        pedaco = payload
        if self._max:
            espaco = self._max - self._written
            if espaco <= 0:
                self._marcar_truncado()
                return
            if len(pedaco) > espaco:
                pedaco = pedaco[:espaco]

        self._written += len(pedaco)
        self._emit({"type": "data", "time": time.time(),
                    "b64": base64.b64encode(pedaco).decode("ascii")})

        if self._max and self._written >= self._max and len(payload) > len(pedaco):
            self._marcar_truncado()

    def _marcar_truncado(self) -> None:
        if self._truncated:
            return
        self._truncated = True
        self._emit({"type": "truncated", "time": time.time(),
                    "limit": self._max})
        self._log("Capture: teto de %d bytes atingido; o resto desta sessão "
                  "não foi gravado" % self._max)

    def close(self, reason: str = "end") -> None:
        if self._file is None:
            return
        arquivo, self._file = self._file, None
        try:
            arquivo.write(json.dumps({
                "type": "end", "time": time.time(),
                "reason": reason, "bytes": self._written}) + "\n")
            arquivo.close()
        except OSError:
            pass


class RelayLimits:
    """How long a connection may do nothing before it is dropped.

    Two different problems, and they need different answers.

    A socket that is *dead* -- the cable pulled, the console switched off,
    a NAT mapping expired -- sends no FIN and no RST. The kernel never
    finds out on its own, so a blocking recv or poll on it waits forever.
    That is what TCP keepalive is for, and it cannot cost a live player
    anything: it only ever discovers connections that are already gone.

    A socket that is *alive but idle* is a judgement call, not a fact.
    Somebody waiting for a friend to call is idle on purpose, and a
    timeout there ends a session a person is actually having. So those
    are configured, default to off, and are the operator's decision.

    The one exception is the handshake. A connection that has not said
    "MOBILE" yet is not a player; on a port the open internet can reach it
    is usually a scanner. Letting it hold a thread for as long as it likes
    is a way to run the relay out of threads with a netcat, so this one
    defaults to on.
    """

    def __init__(self, filename: str = ""):
        config = configparser.ConfigParser()
        if filename:
            config.read(filename)
        section = config["relay"] if "relay" in config else {}

        def seconds(key: str, default: int) -> int:
            try:
                value = int(section.get(key, default))
            except (TypeError, ValueError):
                return default
            return value if value > 0 else 0

        # On by default: cannot end a session anybody is having.
        self.handshake = seconds("handshake_timeout", 15)
        self.keepalive = str(section.get("keepalive", "yes")).strip().lower() \
            not in ("0", "no", "false", "off")
        self.keepalive_idle = seconds("keepalive_idle", 60)
        self.keepalive_interval = seconds("keepalive_interval", 15)
        self.keepalive_count = seconds("keepalive_count", 4)

        # Off by default: each of these can end a live session, so turning
        # one on is the operator saying they want that.
        self.idle = seconds("idle_timeout", 0)
        self.wait = seconds("wait_timeout", 0)
        self.relay = seconds("relay_timeout", 0)

    def describe(self) -> str:
        def show(value: int) -> str:
            return "%ds" % value if value else "off"
        return ("keepalive %s (%ds/%ds x%d), handshake %s, idle %s, "
                "wait %s, relay %s") % (
            "on" if self.keepalive else "off",
            self.keepalive_idle, self.keepalive_interval, self.keepalive_count,
            show(self.handshake), show(self.idle),
            show(self.wait), show(self.relay))

# The client states its protocol version in the first byte of the handshake
# and every command; the server answers in the same version, per
# connection. Two are spoken:
#
#   0  [0]"MOBILE" has_token(1) [token(16)]
#   1  [1]"MOBILE" has_token(1) [token(16)] has_device(1) [device_id(8)]
#
# device_id is the adapter's device-auth identity (the 8 bytes behind the
# `device=` field and the pairing code on REON's "connected devices"
# page). It lets the relay honour a per-device block for peer-to-peer
# calls, which never log in to the ISP and so never reach device-auth. It
# is not signed: the token proves the account, the device is a label
# inside it, and a rebuilt client can send whatever it likes -- the block
# is cooperative, like the rest of device-auth. A hostile or lost device
# is dealt with by changing the log-in password and revoking every device.
#
# Version 0 stays accepted, and logged, until every adapter has shipped
# version 1; then it is cut, since an old client bypasses the block by
# construction. A rejected version-1 client is told why in one byte
# (MobileRelayHandshakeReason) before the socket closes; version 0 gets the
# bare close it always got.
PROTOCOL_VERSION = 0
PROTOCOL_VERSION_DEVICE = 1
PROTOCOL_VERSIONS = (PROTOCOL_VERSION, PROTOCOL_VERSION_DEVICE)
handshake_word = b"MOBILE"
handshake_magic = bytes([PROTOCOL_VERSION]) + handshake_word

# Device id the relay assumes when a client sends none: REON's row for the
# account's unnamed device, the same one device-auth uses when `device=`
# is absent. Blocking that row on the site then reaches these clients too.
# O interruptor que o painel do REON liga ("modo torneio"), em sys_settings.
# O nome é o mesmo dos dois lados e não pode divergir: o painel grava por
# aqui, o relay lê por aqui.
SETTING_CAPTURE = "relay_capture"

DEVICE_ID_NONE = ""
DEVICE_ID_SIZE = 8

# How long any wait-for-something poll blocks before looking around. It is
# not a timeout -- it is the granularity at which one can be noticed, and
# the reason a poll with no deadline still wakes up to see that keepalive
# has condemned the socket underneath it.
POLL_SLICE_MS = 1000

# Version 0 handshakes were accepted, and logged, while the adapters
# shipped version 1; cut on 2026-09-09 once mGBA, libmobile-bgb and
# PicoAdapterGB all carried it. A version 0 client now gets the bare close
# it always got on a bad handshake. Flip back only for a deliberate
# transition, never to accommodate one stale device: an old client is a
# bypass of the per-device block by construction.
ACCEPT_VERSION_0 = False


class RelayKicked(Exception):
    """Ended by the server, deliberately, because a limit was reached.

    Raised instead of ConnectionResetError so it can be caught and logged as
    one line. Letting a timeout escape as an unhandled exception drops the
    connection just as well, but socketserver answers it with a traceback --
    so the log ends up full of stack traces for the one thing that is
    working exactly as configured.
    """


class MobileRelayHandshakeReason(enum.IntEnum):
    TOKEN = 1
    BLOCKED = 2


def pairing_code(device_id: str) -> str:
    # The form REON's "connected devices" page shows: first 8 hex digits,
    # upper case, hyphen in the middle; "----" for the unnamed device.
    if not device_id:
        return "----"
    return device_id[:4].upper() + "-" + device_id[4:8].upper()


class MobileRelayCommand(enum.IntEnum):
    CALL = 0
    WAIT = enum.auto()
    GET_NUMBER = enum.auto()


class MobileRelayCallResult(enum.IntEnum):
    ACCEPTED = 0
    INTERNAL = enum.auto()
    BUSY = enum.auto()
    UNAVAILABLE = enum.auto()


class MobileRelayWaitResult(enum.IntEnum):
    ACCEPTED = 0
    INTERNAL = enum.auto()


# Replaced from config.ini at startup. Built here too so that importing this
# module -- a test, a REPL -- cannot fail on a name that only __main__ sets.
g_limits = RelayLimits()


class MobileRelay(socketserver.BaseRequestHandler):
    user_new: bool
    user: typing.Optional[peers.MobilePeer]
    users: users.MobileUserDatabase
    peers: peers.MobilePeers
    limits: RelayLimits
    capture: RelayCapture
    role: str
    version: int
    device_id: str
    probe: bool
    timed_out: bool

    def setup(self) -> None:
        self.users = g_users
        self.peers = g_peers
        self.limits = g_limits
        self.capture = g_capture
        # Quem ligou e quem esperou. Só serve para nomear a metade de
        # cada gravação; o relay em si trata os dois lados igual.
        self.role = "peer"
        self.user = None
        self.user_new = False
        self.version = PROTOCOL_VERSION
        self.device_id = DEVICE_ID_NONE
        self.probe = False
        self.timed_out = False

        # Keepalive first, because everything below depends on the kernel
        # being willing to tell us the other end is gone. Without it a
        # console that was switched off mid-session leaves this thread in a
        # blocking read that never returns -- and, worse, leaves the account
        # number in the connected set, where MobilePeers.connect() refuses
        # to let that same account log in again until the process restarts.
        if self.limits.keepalive:
            try:
                sock = self.request
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                for option, value in (
                    ("TCP_KEEPIDLE", self.limits.keepalive_idle),
                    ("TCP_KEEPINTVL", self.limits.keepalive_interval),
                    ("TCP_KEEPCNT", self.limits.keepalive_count),
                ):
                    # Not every platform names all three; the plain
                    # SO_KEEPALIVE above still applies with system defaults.
                    if hasattr(socket, option) and value:
                        sock.setsockopt(socket.IPPROTO_TCP,
                                        getattr(socket, option), value)
            except OSError as e:
                self.log("Keepalive unavailable:", e)

        # A connection that has not identified itself yet gets a short leash.
        if self.limits.handshake:
            self.request.settimeout(self.limits.handshake)

    def finish(self) -> None:
        if self.user:
            self.peers.disconnect(self.user)

    def log(self, *args) -> None:
        print(self.client_address, *args)

    def recv_exact(self, size: int) -> bytes:
        data = b""
        while len(data) < size:
            try:
                chunk = self.request.recv(size - len(data))
            except socket.timeout:
                # Out of patience. Report it as a short read, the same shape
                # every caller here already handles, and remember why so the
                # log can say "timed out" instead of "login failed".
                self.timed_out = True
                break
            if not chunk:
                break
            data += chunk
        return data

    def refuse_handshake(self, reason: MobileRelayHandshakeReason) -> bool:
        # Version 1 clients learn why before the close, so a blocked device
        # can say "blocked" rather than "authentication failed".
        if self.version >= PROTOCOL_VERSION_DEVICE:
            try:
                self.request.send(bytes([reason]))
            except OSError:
                pass
        return False

    def recv_handshake(self) -> bool:
        handshake = self.recv_exact(1 + len(handshake_word))
        if len(handshake) != 1 + len(handshake_word):
            # Nothing at all, then a clean close: that is a port probe, not a
            # login that failed. REON's own service-status check is one of
            # these every five minutes, and calling it "Login failed" filled
            # the journal with a failure that never happened -- which is
            # exactly the line somebody would be scanning for when a real
            # login starts failing.
            self.probe = len(handshake) == 0 and not self.timed_out
            return False
        if handshake[1:] != handshake_word:
            return False
        self.version = handshake[0]
        if self.version not in PROTOCOL_VERSIONS:
            return False
        if self.version == PROTOCOL_VERSION and not ACCEPT_VERSION_0:
            self.log("Quit: Protocol version 0 no longer accepted")
            return False

        has_token, = self.recv_exact(1) or (None,)
        self.user_new = False
        if has_token == 0:
            # Live negotiation of a fresh token has been retired -- tokens
            # are now provisioned at account signup and shipped in
            # config.bin (or set manually, both already supported before
            # this). A device connecting without one is on a config.bin
            # from before that, or never configured one; reject rather
            # than mint an anonymous, account-less token.
            return self.refuse_handshake(MobileRelayHandshakeReason.TOKEN)
        elif has_token == 1:
            token = self.recv_exact(16)
            if len(token) != 16:
                return False
        else:
            return False

        # Version 1 names the device; version 0, or a version 1 client with
        # no identity yet, is the account's unnamed device.
        self.device_id = DEVICE_ID_NONE
        if self.version >= PROTOCOL_VERSION_DEVICE:
            has_device, = self.recv_exact(1) or (None,)
            if has_device == 1:
                device = self.recv_exact(DEVICE_ID_SIZE)
                if len(device) != DEVICE_ID_SIZE:
                    return False
                self.device_id = device.hex()
            elif has_device != 0:
                return False

        with self.users:
            account = self.users.lookup_token(token)
            if account is None:
                return self.refuse_handshake(MobileRelayHandshakeReason.TOKEN)
            blocked = self.users.device_blocked(account.user_id,
                                                self.device_id)

        # Who is knocking, before the answer: the owner reads this log to
        # see which devices still speak version 0 once the cut is due.
        self.log("Handshake v%d device %s user_id=%s%s" % (
            self.version, pairing_code(self.device_id), account.user_id,
            " (no device id, update pending)"
            if self.version < PROTOCOL_VERSION_DEVICE else ""))

        if blocked:
            self.log("Quit: Device %s blocked on the site" %
                     pairing_code(self.device_id))
            return self.refuse_handshake(MobileRelayHandshakeReason.BLOCKED)

        user = self.peers.connect(token)
        if user is None:
            # Token vanished meanwhile, or the number is already connected.
            return False

        user.sock = self.request
        self.user = user
        return True

    def send_handshake(self) -> None:
        buffer = bytearray([self.version]) + handshake_word
        buffer.append(self.user_new)
        if self.user_new:
            buffer += self.user.get_token()
        self.request.send(buffer)

    def recv_call(self) -> typing.Optional[str]:
        number_len, = self.request.recv(1)
        if not number_len:
            return None
        number = self.request.recv(number_len).decode()
        return number

    def send_call(self, result: MobileRelayCallResult) -> None:
        buffer = bytearray([self.version, MobileRelayCommand.CALL])
        buffer.append(result)
        self.request.send(buffer)

    def handle_call(self) -> bool:
        number = self.recv_call()
        if number is None:
            return False
        self.log("Command: CALL %s" % number)
        self.role = "caller"

        poller = select.poll()
        poller.register(self.request, select.POLLIN | select.POLLPRI)

        # Find an available peer with the correct phone number
        user = None
        timer = time.time()
        while True:
            # Get peer attached to number
            if user is None:
                user = self.peers.dial(number)

            # Try to call the peer
            if user is not None:
                res = self.user.call(user)
                if res == 1:
                    break
                elif res == 2:
                    self.send_call(MobileRelayCallResult.BUSY)
                    return False
                elif res == 3:
                    self.send_call(MobileRelayCallResult.INTERNAL)
                    raise ConnectionResetError
                elif res != 0:
                    self.send_call(MobileRelayCallResult.INTERNAL)
                    raise ConnectionResetError

            # Time out after a while
            if (time.time() - timer) >= 30:
                if user is not None:
                    self.send_call(MobileRelayCallResult.BUSY)
                else:
                    self.send_call(MobileRelayCallResult.UNAVAILABLE)
                return False

            # If the client sends anything, we can still back out
            if poller.poll(100):
                return False
        self.send_call(MobileRelayCallResult.ACCEPTED)
        self.user.call_ready()
        return True

    def send_wait(self, result: MobileRelayWaitResult,
                  number: str = "") -> None:
        encnum = number.encode()
        buffer = bytearray([self.version, MobileRelayCommand.WAIT])
        buffer.append(result)
        buffer.append(len(encnum))
        buffer += encnum
        self.request.send(buffer)

    def handle_wait(self) -> bool:
        self.log("Command: WAIT")
        self.role = "receiver"

        poller = select.poll()
        poller.register(self.user.sock, select.POLLIN)
        poller.register(self.user.rpipe, select.POLLIN)

        # Set self into waiting state, break out when called
        #
        # This poll used to have no timeout of any kind, so a console that
        # went away while waiting for a call sat here forever -- holding a
        # thread, holding its number in the connected set, and so keeping
        # that account from logging in again.
        deadline = time.time() + self.limits.wait if self.limits.wait else None
        while True:
            res = self.user.wait()
            if res == 1:
                break
            elif res != 0:
                self.send_wait(MobileRelayWaitResult.INTERNAL)
                raise ConnectionResetError

            # Wait for any event. Poll in slices even with no deadline, so
            # a dead socket is noticed once keepalive has condemned it
            # rather than only when something happens to arrive.
            events = poller.poll(POLL_SLICE_MS)

            # Break out if any data or error is available in the socket
            if any(fd == self.user.sock.fileno() for fd, _ in events):
                if not self.user.wait_stop():
                    raise ConnectionResetError
                return False

            if deadline is not None and time.time() >= deadline:
                # There is no "timed out" in MobileRelayWaitResult, and
                # inventing one by sending INTERNAL would tell the adapter
                # the server broke. Dropping the connection is what a kick
                # is, and it is the truthful one: stop waiting, then close.
                self.user.wait_stop()
                raise RelayKicked("Waited %ds without a call"
                                  % self.limits.wait)
        self.send_wait(MobileRelayWaitResult.ACCEPTED,
                       self.user.get_pair_number())
        self.user.wait_ready()
        return True

    def send_get_number(self) -> None:
        number = self.user.get_number().encode()
        buffer = bytearray([self.version, MobileRelayCommand.GET_NUMBER])
        buffer.append(len(number))
        buffer += number
        self.request.send(buffer)

    def handle_get_number(self) -> None:
        self.log("Command: GET_NUMBER")
        self.send_get_number()

    def handle_relay(self) -> None:
        # Wait until peer is ready to receive data
        poller = select.poll()
        poller.register(self.user.rpipe, select.POLLIN)
        if not poller.poll(1000):
            raise ConnectionResetError
        if self.user.accept() != 1:
            raise ConnectionResetError

        self.log("Starting relay")
        # Uma gravação por conexão, com o par identificado no nome. Aberta
        # aqui e não no handshake: antes disto não há partida, e um arquivo
        # por scanner que bate na porta não serve a ninguém.
        # A consulta ao painel vai DENTRO do contexto do banco, como a de
        # bloqueio de aparelho no handshake: fora dele a conexão nem existe,
        # e a leitura falharia toda sessão -- caindo no valor do arquivo com
        # uma linha de erro no log, ou seja, o painel nunca ligaria nada.
        with self.users:
            ligado = self.capture.active(self.users)
        gravacao = CaptureSession(
            self.capture, self.log, self.role,
            self.user.get_number(), self.user.get_pair_number(),
            self.device_id, ligado)
        # TODO: Fork out a process, close sockets in parent
        #       This helps avoid the GIL and would reduce issues
        #        with many simultaneous clients (assuming no directed abuse).
        try:
            mine = self.request
            pair = self.user.get_pair_socket()

            poller = select.poll()
            poller.register(mine, select.POLLIN | select.POLLPRI)
            poller.register(pair, select.POLLRDHUP)
            quiet_since = time.time()
            while True:
                events = poller.poll(POLL_SLICE_MS)

                if not events:
                    if self.limits.relay and \
                            time.time() - quiet_since >= self.limits.relay:
                        self.log("Quit: No traffic for %ds"
                                 % self.limits.relay)
                        return
                    continue
                quiet_since = time.time()

                for fd, event in events:
                    if fd == mine.fileno():
                        data = mine.recv(1024)
                        if not data:
                            return
                        # O envio ao par vem PRIMEIRO. Gravar é auxiliar, e
                        # nada nele deve entrar entre o que um console
                        # mandou e o que o outro recebe.
                        pair.send(data)
                        gravacao.data(data)
                    elif fd == pair.fileno() and event & select.POLLRDHUP:
                        return
        except socket.timeout:
            # Only reachable with an idle timeout configured, which puts the
            # socket in timeout mode: the pair stopped draining what we send.
            # Ending the relay is the right answer either way.
            self.log("Quit: Peer stopped reading")
        except ConnectionResetError:
            # There's a billion normal circumstances in which a client can
            #  cause this error instead of returning an empty buffer.
            # We don't care about them at this point.
            pass
        finally:
            gravacao.close()
            self.log("Quit: Disconnect")

    def handle(self) -> None:
        self.log("Connected")

        if not self.recv_handshake():
            if self.timed_out:
                self.log("Quit: Silent for %ds" % self.limits.handshake)
            elif self.probe:
                self.log("Quit: Port probe")
            else:
                self.log("Quit: Login failed")
            return
        self.send_handshake()
        self.log("Logged in as %s" % self.user.get_number(),
                 "(new user)" if self.user_new else "")

        # Past the handshake this is a player, not a scanner. The leash
        # becomes whatever the operator configured for an idle session --
        # by default none at all, and then the socket goes back to blocking
        # so nothing below has to know about timeouts.
        self.request.settimeout(self.limits.idle or None)

        try:
            self.command_loop()
        except RelayKicked as reason:
            self.log("Quit:", reason)

    def command_loop(self) -> None:
        while True:
            try:
                data = self.request.recv(2)
            except socket.timeout:
                raise RelayKicked("Idle for %ds" % self.limits.idle)
            if len(data) < 2:
                self.log("Quit: Disconnect")
                return

            version, command = data
            if version != self.version:
                self.log("Quit: Invalid command")
                return

            if command == MobileRelayCommand.CALL:
                if self.handle_call():
                    return self.handle_relay()
            elif command == MobileRelayCommand.WAIT:
                if self.handle_wait():
                    return self.handle_relay()
            elif command == MobileRelayCommand.GET_NUMBER:
                self.handle_get_number()
            else:
                self.log("Quit: Invalid command")
                return


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True


if __name__ == "__main__":
    HOST, PORT = "", 31227
    g_users = users.MobileUserDatabase("config.ini")
    g_peers = peers.MobilePeers(g_users)
    g_limits = RelayLimits("config.ini")
    g_capture = RelayCapture("config.ini")
    print("Limits:", g_limits.describe())
    print("Capture:", g_capture.describe())
    with Server((HOST, PORT), MobileRelay) as server:
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            server.shutdown()
