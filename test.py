#!/usr/bin/env python3

import time
import typing
import unittest
import socket
import users
from server import PROTOCOL_VERSION, PROTOCOL_VERSION_DEVICE, \
    handshake_word, handshake_magic, MobileRelayCommand, \
    MobileRelayCallResult, MobileRelayWaitResult, MobileRelayHandshakeReason, \
    DEVICE_ID_SIZE

# Duas coisas que existiam quando esta suíte foi escrita e não existem mais.
# Ela falhava em 5 dos 6 testes por causa delas, e não por defeito no relay:
#
#   - a versão 0 do protocolo deixou de ser aceita (ACCEPT_VERSION_0). O que
#     se fala hoje é a versão 1, a que leva o id do aparelho;
#   - a negociação de token ao vivo foi aposentada. Um cliente sem token não
#     ganha mais um: token é provisionado no cadastro e entregue dentro do
#     mobile_config.bin. Por isso os testes agora CRIAM contas antes de
#     conectar, pelo mesmo caminho que o cadastro usa (MobileUserDatabase.new).
#
# Isso dá à suíte um efeito colateral que ela não tinha: ela escreve no banco
# do relay. Rode contra um banco de teste -- o config.example.ini traz o
# [sqlite] justamente para isso -- e não contra o banco que atende gente.

DB: typing.Optional[users.MobileUserDatabase] = None
CONTADOR = 0


def setUpModule() -> None:
    global DB
    DB = users.MobileUserDatabase("config.ini")


def conta_nova() -> typing.Tuple[users.MobileUser, bytes]:
    """Uma conta recém-provisionada, com um id de aparelho só dela.

    Uma por cliente, e nunca reaproveitada dentro da execução. Não é
    desperdício: o relay recusa a MESMA conta conectada duas vezes, e um
    cliente que fecha leva um instante para o servidor soltar o número dele.
    Compartilhar conta entre testes faz a suíte falhar conforme a ordem e a
    velocidade da máquina -- que foi exatamente o que aconteceu aqui antes
    desta mudança.
    """
    global CONTADOR
    CONTADOR += 1
    with DB:
        user = DB.new()
    assert user is not None, "não consegui criar conta de teste"
    # Id de aparelho derivado do contador: dois clientes com o mesmo id
    # seriam o mesmo aparelho para o servidor, e há regras por aparelho
    # (bloqueio) que não queremos exercitar por acaso.
    return user, bytes([CONTADOR & 0xFF]) * DEVICE_ID_SIZE


class MobileRelayClient:
    sock: typing.Optional[socket.socket]

    # O aparelho tem DEVICE_ID_SIZE bytes, não 16: mandar mais faz o servidor
    # ler o excedente como se fosse o próximo comando, e a conexão morre com
    # "Invalid command" logo depois de um login que deu certo.
    def __init__(self, token: typing.Optional[bytes] = None,
                 version: int = PROTOCOL_VERSION_DEVICE,
                 device: typing.Optional[bytes] = b"\x00" * DEVICE_ID_SIZE,
                 port: int = 31227):
        self.sock = None
        self.token = token
        self.version = version
        self.device = device
        self.port = port
        self.connect()

    def connect(self) -> None:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect(("127.0.0.1", self.port))

    def close(self) -> None:
        if self.sock:
            self.sock.close()
            self.sock = None

    def send_handshake(self) -> None:
        buffer = bytearray([self.version]) + handshake_word
        if self.token is not None:
            buffer.append(1)
            buffer += self.token
        else:
            buffer.append(0)
        if self.version >= PROTOCOL_VERSION_DEVICE:
            if self.device is not None:
                buffer.append(1)
                buffer += self.device
            else:
                buffer.append(0)
        self.sock.send(buffer)

    # Only for a version 1 client the server turned away: the one reason
    # byte it sends before closing, or None if the socket just closed.
    def recv_refusal(self) -> typing.Optional[MobileRelayHandshakeReason]:
        data = self.sock.recv(1)
        if not data:
            return None
        return MobileRelayHandshakeReason(data[0])

    def recv_handshake(self) -> typing.Optional[bytes]:
        handshake = self.sock.recv(1 + len(handshake_word))
        assert handshake == bytes([self.version]) + handshake_word
        new_token, = self.sock.recv(1)
        if new_token == 1:
            token = self.sock.recv(16)
            assert len(token) == 16
            self.token = token
            return token
        assert new_token == 0
        return None

    def send_call(self, number: str) -> None:
        encnum = number.encode()
        buffer = bytearray([self.version, MobileRelayCommand.CALL])
        buffer.append(len(encnum))
        buffer += encnum
        self.sock.send(buffer)

    def recv_call(self) -> MobileRelayCallResult:
        recv = self.sock.recv(3)
        assert recv[0] == self.version
        assert recv[1] == MobileRelayCommand.CALL
        return MobileRelayCallResult(recv[2])

    def send_wait(self) -> None:
        buffer = bytearray([self.version, MobileRelayCommand.WAIT])
        self.sock.send(buffer)

    def recv_wait(self) -> tuple[MobileRelayWaitResult, str]:
        recv = self.sock.recv(4)
        assert recv[0] == self.version
        assert recv[1] == MobileRelayCommand.WAIT
        assert recv[3] != 0
        number = self.sock.recv(recv[3])
        assert len(number) == recv[3]
        return MobileRelayWaitResult(recv[2]), number.decode()

    def send_get_number(self) -> None:
        buffer = bytearray([self.version, MobileRelayCommand.GET_NUMBER])
        self.sock.send(buffer)

    def recv_get_number(self) -> str:
        recv = self.sock.recv(3)
        assert recv[0] == self.version
        assert recv[1] == MobileRelayCommand.GET_NUMBER
        assert recv[2] != 0
        number = self.sock.recv(recv[2])
        assert len(number) == recv[2]
        return number.decode()


class Tests(unittest.TestCase):
    def cliente(self, **kwargs) -> MobileRelayClient:
        """Um cliente com conta própria, já conectado."""
        conta, aparelho = conta_nova()
        c = MobileRelayClient(token=conta.token, device=aparelho, **kwargs)
        c.conta = conta
        return c

    def test_token_provisionado(self):
        """Quem chega com um token válido entra, e NÃO recebe outro."""
        c = self.cliente()
        c.send_handshake()
        # None aqui quer dizer "nenhum token novo", que é o certo: o token
        # dele já é o que está no cadastro.
        self.assertIs(c.recv_handshake(), None)
        c.close()

    def test_token_ausente_recusado(self):
        """Sem token não se entra mais. A negociação ao vivo foi aposentada."""
        c = MobileRelayClient(token=None)
        c.send_handshake()
        self.assertEqual(c.recv_refusal(), MobileRelayHandshakeReason.TOKEN)
        c.close()

    def test_token_desconhecido_recusado(self):
        c = MobileRelayClient(token=b"\xff" * 16)
        c.send_handshake()
        self.assertEqual(c.recv_refusal(), MobileRelayHandshakeReason.TOKEN)
        c.close()

    def test_versao_0_recusada(self):
        """A versão 0 não é mais falada. O servidor fecha sem dizer por quê.

        Sem reason byte de propósito: quem fala a versão 0 não entende o
        campo que o explicaria, então o servidor apenas encerra.
        """
        conta, _ = conta_nova()
        c = MobileRelayClient(token=conta.token,
                              version=PROTOCOL_VERSION, device=None)
        c.send_handshake()
        self.assertIs(c.recv_refusal(), None)
        c.close()

    def test_conn(self):
        c1 = self.cliente()
        c1.send_handshake()
        self.assertIs(c1.recv_handshake(), None)
        c2 = self.cliente()
        c2.send_handshake()
        self.assertIs(c2.recv_handshake(), None)

        c1.send_get_number()
        num = c1.recv_get_number()
        c2.send_call(num)
        c1.send_wait()
        self.assertEqual(c2.recv_call(), MobileRelayCallResult.ACCEPTED)
        self.assertEqual(c1.recv_wait()[0], MobileRelayWaitResult.ACCEPTED)

        msg = b"hello"
        c1.sock.send(msg)
        c2.sock.send(msg)
        self.assertEqual(c2.sock.recv(16), msg)
        self.assertEqual(c1.sock.recv(16), msg)

        c1.close()
        c2.close()

    def test_numero_e_o_da_conta(self):
        """GET_NUMBER devolve o número provisionado, não um sorteado agora."""
        c = self.cliente()
        c.send_handshake()
        c.recv_handshake()
        c.send_get_number()
        self.assertEqual(c.recv_get_number(), c.conta.number)
        c.close()

    def test_disconnect_call(self):
        c = self.cliente()
        c.send_handshake()
        self.assertIs(c.recv_handshake(), None)
        c.send_call("1234")
        time.sleep(0.1)
        c.close()

    def test_disconnect_wait(self):
        c = self.cliente()
        c.send_handshake()
        self.assertIs(c.recv_handshake(), None)
        c.send_wait()
        time.sleep(0.1)
        c.close()

    def test_connerr(self):
        c = self.cliente()
        c.send_handshake()
        c.close()

    def test_connerr_relay(self):
        c1 = self.cliente()
        c1.send_handshake()
        self.assertIs(c1.recv_handshake(), None)
        c1.send_get_number()
        num = c1.recv_get_number()

        c2 = self.cliente()
        c2.send_handshake()
        self.assertIs(c2.recv_handshake(), None)

        c2.send_call(num)
        c1.send_wait()
        time.sleep(0.2)
        c1.close()
        c2.recv_call()
        c2.close()

if __name__ == '__main__':
    unittest.main(verbosity=2)
