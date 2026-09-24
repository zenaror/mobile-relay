# SPDX-License-Identifier: GPL-3.0-or-later

import typing
import secrets
import threading
import dataclasses
import contextlib
import configparser

import sqlite3
try:
    import MySQLdb
except ImportError as e:
    MySQLdb = e


@dataclasses.dataclass
class MobileUser:
    token: bytes
    number: str
    # REON account the token was provisioned for; None for a row minted by
    # the retired live negotiation, which belongs to nobody.
    user_id: typing.Optional[int] = None


class DatabaseSQLBase(threading.local):
    _args: dict

    def __init__(self):
        self._db = None
        self._module = None

    def __repr__(self):
        return self._module.__name__

    def _format(self, string):
        return string

    def init(self):
        self.connect()
        self.create()
        self.close()

    def create(self):
        with contextlib.closing(self._db.cursor()) as c:
            c.execute("""
                CREATE TABLE IF NOT EXISTS relay_users (
                    token      BINARY(16) NOT NULL UNIQUE,
                    number     VARCHAR(12) NOT NULL UNIQUE,
                    last_seen  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    registered INT,
                    user_id    INT NULL UNIQUE
                )
            """)
            # Pre-existing databases from before user_id existed: add it
            # without disturbing rows already provisioned by live
            # negotiation (those just stay NULL here, keyed by token only,
            # same as always). No UNIQUE here -- SQLite's ADD COLUMN can't
            # carry one, and uniqueness is already enforced by PHP only
            # ever assigning a user_id once, at account creation.
            #
            # "ADD COLUMN IF NOT EXISTS" isn't valid syntax on real MySQL
            # (only MariaDB accepts it) -- catch the duplicate-column error
            # instead, which is portable across both that and SQLite.
            try:
                c.execute("ALTER TABLE relay_users ADD COLUMN user_id INT NULL")
            except Exception as e:
                if "duplicate column" not in str(e).lower():
                    raise

            # Small single-purpose key/value table -- currently just holds
            # the live P2P connection count, kept in sync on every
            # connect()/disconnect() so REON's status page can read an
            # exact, real-time figure instead of approximating from
            # relay_users.last_seen.
            c.execute("""
                CREATE TABLE IF NOT EXISTS relay_stats (
                    name  VARCHAR(32) NOT NULL UNIQUE,
                    value INT NOT NULL
                )
            """)

    # Portable single-row upsert (works identically on MySQL and SQLite,
    # unlike "ON DUPLICATE KEY UPDATE" / "INSERT OR REPLACE") -- fine here
    # since relay_stats is tiny and write frequency is low.
    def set_stat(self, name, value):
        with contextlib.closing(self._db.cursor()) as c:
            c.execute(self._format("DELETE FROM relay_stats WHERE name = ?"), (name,))
            c.execute(self._format("INSERT INTO relay_stats(name, value) VALUES(?, ?)"), (name, value))

    def connect(self):
        if self._db is None:
            self._db = self._module.connect(**self._args)

    def close(self):
        self._db.close()
        self._db = None

    def commit(self, *args, **kwargs):
        return self._db.commit(*args, **kwargs)

    def insert_user(self, token, number):
        with contextlib.closing(self._db.cursor()) as c:
            c.execute(self._format("""
                INSERT INTO relay_users(token, number) VALUES(?, ?)
            """), (token, number))

    def update_timestamp(self, token, number):
        with contextlib.closing(self._db.cursor()) as c:
            c.execute(self._format("""
                UPDATE relay_users SET last_seen = CURRENT_TIMESTAMP
                WHERE token = ? AND number = ?
            """), (token, number))

    def lookup_token(self, token):
        with contextlib.closing(self._db.cursor()) as c:
            c.execute(self._format("""
                SELECT token, number, user_id FROM relay_users WHERE token = ?
            """), (token,))
            return c.fetchone()

    def lookup_number(self, number):
        with contextlib.closing(self._db.cursor()) as c:
            c.execute(self._format("""
                SELECT token, number, user_id FROM relay_users WHERE number = ?
            """), (number,))
            return c.fetchone()

    # Whether REON's "connected devices" page has this device of this
    # account blocked. Only the MySQL backend can answer (the table lives
    # in REON's own database, next to ours on the same server); anything
    # else has no opinion and the relay lets the device through, the same
    # fail-open the adapters apply when the server does not answer.
    #
    # Read-only on purpose: the handshake that carries the device id is not
    # signed, so it must never create rows (an account has 32 device slots)
    # nor touch "last seen" -- only a signed device-auth query may.
    def lookup_device_blocked(self, user_id, device_id):
        return None


class DatabaseMySQL(DatabaseSQLBase):
    def __init__(self, **kwargs):
        if isinstance(MySQLdb, ImportError):
            raise MySQLdb

        super().__init__()
        self._module = MySQLdb
        # Name of REON's database, holding sys_device_counter. Optional:
        # without it the relay never blocks a device. Popped so it does
        # not reach MySQLdb.connect().
        self._reon_db = kwargs.pop("reon_db", None)
        self._args = kwargs

    def _format(self, string):
        return string.replace("?", "%s")

    def has_device_blocks(self):
        return bool(self._reon_db)

    def lookup_device_blocked(self, user_id, device_id):
        if not self._reon_db:
            return None
        with contextlib.closing(self._db.cursor()) as c:
            c.execute(self._format("""
                SELECT blocked FROM `%s`.sys_device_counter
                WHERE user_id = ? AND device_id = ?
            """ % self._reon_db.replace("`", "")), (user_id, device_id))
            row = c.fetchone()
            if row is None:
                return None
            return bool(row[0])

    # Um interruptor que o painel do REON liga e desliga (sys_settings).
    # Lido a cada consulta, nunca guardado: o painel tem de fazer efeito sem
    # reiniciar o relay -- e um valor lido uma vez no arranque foi
    # exatamente a causa de o relay-policy passar dias recusando correio com
    # uma senha velha na memória.
    def lookup_setting(self, name):
        if not self._reon_db:
            return None
        with contextlib.closing(self._db.cursor()) as c:
            c.execute(self._format("""
                SELECT value FROM `%s`.sys_settings WHERE name = ?
            """ % self._reon_db.replace("`", "")), (name,))
            row = c.fetchone()
            return None if row is None else str(row[0])


class DatabaseSQLite(DatabaseSQLBase):
    def __init__(self, **kwargs):
        super().__init__()
        self._module = sqlite3
        self._args = kwargs


class MobileUserDatabase:
    _db: typing.Union[DatabaseMySQL, DatabaseSQLite]
    _new_write_lock: threading.Lock

    def __init__(self, filename):
        dbconfig = configparser.ConfigParser()
        dbconfig.read(filename)
        if "mysql" in dbconfig:
            self._db = DatabaseMySQL(**dbconfig["mysql"])
        elif "sqlite" in dbconfig:
            self._db = DatabaseSQLite(**dbconfig["sqlite"])
        else:
            self._db = DatabaseSQLite(database="users.db")
        print("Database:", self._db)
        if getattr(self._db, "has_device_blocks", lambda: False)():
            print("Device blocks: enabled (reon_db = %s)" % self._db._reon_db)
        else:
            print("Device blocks: disabled (no [mysql] reon_db configured)")

        self._db.init()
        self._new_write_lock = threading.Lock()

    def __enter__(self):
        self.connect()

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def connect(self) -> None:
        self._db.connect()

    def close(self) -> None:
        self._db.close()

    def _generate_token(self) -> typing.Optional[bytes]:
        for x in range(10):
            token = secrets.token_bytes(16)
            if self.lookup_token(token):
                continue
            return token
        return None

    def _generate_number(self) -> typing.Optional[str]:
        for x in range(10):
            number = "0" + "%09d" % secrets.randbelow(1000000000)
            if number.startswith("00"):
                continue
            if number.startswith("010"):
                continue
            if self.lookup_number(number):
                continue
            return number
        return None

    def new(self) -> typing.Optional[MobileUser]:
        with self._new_write_lock:
            token = self._generate_token()
            number = self._generate_number()
            if not token or not number:
                return None
            self._db.insert_user(token, number)
            self._db.commit()
        return MobileUser(token, number)

    def update(self, user: MobileUser) -> None:
        self._db.update_timestamp(user.token, user.number)
        self._db.commit()

    def set_connected_count(self, count: int) -> None:
        self._db.set_stat("connected_count", count)
        self._db.commit()

    def lookup_token(self, token: bytes) -> typing.Optional[MobileUser]:
        row = self._db.lookup_token(token)
        if not row:
            return None
        return MobileUser(row[0], row[1], row[2])

    def lookup_number(self, number: str) -> typing.Optional[MobileUser]:
        row = self._db.lookup_number(number)
        if not row:
            return None
        return MobileUser(row[0], row[1], row[2])

    # True only when REON has that (account, device) row and it is blocked.
    # Unknown row, unknown device, no account, or no REON database all
    # come back False: the relay only enforces a block it can see.
    def device_blocked(self, user_id: typing.Optional[int],
                       device_id: str) -> bool:
        if user_id is None:
            return False
        try:
            return self._db.lookup_device_blocked(user_id, device_id) is True
        except Exception as e:
            print("Device block lookup failed, letting through:", e)
            return False

    # O valor que o painel gravou, ou None quando não há como saber -- sem
    # banco do REON, sem a tabela, ou falha na consulta. Quem chama decide o
    # que fazer com o None, e aqui isso sempre significa "siga o config.ini".
    def setting(self, name: str) -> typing.Optional[str]:
        try:
            return getattr(self._db, "lookup_setting", lambda n: None)(name)
        except Exception as e:
            print("Setting lookup failed (%s), using the file:" % name, e)
            return None
