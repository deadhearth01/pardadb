"""Database adapters. Each exposes the same tiny interface, so the engine never cares which DB it talks to."""
import hashlib
import os
import sqlite3

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SQLITE_PATH = os.environ.get("PARDADB_SQLITE", os.path.join(HERE, "bank_demo.sqlite"))
READER_FILE = os.path.join(HERE, ".mysql_reader")


def _reader_password():
    if os.environ.get("PARDADB_MYSQL_PASSWORD") is not None:
        return os.environ["PARDADB_MYSQL_PASSWORD"]
    if os.path.exists(READER_FILE):
        with open(READER_FILE) as f:
            return f.read().strip()
    return ""


MYSQL = dict(
    host=os.environ.get("PARDADB_MYSQL_HOST", "127.0.0.1"),
    user=os.environ.get("PARDADB_MYSQL_USER", "pardadb_reader"),
    password=_reader_password(),
    database=os.environ.get("PARDADB_MYSQL_DB", "pardadb_demo"),
)


class Backend:
    dialect = None

    def tables(self):
        raise NotImplementedError

    def columns(self, table):
        raise NotImplementedError

    def execute(self, sql, params=()):
        cur = self.conn.cursor()
        cur.execute(sql, params)
        cols = [d[0] for d in cur.description] if cur.description else []
        return cols, [list(r) for r in cur.fetchall()]

    def schema(self):
        return {t: {c: "TEXT" for c in self.columns(t)} for t in self.tables()}

    def sample(self, table, column, n=50):
        q = self.quote
        _, rows = self.execute(f"SELECT {q(column)} FROM {q(table)} WHERE {q(column)} IS NOT NULL LIMIT {int(n)}")
        return [r[0] for r in rows]

    def fingerprint(self, table):
        """SHA-256 over every raw row: proves the underlying data never changed."""
        q = self.quote
        cols = self.columns(table)
        _, rows = self.execute(f"SELECT * FROM {q(table)} ORDER BY {q(cols[0])}")
        h = hashlib.sha256()
        for r in rows:
            h.update(repr([str(x) for x in r]).encode())
        return h.hexdigest()[:16], len(rows)


class SQLiteBackend(Backend):
    dialect = "sqlite"
    name = "SQLite"

    def __init__(self, path=SQLITE_PATH):
        # read-only connection: the engine physically cannot modify data
        self.conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)

    @staticmethod
    def quote(x):
        return '"' + x.replace('"', '""') + '"'

    def tables(self):
        _, rows = self.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
        return [r[0] for r in rows]

    def columns(self, table):
        _, rows = self.execute(f"PRAGMA table_info({self.quote(table)})")
        return [r[1] for r in rows]


class MySQLBackend(Backend):
    dialect = "mysql"
    name = "MySQL"

    def __init__(self, cfg=None):
        import pymysql

        cfg = cfg or dict(MYSQL, password=_reader_password())
        self.db = cfg["database"]
        self.conn = pymysql.connect(**cfg, autocommit=True)
        self.conn.cursor().execute("SET SESSION TRANSACTION READ ONLY")

    @staticmethod
    def quote(x):
        return "`" + x.replace("`", "``") + "`"

    def tables(self):
        _, rows = self.execute(
            "SELECT table_name FROM information_schema.tables WHERE table_schema=%s ORDER BY table_name", (self.db,)
        )
        return [r[0] for r in rows]

    def columns(self, table):
        _, rows = self.execute(
            "SELECT column_name FROM information_schema.columns WHERE table_schema=%s AND table_name=%s "
            "ORDER BY ordinal_position",
            (self.db, table),
        )
        return [r[0] for r in rows]


def connect(name):
    name = name.lower()
    if name == "sqlite":
        return SQLiteBackend()
    if name == "mysql":
        return MySQLBackend()
    raise SystemExit(f"unknown backend {name!r} (use sqlite or mysql)")
