"""SQLite store; all user/password/token state is untracked local runtime data."""
import os
import contextlib
import pathlib
import sqlite3
import threading
import time
from server.security import password_hash
from server.models import username_ok, password_ok

_write_lock = threading.RLock()


def db_file():
    root = pathlib.Path(os.environ.get('SECURENET_DATA_DIR', 'runtime'))
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    return root / 'users.sqlite3'


@contextlib.contextmanager
def connect():
    conn = sqlite3.connect(str(db_file()), timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA busy_timeout=10000')
    conn.execute('PRAGMA foreign_keys=ON')
    try:
        with conn:
            yield conn
    finally:
        conn.close()


def initialize():
    with _write_lock, connect() as db:
        db.executescript('''
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY, pwd_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('user', 'admin')),
            totp_secret TEXT, pending_totp_secret TEXT, pending_since INTEGER,
            last_totp_step INTEGER NOT NULL DEFAULT -1
        );
        CREATE TABLE IF NOT EXISTS revoked (
            jti TEXT PRIMARY KEY, exp INTEGER NOT NULL
        );
        ''')
    try:
        os.chmod(db_file(), 0o600)
    except OSError:
        pass


def add_user(username, password, role):
    if not username_ok(username) or not password_ok(password) or role not in ('user','admin'):
        raise ValueError('invalid username/password/role')
    digest = password_hash(password)
    with _write_lock, connect() as db:
        db.execute('INSERT INTO users (username,pwd_hash,role) VALUES (?,?,?)', (username,digest,role))


def get_user(username):
    with connect() as db:
        row = db.execute('SELECT * FROM users WHERE username=?', (username,)).fetchone()
        return dict(row) if row is not None else None


def set_pending_totp(username, secret):
    with _write_lock, connect() as db:
        db.execute('UPDATE users SET pending_totp_secret=?,pending_since=? WHERE username=? AND totp_secret IS NULL', (secret,int(time.time()),username))


def confirm_totp(username, secret, otp_step):
    with _write_lock, connect() as db:
        cur=db.execute('''UPDATE users SET totp_secret=?,last_totp_step=?,pending_totp_secret=NULL,pending_since=NULL
                          WHERE username=? AND pending_totp_secret=? AND totp_secret IS NULL''', (secret,otp_step,username,secret))
        return cur.rowcount == 1


def consume_totp(username, step):
    with _write_lock, connect() as db:
        return db.execute('UPDATE users SET last_totp_step=? WHERE username=? AND last_totp_step<?', (step,username,step)).rowcount == 1


def revoke_token(jti, exp):
    with _write_lock, connect() as db:
        db.execute('INSERT OR IGNORE INTO revoked(jti,exp) VALUES (?,?)', (jti,exp))
        db.execute('DELETE FROM revoked WHERE exp<?', (int(time.time()),))


def is_revoked(jti):
    with connect() as db:
        return db.execute('SELECT 1 FROM revoked WHERE jti=?', (jti,)).fetchone() is not None
