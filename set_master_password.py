#!/usr/bin/env python3
"""
Set a new master password non-interactively.

rekey.py is the interactive path and wants the CURRENT password typed in by
its owner. This variant is for changes Alex makes on Dallas's behalf, where the
current key is already on disk and typing it would only create a second
exposure. Both keys come from environment variables so neither lands in `ps`
output.

    CW_CURRENT='...' CW_NEW='...' ./set_master_password.py

Verifies in both directions and refuses to leave the vault in a state where the
old key still works.
"""
import os
import shutil
import sys
import time
from datetime import datetime

HERE = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(HERE, 'passwords.db')
BACKUP_DIR = os.path.join(HERE, 'backups')

_VENV_PY = os.path.join(HERE, 'venv', 'bin', 'python')
if not os.environ.get('_CW_VENV_BOOTSTRAPPED') and os.path.exists(_VENV_PY):
    try:
        import pysqlcipher3  # noqa: F401
    except ImportError:
        os.environ['_CW_VENV_BOOTSTRAPPED'] = '1'
        os.execv(_VENV_PY, [_VENV_PY] + sys.argv)

from pysqlcipher3 import dbapi2 as sqlcipher

TABLES = ('folders', 'items', 'uris', 'fields')


def open_with(key):
    try:
        conn = sqlcipher.connect(DB_PATH)
        conn.execute("PRAGMA key = '" + key.replace("'", "''").replace('\x00', '') + "'")
        conn.execute("PRAGMA cipher_compatibility = 4")
        for table in TABLES:
            conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()
        return conn
    except Exception:
        return None


def counts(conn):
    return {t: conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
            for t in TABLES}


def main():
    current = os.environ.get('CW_CURRENT', '')
    new = os.environ.get('CW_NEW', '')
    if not current or not new:
        sys.exit("Set both CW_CURRENT and CW_NEW.")
    if current == new:
        sys.exit("CW_CURRENT and CW_NEW are identical; nothing to do.")
    if '\n' in new or '\n' in current:
        sys.exit("Keys must be single-line.")

    label = sys.argv[1] if len(sys.argv) > 1 else 'change'

    conn = open_with(current)
    if conn is None:
        sys.exit("CW_CURRENT does not open the vault. Nothing changed.")
    before = counts(conn)
    print(f"before: {before}")

    os.makedirs(BACKUP_DIR, exist_ok=True)
    stamp = datetime.now().strftime('%Y%m%d-%H%M%S')
    backup = os.path.join(BACKUP_DIR, f'passwords.db.pre-{label}.{stamp}')
    shutil.copy2(DB_PATH, backup)
    os.chmod(backup, 0o600)
    print(f"backup: {backup}")

    started = time.time()
    conn.execute("PRAGMA rekey = '" + new.replace("'", "''") + "'")
    conn.execute("SELECT COUNT(*) FROM items").fetchone()
    conn.commit()
    conn.close()
    print(f"rekeyed in {time.time() - started:.1f}s")

    check = open_with(new)
    if check is None:
        sys.exit(f"*** FAILED: new key does not open the vault.\n"
                 f"    Restore: cp {backup} {DB_PATH}")
    after = counts(check)
    check.close()
    print(f"after:  {after}")

    if after != before:
        sys.exit(f"*** FAILED: counts changed. Restore: cp {backup} {DB_PATH}")
    if open_with(current) is not None:
        sys.exit("*** WARNING: the old key still opens the vault.")

    print("\n[ok] new key opens the vault")
    print("[ok] old key no longer opens it")
    print("[ok] counts identical")
    return 0


if __name__ == '__main__':
    sys.exit(main())
