#!/usr/bin/env python3
"""
Re-encrypt passwords.db under a new master password.

You only ever type your CURRENT master password. The new one is read from a
0600 file so a long random passphrase never passes through your keyboard, a
terminal history, or a shoulder-surfer.

Before anything changes, this makes a timestamped backup and refuses to run
unless the current password actually opens the database. After rekeying it
verifies that the NEW key works AND that the old key no longer does, so a
silent half-failure cannot leave you thinking you are protected when you are not.
"""
import os
import sys

# Re-exec into the local venv before importing anything from it.
#
# The `#!/usr/bin/env python3` shebang resolves to /usr/bin/python3, which has
# no pysqlcipher3 -- running this directly died with ModuleNotFoundError even
# though the venv sitting next to it was perfectly healthy. A shebang cannot
# expand `venv/bin/python`, so bootstrap it here.
#
# Note: do NOT compare os.path.realpath(sys.executable) against the venv
# interpreter. venv/bin/python symlinks through to /usr/bin/python3.12, so both
# resolve to the same file and the comparison reports "already in the venv"
# while pysqlcipher3 is still unimportable. Ask whether the module imports
# instead, and set a sentinel so a broken venv cannot cause an exec loop.
_VENV_PY = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        'venv', 'bin', 'python')
if not os.environ.get('_CW_VENV_BOOTSTRAPPED') and os.path.exists(_VENV_PY):
    try:
        import pysqlcipher3  # noqa: F401
    except ImportError:
        os.environ['_CW_VENV_BOOTSTRAPPED'] = '1'
        os.execv(_VENV_PY, [_VENV_PY] + sys.argv)

import getpass
import shutil
import time
from datetime import datetime

from pysqlcipher3 import dbapi2 as sqlcipher

HERE = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(HERE, 'passwords.db')
BACKUP_DIR = os.path.join(HERE, 'backups')
NEW_PASSWORD_FILE = os.path.expanduser(
    '~/Private/cipher-warden-master-password.txt')


def try_open(key):
    """Return a connection if `key` unlocks the db, else None."""
    try:
        conn = sqlcipher.connect(DB_PATH)
        escaped = key.replace("'", "''").replace('\x00', '')
        conn.execute(f"PRAGMA key = '{escaped}'")
        conn.execute("PRAGMA cipher_compatibility = 4")
        conn.execute("SELECT COUNT(*) FROM folders").fetchone()
        conn.row_factory = sqlcipher.Row
        return conn
    except Exception:
        return None


def read_new_password():
    """Return the password staged in NEW_PASSWORD_FILE -- and nothing else.

    The staged file carries a human-readable preamble above the password.
    This used to do `fh.read().strip()`, which trims whitespace from the ends
    of the WHOLE file and hands back every header line too. rekey.py then
    re-encrypted the vault under that multi-line string, and the real password
    would never have worked at the login prompt. Take the last non-empty line.
    """
    if not os.path.exists(NEW_PASSWORD_FILE):
        sys.exit(f"New-password file not found: {NEW_PASSWORD_FILE}")
    mode = os.stat(NEW_PASSWORD_FILE).st_mode & 0o777
    if mode & 0o077:
        sys.exit(f"Refusing: {NEW_PASSWORD_FILE} is mode {mode:o}, "
                 f"expected 600. Run: chmod 600 {NEW_PASSWORD_FILE}")
    with open(NEW_PASSWORD_FILE) as fh:
        lines = fh.read().splitlines()
    non_empty = [line.strip() for line in lines if line.strip()]
    if not non_empty:
        sys.exit(f"Refusing: {NEW_PASSWORD_FILE} has no password on it.")
    value = non_empty[-1]
    if len(value) < 20:
        sys.exit(f"Refusing: staged new password is only {len(value)} chars.")
    # A real password is one line. Anything else means the file is not the
    # staged format we expect, and guessing here would re-key the vault wrong.
    if len(non_empty) != 1 and value == lines[0].strip():
        sys.exit(f"Refusing: could not identify the password line in "
                 f"{NEW_PASSWORD_FILE}.")
    return value


def main():
    if not os.path.exists(DB_PATH):
        sys.exit(f"No database at {DB_PATH}")

    print("=" * 62)
    print("Cipher Warden -- master password change")
    print("=" * 62)

    current = getpass.getpass("\nEnter your CURRENT master password: ")
    if not current:
        sys.exit("No password entered.")

    conn = try_open(current)
    if conn is None:
        sys.exit("\nThat password does not open the database. "
                 "Nothing has been changed.")
    folders = conn.execute("SELECT COUNT(*) FROM folders").fetchone()[0]
    items = conn.execute("SELECT COUNT(*) FROM items").fetchone()[0]
    print(f"\nVerified. Vault currently holds {folders} folders / {items} items.")
    conn.close()

    new = read_new_password()
    if new == current:
        sys.exit("\nThe staged new password is identical to the current one. "
                 "Nothing changed.")

    os.makedirs(BACKUP_DIR, exist_ok=True)
    stamp = datetime.now().strftime('%Y%m%d-%H%M%S')
    backup = os.path.join(BACKUP_DIR, f'passwords.db.pre-rekey.{stamp}')
    shutil.copy2(DB_PATH, backup)
    os.chmod(backup, 0o600)
    print(f"\nBackup written: {backup}")

    print("\nRe-encrypting. This rewrites the whole file; do not interrupt.")
    started = time.time()
    conn = try_open(current)
    escaped_new = new.replace("'", "''").replace('\x00', '')
    conn.execute(f"PRAGMA rekey = '{escaped_new}'")
    conn.execute("SELECT COUNT(*) FROM items").fetchone()
    conn.commit()
    conn.close()
    print(f"Rekey finished in {time.time() - started:.1f}s.")

    print("\nVerifying...")
    ok = try_open(new)
    if ok is None:
        sys.exit("\n*** VERIFICATION FAILED: the new password does NOT open the "
                 f"database.\n    Restore with: cp {backup} {DB_PATH}")
    new_folders = ok.execute("SELECT COUNT(*) FROM folders").fetchone()[0]
    new_items = ok.execute("SELECT COUNT(*) FROM items").fetchone()[0]
    ok.close()
    print(f"  [ok] new password opens the vault ({new_folders} folders / "
          f"{new_items} items)")

    if try_open(current) is not None:
        sys.exit("\n*** WARNING: the OLD password still opens the database. "
                 f"Do not rely on this change.\n    Backup: {backup}")
    print("  [ok] old password no longer opens it")

    if (new_folders, new_items) != (folders, items):
        sys.exit("\n*** WARNING: item counts changed during rekey. "
                 f"Restore with: cp {backup} {DB_PATH}")

    print("\n" + "=" * 62)
    print("Done. Your master password has been changed.")
    print("=" * 62)
    print("\n  1. Save the new password somewhere you trust. It is staged at:")
    print(f"     {NEW_PASSWORD_FILE}")
    print("  2. When it is saved in your password manager, delete that file:")
    print(f"     shred -u {NEW_PASSWORD_FILE}")
    print(f"\n  The pre-change backup stays at:\n     {backup}")
    print("  Delete it once you have confirmed the new password works.")


if __name__ == '__main__':
    main()
