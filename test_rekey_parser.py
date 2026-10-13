#!/usr/bin/env python3
"""
Regression test for the rekey password-file parser.

Bug (2026-10-13): read_new_password() did `fh.read().strip()`, which strips
whitespace from the ends of the ENTIRE file and returns the whole thing --
headers included. rekey.py then encrypted the vault under a multi-line string
containing its own explanatory preamble, and the real password would never have
worked at the login prompt.

These checks pin the parsing contract so it cannot regress.
"""
import os
import sys
import tempfile

_VENV_PY = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        'venv', 'bin', 'python')
if not os.environ.get('_CW_VENV_BOOTSTRAPPED') and os.path.exists(_VENV_PY):
    try:
        import pysqlcipher3  # noqa: F401
    except ImportError:
        os.environ['_CW_VENV_BOOTSTRAPPED'] = '1'
        os.execv(_VENV_PY, [_VENV_PY] + sys.argv)

import importlib.util

PASS, FAIL = [], []


def check(name, condition, detail=''):
    (PASS if condition else FAIL).append(name)
    mark = '\033[32mPASS\033[0m' if condition else '\033[31mFAIL\033[0m'
    print(f"  [{mark}] {name}")
    if detail and not condition:
        print(f"         {detail}")


def load_rekey():
    here = os.path.dirname(os.path.abspath(__file__))
    spec = importlib.util.spec_from_file_location(
        'rekey_under_test', os.path.join(here, 'rekey.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def staged_file(contents):
    fh = tempfile.NamedTemporaryFile('w', delete=False, suffix='.txt')
    fh.write(contents)
    fh.close()
    os.chmod(fh.name, 0o600)
    return fh.name


# The exact format written by the 2026-10-13 staging step.
REAL_FORMAT = (
    "Cipher Warden master password\n"
    "Generated 2026-10-13 08:58 by Alex.\n"
    "Not yet applied -- run ~/cipher-warden/rekey.py to activate it.\n"
    "Once it is saved in your password manager: shred -u this file\n"
    "\n"
    "TESTONLYfixtureValue-0123456789abcd\n"
)
SECRET = "TESTONLYfixtureValue-0123456789abcd"


def main():
    rekey = load_rekey()
    print("\n\033[1mread_new_password() must return ONLY the password\033[0m")
    paths = []

    cases = {
        'the real staged-file format (headers + blank line + password)': REAL_FORMAT,
        'password only, no headers': SECRET + '\n',
        'password with no trailing newline': SECRET,
        'trailing blank lines after the password': SECRET + '\n\n\n',
        'CRLF line endings': REAL_FORMAT.replace('\n', '\r\n'),
    }

    original = rekey.NEW_PASSWORD_FILE
    for label, content in cases.items():
        path = staged_file(content)
        paths.append(path)
        rekey.NEW_PASSWORD_FILE = path
        try:
            got = rekey.read_new_password()
        except SystemExit as exc:
            got = f'<refused: {exc}>'
        check(label, got == SECRET, f'got {got!r}')

    print("\n\033[1mGuards still apply\033[0m")
    short = staged_file("a\nb\nshort\n")
    paths.append(short)
    rekey.NEW_PASSWORD_FILE = short
    try:
        rekey.read_new_password()
        refused = False
    except SystemExit:
        refused = True
    check('refuses a password under 20 characters', refused)

    loose = staged_file(SECRET + '\n')
    os.chmod(loose, 0o644)
    paths.append(loose)
    rekey.NEW_PASSWORD_FILE = loose
    try:
        rekey.read_new_password()
        refused = False
    except SystemExit:
        refused = True
    check('refuses a world-readable password file', refused)

    rekey.NEW_PASSWORD_FILE = original
    for path in paths:
        try:
            os.unlink(path)
        except OSError:
            pass

    print("\n" + "=" * 62)
    print(f"  {len(PASS)} passed, {len(FAIL)} failed")
    if FAIL:
        for name in FAIL:
            print(f"    FAILED: {name}")
    print("=" * 62)
    return 1 if FAIL else 0


if __name__ == '__main__':
    sys.exit(main())
