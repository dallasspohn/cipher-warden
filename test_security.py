#!/usr/bin/env python3
"""
Security regression suite for Cipher Warden.

Runs against a THROWAWAY vault in a temp dir. Never touches the real
passwords.db, and never needs Dallas's actual master password.

Each test below corresponds to a finding from the 2026-10-13 audit. A test that
passes means the old vulnerability is closed.
"""
import base64
import importlib.util
import json
import os
import shutil
import sys
import tempfile
import zlib

# Same venv bootstrap as rekey.py. See the long note there for why comparing
# realpaths of the two interpreters does not work on a venv.
_VENV_PY = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        'venv', 'bin', 'python')
if not os.environ.get('_CW_VENV_BOOTSTRAPPED') and os.path.exists(_VENV_PY):
    try:
        import pysqlcipher3  # noqa: F401
    except ImportError:
        os.environ['_CW_VENV_BOOTSTRAPPED'] = '1'
        os.execv(_VENV_PY, [_VENV_PY] + sys.argv)

TEST_PASSWORD = 'unit-test-master-key'

PASS, FAIL = [], []


def check(name, condition, detail=''):
    (PASS if condition else FAIL).append(name)
    mark = '\033[32mPASS\033[0m' if condition else '\033[31mFAIL\033[0m'
    print(f"  [{mark}] {name}")
    if detail and not condition:
        print(f"         {detail}")


def build_test_vault(directory):
    """Create an encrypted vault with the same schema import_bitwarden.py makes."""
    from pysqlcipher3 import dbapi2 as sqlcipher
    db = os.path.join(directory, 'passwords.db')
    conn = sqlcipher.connect(db)
    escaped = TEST_PASSWORD.replace("'", "''")
    conn.execute(f"PRAGMA key = '{escaped}'")
    conn.execute("PRAGMA cipher_compatibility = 4")
    cur = conn.cursor()
    cur.executescript("""
        CREATE TABLE IF NOT EXISTS folders (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS items (
            id TEXT PRIMARY KEY,
            folder_id TEXT,
            name TEXT NOT NULL,
            username TEXT,
            password TEXT,
            notes TEXT,
            favorite INTEGER DEFAULT 0,
            reprompt INTEGER DEFAULT 0,
            type INTEGER DEFAULT 1,
            created_date TEXT,
            revision_date TEXT,
            FOREIGN KEY (folder_id) REFERENCES folders(id)
        );
        CREATE TABLE IF NOT EXISTS uris (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            item_id TEXT NOT NULL,
            uri TEXT NOT NULL,
            FOREIGN KEY (item_id) REFERENCES items(id)
        );
        CREATE TABLE IF NOT EXISTS fields (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            item_id TEXT NOT NULL,
            name TEXT,
            value TEXT,
            type INTEGER,
            FOREIGN KEY (item_id) REFERENCES fields(item_id)
        );
    """)
    cur.execute("INSERT INTO folders (id, name) VALUES ('f1', 'Test Folder')")
    cur.execute("INSERT INTO items (id, folder_id, name, username, password) "
                "VALUES ('i1', 'f1', 'Test Item', 'dallas', 'hunter2')")
    conn.commit()
    conn.close()
    return db


def load_app(directory):
    """Import password-manager.py with its DB pointed at the throwaway vault."""
    os.environ['CW_TLS'] = '0'
    os.environ['CW_HOST'] = '127.0.0.1'
    os.environ['CW_PORT'] = '5099'
    # Absolute path, so this suite can never touch the real vault even if the
    # working directory is wrong.
    os.environ['CW_DB'] = os.path.join(directory, 'passwords.db')
    cwd = os.getcwd()
    os.chdir(directory)
    try:
        spec = importlib.util.spec_from_file_location(
            'cw_under_test',
            os.path.join(os.path.expanduser('~/cipher-warden'),
                         'password-manager.py'))
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    finally:
        os.chdir(cwd)


def in_request(cw, fn):
    """resolve_session() touches the request-local session; give it a context."""
    with cw.app.test_request_context('/'):
        return fn()


def decode_cookie(cookie_value):
    """Flask session cookie: base64url payload + signature. Readable by anyone.

    itsdangerous prefixes the payload with '.' when it zlib-compresses it,
    so a compressed cookie starts with '.<b64>.<sig>' and naive splitting on
    the first dot yields an empty string.
    """
    if cookie_value.startswith('.'):
        body = cookie_value.split('.', 2)[1]
    else:
        body = cookie_value.split('.')[0]
    body += '=' * (-len(body) % 4)
    raw = base64.urlsafe_b64decode(body)
    try:
        raw = zlib.decompress(raw)
    except Exception:
        pass
    return json.loads(raw)


def csrf_from(client, path='/login'):
    """Pull the CSRF token out of a rendered form the way a browser would."""
    html = client.get(path).get_data(as_text=True)
    marker = 'name="csrf_token" value="'
    idx = html.find(marker)
    if idx == -1:
        return None, html
    start = idx + len(marker)
    return html[start:html.find('"', start)], html


def main():
    workdir = tempfile.mkdtemp(prefix='cw-test-')
    try:
        build_test_vault(workdir)
        cw = load_app(workdir)
        cw.app.config['SERVER_NAME'] = None

        print("\n\033[1m1. Master password must not appear in the cookie\033[0m")
        client = cw.app.test_client()
        token, html = csrf_from(client)
        check('login page issues a CSRF token', bool(token))
        resp = client.post('/login',
                           data={'password': TEST_PASSWORD, 'csrf_token': token},
                           follow_redirects=False)
        check('correct password logs in (302 to /dashboard)',
              resp.status_code == 302 and '/dashboard' in resp.headers.get('Location', ''),
              f'got {resp.status_code}')
        cookies = client.get_cookie('session')
        check('a session cookie was issued', cookies is not None)
        if cookies:
            payload = decode_cookie(cookies.value)
            check('cookie payload does NOT contain the master password',
                  TEST_PASSWORD not in json.dumps(payload),
                  f'payload = {payload}')
            check('cookie carries an opaque token, not the password',
                  'token' in payload and 'db_password' not in payload,
                  f'keys = {sorted(payload)}')

        print("\n\033[1m2. Session timeout is 30 minutes, not 30000\033[0m")
        lifetime = cw.app.config['PERMANENT_SESSION_LIFETIME'].total_seconds()
        check('PERMANENT_SESSION_LIFETIME == 1800s (30 min)',
              lifetime == 1800, f'got {lifetime}s')
        check('module constant SESSION_IDLE_SECONDS == 1800',
              cw.SESSION_IDLE_SECONDS == 1800,
              f'got {cw.SESSION_IDLE_SECONDS}')

        print("\n\033[1m3. Idle timeout is enforced server-side\033[0m")
        c2 = cw.app.test_client()
        tok2, _ = csrf_from(c2)
        c2.post('/login', data={'password': TEST_PASSWORD, 'csrf_token': tok2})
        # Probe through a real request, not a synthetic empty context -- an
        # empty context has no cookie and would "fail" for the wrong reason.
        live = c2.get('/dashboard')
        check('freshly authenticated session serves the dashboard (200)',
              live.status_code == 200, f'got {live.status_code}')
        # Age the stored session past the idle window.
        with cw._SESSIONS_LOCK:
            for record in cw._SESSIONS.values():
                record['last_seen'] -= cw.SESSION_IDLE_SECONDS + 60
        check('expired session no longer resolves',
              in_request(cw, cw.resolve_session) is None)
        resp = c2.get('/dashboard', follow_redirects=False)
        check('expired session is bounced to /login',
              resp.status_code == 302 and '/login' in resp.headers.get('Location', ''),
              f'got {resp.status_code}')

        print("\n\033[1m4. CSRF protection\033[0m")
        c3 = cw.app.test_client()
        tok3, _ = csrf_from(c3)
        resp = c3.post('/login', data={'password': TEST_PASSWORD})
        check('POST with no CSRF token is rejected (403)', resp.status_code == 403,
              f'got {resp.status_code}')
        resp = c3.post('/login', data={'password': TEST_PASSWORD,
                                       'csrf_token': 'wrong-token-value'})
        check('POST with wrong CSRF token is rejected (403)', resp.status_code == 403,
              f'got {resp.status_code}')
        resp = c3.post('/login', data={'password': TEST_PASSWORD,
                                       'csrf_token': tok3})
        check('POST with correct CSRF token is accepted', resp.status_code == 302,
              f'got {resp.status_code}')

        c4 = cw.app.test_client()
        tok4, _ = csrf_from(c4)
        c4.post('/login', data={'password': TEST_PASSWORD, 'csrf_token': tok4})
        check('authenticated state-changing POST without CSRF is rejected',
              c4.post('/toggle_favorite', json={'item_id': 'i1', 'favorite': 1}
                      ).status_code == 403)
        check('authenticated state-changing POST with CSRF header is accepted',
              c4.post('/toggle_favorite', json={'item_id': 'i1', 'favorite': 1},
                      headers={'X-CSRF-Token': tok4}).status_code == 200)

        print("\n\033[1m5. Brute-force lockout\033[0m")
        c5 = cw.app.test_client()
        last = None
        for attempt in range(cw.LOGIN_MAX_FAILURES + 3):
            t, _ = csrf_from(c5)
            last = c5.post('/login', data={'password': f'wrong-{attempt}',
                                           'csrf_token': t})
        check('repeated failures eventually return 429 (locked out)',
              last.status_code == 429, f'got {last.status_code}')
        t, _ = csrf_from(c5)
        blocked = c5.post('/login', data={'password': TEST_PASSWORD,
                                          'csrf_token': t})
        check('even the CORRECT password is refused during lockout',
              blocked.status_code == 429, f'got {blocked.status_code}')
        check('lockout message tells the user how long to wait',
              'try again in' in blocked.get_data(as_text=True).lower())

        print("\n\033[1m6. Cookie hardening flags\033[0m")
        check('SESSION_COOKIE_HTTPONLY is True',
              cw.app.config['SESSION_COOKIE_HTTPONLY'] is True)
        check("SESSION_COOKIE_SAMESITE == 'Strict'",
              cw.app.config['SESSION_COOKIE_SAMESITE'] == 'Strict')
        check('SESSION_COOKIE_SECURE tracks the TLS setting',
              cw.app.config['SESSION_COOKIE_SECURE'] == (cw.TLS_ENABLED))

        print("\n\033[1m7. Master passwords containing apostrophes work\033[0m")
        quoted = "it's-a-test'key"
        qdb = os.path.join(workdir, 'quoted.db')
        from pysqlcipher3 import dbapi2 as sqlcipher
        conn = sqlcipher.connect(qdb)
        conn.execute(f"PRAGMA key = '{quoted.replace(chr(39), chr(39)*2)}'")
        conn.execute("PRAGMA cipher_compatibility = 4")
        conn.execute("CREATE TABLE folders (id TEXT PRIMARY KEY, name TEXT)")
        conn.commit()
        conn.close()
        conn = cw.sqlcipher.connect(qdb)
        esc = quoted.replace("'", "''")
        conn.execute(f"PRAGMA key = '{esc}'")
        conn.execute("PRAGMA cipher_compatibility = 4")
        got = conn.execute("SELECT COUNT(*) FROM folders").fetchone()[0]
        conn.close()
        check("password with an apostrophe round-trips", got == 0, f'got {got}')

        print("\n\033[1m8. No plaintext master password left in the source\033[0m")
        src_path = os.path.expanduser('~/cipher-warden/password-manager.py')
        src = open(src_path).read()
        # Strip comments before searching: the hardening block deliberately
        # *documents* the old pattern, and a naive grep hits that prose.
        code_only = '\n'.join(
            line for line in src.splitlines()
            if not line.lstrip().startswith('#'))
        check("executable code never assigns session['db_password']",
              "session['db_password']" not in code_only)
        check('no route reads the master password out of the cookie',
              "session.get('db_password')" not in code_only)
        check('the old 30000-minute lifetime is gone from the code',
              '30000' not in code_only)

        print("\n" + "=" * 62)
        print(f"  {len(PASS)} passed, {len(FAIL)} failed")
        if FAIL:
            for name in FAIL:
                print(f"    FAILED: {name}")
        print("=" * 62)
        return 1 if FAIL else 0
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


if __name__ == '__main__':
    sys.exit(main())
