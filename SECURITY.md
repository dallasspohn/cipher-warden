# Cipher Warden — security notes

Hardening pass on **2026-10-13**. Original code backed up to
`~/Private/cipher-warden-backup-2026-10-13/` before any edit.

## What was wrong

| # | Finding | Impact |
|---|---|---|
| 1 | `session['db_password'] = password` — Flask sessions are a client-side **signed**, not encrypted, cookie | The master password sat in the browser recoverable with plain base64 |
| 2 | `PERMANENT_SESSION_LIFETIME = 30000` minutes | ~21 days, not the 30 minutes the README promised — off by ~500× |
| 3 | Login route had no attempt counter, backoff, or lockout | Unlimited brute force against the master password |
| 4 | No CSRF token anywhere in the app | Any site could drive state-changing POSTs at your vault |
| 5 | Served plain HTTP on `0.0.0.0:5000` | Master password and every secret crossed the wire in cleartext |
| 6 | `f"PRAGMA key = '{password}'"` | Any master password containing an apostrophe could never authenticate |
| 7 | Flask 2.3.0 paired with Werkzeug 3.1.8 | Unsupported combination; broke `test_client` outright |

## What changed

1. **Master password removed from the cookie.** The cookie now carries only an
   opaque random token; the password lives in an in-process `_SESSIONS` dict,
   never leaving the server. Because the store is in memory, a restart drops
   every session — which is also why the per-process random `secret_key` is
   fine to keep: old cookies die with the process that minted them.
2. **Idle timeout is now genuinely 30 minutes**, enforced *server-side* on every
   authenticated request, not just in the cookie's `Expires`.
3. **Login throttling** per client IP: 5 failures in 5 minutes → 30 second
   backoff, re-armed on each subsequent failure.
4. **CSRF tokens** on all four forms plus both JSON fetches, checked in
   `before_request`, alongside `SameSite=Strict`.
5. **HTTPS** with a persistent self-signed cert (`tls/make-cert.sh`, 10-year
   validity, SANs for localhost + both LAN IPs). `SESSION_COOKIE_SECURE=True`.
6. **SQLite string escaping fixed** — single quotes are doubled by hand, since
   `PRAGMA` accepts no bind parameters.
7. **Werkzeug pinned** to `>=2.3.7,<3`.

## Configuration

All overridable by environment variable — see `password-manager.py` for defaults.

| Variable | Default | Meaning |
|---|---|---|
| `CW_TLS` | `1` | `0` serves plain HTTP. Only use behind a TLS-terminating proxy. |
| `CW_HOST` | `0.0.0.0` | Set to `127.0.0.1` to remove LAN exposure entirely. |
| `CW_PORT` | `5000` | Listen port |
| `CW_TLS_CERT` / `CW_TLS_KEY` | `tls/cipher-warden.{crt,key}` | Certificate paths |
| `CW_IDLE_SECONDS` | `1800` | Idle timeout |
| `CW_MAX_FAILURES` | `5` | Failures before backoff |
| `CW_LOGIN_WINDOW` | `300` | Failure counting window |
| `CW_BACKOFF` | `30` | Lockout seconds |
| `CW_DB` | `passwords.db` | Vault path |

## Changing the master password

```bash
./rekey.py
```

You are prompted **only** for the current password. The new one is read from
`~/Private/cipher-warden-master-password.txt` (mode 600), so a 32-character
random passphrase never passes through your keyboard or a shell history.

The script backs up to `backups/` first, refuses to run if the current password
does not open the vault, and afterwards verifies that the new key works **and**
that the old key no longer does — so a silent half-failure cannot leave you
believing you are protected when you are not.

Once the new password is saved in your password manager:

```bash
shred -u ~/Private/cipher-warden-master-password.txt
```

## Tests

```bash
./venv/bin/python test_security.py
```

25 checks against a throwaway vault in a temp dir. It never touches the real
`passwords.db` and never needs your master password.

## Still true — worth knowing

- **A restart logs you out.** Intended now: the server-side session store is in
  memory. If that becomes annoying, persist sessions to disk.
- **Self-signed cert means a browser warning on first visit.** Expected. The
  connection really is encrypted. Pin the certificate if the warning irritates
  you.
- **`0.0.0.0` still means every device on the LAN can reach the login page.**
  Throttling and HTTPS reduce the risk; they do not remove the exposure. For
  that, set `CW_HOST=127.0.0.1` and reach it over an SSH tunnel or Tailscale.
- **The vault is only as strong as its master password.** No amount of
  application hardening rescues a dictionary phrase.
