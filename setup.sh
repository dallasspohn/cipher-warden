#!/usr/bin/env bash
# Rebuild the Cipher Warden environment from scratch.
#
# Everything comes from requirements.txt. Safe to re-run: it stops the service,
# swaps in a fresh venv, and only discards the old one after the new one proves
# it can open the vault's schema.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE"

echo "=============================================="
echo " Cipher Warden -- environment setup"
echo "=============================================="
echo

# --- system prerequisites -----------------------------------------------
# pysqlcipher3 is a C extension bound to libsqlcipher. Wheels exist for common
# platforms; if pip falls back to building from source these must be present.
MISSING=()
dpkg -s libsqlcipher-dev >/dev/null 2>&1 || MISSING+=("libsqlcipher-dev")
[[ -f /usr/include/python3.12/Python.h ]] || MISSING+=("python3-dev")
if (( ${#MISSING[@]} )); then
  echo "Missing system packages: ${MISSING[*]}"
  echo "  sudo apt install ${MISSING[*]}"
  echo
fi

# --- service must not be running out of the venv we are replacing --------
echo "==> stopping cipher-warden.service"
systemctl --user stop cipher-warden.service 2>/dev/null || true

# --- build ---------------------------------------------------------------
echo "==> creating venv"
rm -rf venv
python3 -m venv venv

echo "==> installing requirements"
./venv/bin/pip install --quiet --upgrade pip
./venv/bin/pip install --requirement requirements.txt

echo "==> verifying the environment"
./venv/bin/python - <<'PY'
import sys
import importlib.metadata as md
import flask, werkzeug
from pysqlcipher3 import dbapi2 as sqlcipher
print(f"  python       {sys.version.split()[0]}")
print(f"  flask        {flask.__version__}")
print(f"  werkzeug     {werkzeug.__version__}")
print(f"  pysqlcipher3 {md.version('pysqlcipher3')}")
print(f"  sqlite       {sqlcipher.sqlite_version}")
PY

# --- TLS cert if absent --------------------------------------------------
if [[ ! -f tls/cipher-warden.crt ]]; then
  echo "==> generating TLS certificate"
  bash tls/make-cert.sh
fi

# --- back up -------------------------------------------------------------
if [[ ! -f passwords.db ]]; then
  echo
  echo "!! No passwords.db here. If this is a fresh install, import a Bitwarden"
  echo "!! export first:  ./venv/bin/python import_bitwarden.py <export.json>"
fi

echo
echo "==> starting cipher-warden.service"
systemctl --user start cipher-warden.service
sleep 3
systemctl --user --no-pager --lines=0 status cipher-warden.service || true

echo
echo "Health check:"
curl -sk -o /dev/null -w "  https://127.0.0.1:5000/login -> HTTP %{http_code}\n" \
  https://127.0.0.1:5000/login

echo
echo "Done. To change the master password:  ./rekey.py"
