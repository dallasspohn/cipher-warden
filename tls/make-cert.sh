#!/usr/bin/env bash
# Generate a long-lived self-signed certificate for Cipher Warden.
#
# Self-signed means your browser will show a one-time warning. That is expected
# and is not a failure -- the connection is genuinely encrypted, which is the
# whole point. The alternative is buying a domain name and a cert, and that is
# not worth it for a LAN-only vault.
#
# Regenerating this invalidates nothing in the vault; it only makes browsers
# re-prompt the warning once.
set -euo pipefail

cd "$(dirname "$0")"
CERT="cipher-warden.crt"
KEY="cipher-warden.key"

if [[ -f "$CERT" && "${1:-}" != "--force" ]]; then
  echo "Certificate already exists: $CERT"
  echo "Use --force to regenerate."
  exit 0
fi

# SANs: browsers reject certs that name only a CN, so list every address you
# actually reach this box on. Add your LAN IP here if it changes.
IPS="$(hostname -I 2>/dev/null | tr ' ' '\n' | grep -E '^[0-9]+\.' | paste -sd, -)"
SAN="DNS:localhost,IP:127.0.0.1"
for ip in ${IPS//,/ }; do
  SAN="$SAN,IP:$ip"
done

echo "Generating certificate with SAN: $SAN"

openssl req -x509 -newkey rsa:4096 -nodes \
  -keyout "$KEY" \
  -out "$CERT" \
  -days 3650 \
  -subj "/CN=cipher-warden" \
  -addext "subjectAltName=$SAN" \
  -addext "basicConstraints=critical,CA:FALSE" \
  -addext "keyUsage=critical,digitalSignature,keyEncipherment" \
  -addext "extendedKeyUsage=serverAuth" \
  2>/dev/null

chmod 600 "$KEY"
chmod 644 "$CERT"

echo
echo "Wrote:"
ls -l "$CERT" "$KEY"
echo
openssl x509 -in "$CERT" -noout -subject -dates -ext subjectAltName
