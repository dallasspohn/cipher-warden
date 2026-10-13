#!/usr/bin/env bash
# Switch cipher-warden from the user unit to the system unit.
# Needs your sudo password -- I don't have one, so this is yours to run.
set -euo pipefail

echo "==> disabling the user unit"
systemctl --user disable --now cipher-warden.service

echo "==> installing the system unit"
sudo cp /home/dallas/cipher-warden/deploy/cipher-warden.service /etc/systemd/system/cipher-warden.service
sudo systemctl daemon-reload

echo "==> enabling the system unit"
sudo systemctl enable --now cipher-warden.service

sleep 3
sudo systemctl --no-pager status cipher-warden.service
curl -s -o /dev/null -w "GET /login -> HTTP %{http_code}\n" http://127.0.0.1:5000/login
