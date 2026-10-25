#!/usr/bin/env bash
# Build dh-p2p and install it as a system service.
# Run from the repository root as a normal user, sudo is used where needed.
set -euo pipefail

cd "$(dirname "$0")/.."

cargo build --release

sudo install -Dm755 target/release/dh-p2p /usr/local/bin/dh-p2p
sudo install -Dm644 contrib/dh-p2p@.service /etc/systemd/system/dh-p2p@.service
sudo install -Dm644 contrib/90-dh-p2p.conf /etc/sysctl.d/90-dh-p2p.conf
sudo install -dm755 /etc/dh-p2p

if [ ! -e /etc/dh-p2p/camera.env ] && [ -z "$(ls -A /etc/dh-p2p)" ]; then
    sudo install -Dm600 contrib/example.env /etc/dh-p2p/camera.env
    echo "Created /etc/dh-p2p/camera.env, edit it before starting the service"
fi

sudo sysctl --quiet --system
sudo systemctl daemon-reload

# restart tunnels that are already running so they use the new binary
for unit in $(systemctl list-units --plain --no-legend 'dh-p2p@*' | awk '{print $1}'); do
    sudo systemctl restart "$unit"
done

echo "Installed. Next:"
echo "  sudoedit /etc/dh-p2p/camera.env"
echo "  sudo systemctl enable --now dh-p2p@camera"
echo "  journalctl -u dh-p2p@camera -f"
