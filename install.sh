#!/usr/bin/env bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export PATH="$HOME/.go/bin:/home/yhsajib/.go/bin:/usr/local/go/bin:$PATH"

echo "==================================================================="
echo " Installing HoatzinGenz Protection Server & Security Agent Suite"
echo "==================================================================="

if [ "$EUID" -ne 0 ]; then
  echo "[ERROR] Please run installer as root (sudo ./install.sh)"
  exit 1
fi

INSTALL_DIR="/opt/hoatzingenz-protection"
AGENT_DIR="/opt/diagnostic-agent"
DATA_DIR="/var/lib/hoatzingenz"

mkdir -p "$INSTALL_DIR/bin"
mkdir -p "$AGENT_DIR/bin"
mkdir -p "$AGENT_DIR/quarantine"
mkdir -p "$DATA_DIR"
mkdir -p "/etc/diagnostic-agent"

if [ "$SCRIPT_DIR" != "$INSTALL_DIR" ]; then
  echo "[INFO] Syncing source code to $INSTALL_DIR..."
  cp -r "$SCRIPT_DIR"/* "$INSTALL_DIR/"
fi

cd "$INSTALL_DIR"

echo "[INFO] Compiling Go server binary..."
go build -o "$INSTALL_DIR/bin/server" "$INSTALL_DIR/cmd/server"
chmod +x "$INSTALL_DIR/bin/server"

echo "[INFO] Compiling Go agent binary..."
cd "$INSTALL_DIR/diagnostic-agent"
go build -o "$AGENT_DIR/bin/diagnostic-agent" .
chmod +x "$AGENT_DIR/bin/diagnostic-agent"
cd "$INSTALL_DIR"

if [ -d "$INSTALL_DIR/web/dist" ]; then
  echo "[INFO] Installing Web UI build..."
  mkdir -p "$INSTALL_DIR/web"
  cp -rf "$INSTALL_DIR/web/dist/"* "$INSTALL_DIR/web/"  || true
fi

echo "[INFO] Installing Systemd services..."
cp "$INSTALL_DIR/systemd/hoatzingenz-server.service" /etc/systemd/system/
cp "$INSTALL_DIR/systemd/hoatzingenz-agent.service" /etc/systemd/system/

if command -v systemctl &> /dev/null; then
  systemctl daemon-reload || true
  systemctl enable --now hoatzingenz-server  || true
  systemctl enable --now hoatzingenz-agent  || true
fi

echo "==================================================================="
echo "  Installation Complete!"
echo " Control Panel running at: http://localhost:8080"
echo " SQLite Database path: $DATA_DIR/controlpanel.db"
echo " Default Login Credentials: admin / admin123"
echo "==================================================================="
