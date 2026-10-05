#!/usr/bin/env bash
set -e

echo "=================================================================="
echo " Installing HoatzinGenz Protection Server & Security Agent Suite"
echo "=================================================================="

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

echo "[INFO] Compiling Go server binary..."
go build -o "$INSTALL_DIR/bin/server" ./cmd/server
chmod +x "$INSTALL_DIR/bin/server"

echo "[INFO] Compiling Go agent binary..."
cd diagnostic-agent
go build -o "$AGENT_DIR/bin/diagnostic-agent" .
chmod +x "$AGENT_DIR/bin/diagnostic-agent"
cd ..

if [ -d "web/dist" ]; then
  echo "[INFO] Installing Web UI build..."
  mkdir -p "$INSTALL_DIR/web"
  cp -r web/dist "$INSTALL_DIR/web/"
fi

echo "[INFO] Installing Systemd services..."
cp systemd/hoatzingenz-server.service /etc/systemd/system/
cp systemd/hoatzingenz-agent.service /etc/systemd/system/

systemctl daemon-reload
systemctl enable --now hoatzingenz-server
systemctl enable --now hoatzingenz-agent

echo "=================================================================="
echo " 🎉 Installation Complete!"
echo " Control Panel running at: http://localhost:8080"
echo " SQLite Database path: $DATA_DIR/controlpanel.db"
echo " Default Login Credentials: admin / admin123"
echo "=================================================================="
