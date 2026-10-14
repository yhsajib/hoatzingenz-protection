#!/usr/bin/env bash
# ==============================================================================
# HoatzinGenz Protection Suite & Web Control Panel — Production VPS Installer
# Supported OS: Ubuntu 22.04 LTS / 24.04 LTS, Debian 11 / 12
# ==============================================================================
set -e

GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${CYAN}===================================================================${NC}"
echo -e "${CYAN}  HoatzinGenz Protection Server & Security Suite — VPS Installer  ${NC}"
echo -e "${CYAN}===================================================================${NC}"

if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}[ERROR] This script must be run as root. Please run: sudo ./install.sh${NC}"
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="/opt/hoatzingenz-protection"
AGENT_DIR="/opt/diagnostic-agent"
DATA_DIR="/var/lib/hoatzingenz"

# 1. Update package manager & install core utilities
echo -e "\n${GREEN}[1/7] Updating package index & installing essential tools...${NC}"
apt-get update -y -q
apt-get install -y -q curl wget git sqlite3 ufw fail2ban nginx certbot python3-certbot-nginx build-essential rsync

# 2. Check or Install Go (Golang)
echo -e "\n${GREEN}[2/7] Checking Golang runtime environment...${NC}"
export PATH="/usr/local/go/bin:$HOME/go/bin:$HOME/.go/bin:/usr/bin:$PATH"

if ! command -v go &> /dev/null; then
  echo -e "${YELLOW}[INFO] Installing Golang from official distribution...${NC}"
  GO_ARCH="amd64"
  if [ "$(uname -m)" = "aarch64" ]; then GO_ARCH="arm64"; fi
  GO_VERSION="1.22.6"
  wget -q "https://go.dev/dl/go${GO_VERSION}.linux-${GO_ARCH}.tar.gz" -O /tmp/go.tar.gz
  rm -rf /usr/local/go && tar -C /usr/local -xzf /tmp/go.tar.gz
  rm -f /tmp/go.tar.gz
  export PATH="/usr/local/go/bin:$PATH"
  echo "export PATH=\$PATH:/usr/local/go/bin" >> /etc/profile
fi
echo -e "${CYAN}[INFO] Go version: $(go version)${NC}"

# 3. Check or Install Node.js (for Web UI build if needed)
echo -e "\n${GREEN}[3/7] Checking Frontend Web Assets...${NC}"
if [ ! -d "$SCRIPT_DIR/web/dist" ] || [ "$1" = "--rebuild" ]; then
  echo -e "${YELLOW}[INFO] Web distribution missing or rebuild requested. Preparing Node.js...${NC}"
  if ! command -v node &> /dev/null; then
    echo -e "${CYAN}[INFO] Installing Node.js LTS via NodeSource...${NC}"
    curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
    apt-get install -y -q nodejs
  fi
  echo -e "${CYAN}[INFO] Building React/Vite UI bundle...${NC}"
  cd "$SCRIPT_DIR/web"
  npm ci || npm install
  npm run build
  cd "$SCRIPT_DIR"
else
  echo -e "${CYAN}[INFO] Precompiled web assets found in web/dist.${NC}"
fi

# 4. Prepare Destination Directories
echo -e "\n${GREEN}[4/7] Setting up directories in /opt & /var/lib...${NC}"
mkdir -p "$INSTALL_DIR/bin"
mkdir -p "$AGENT_DIR/bin"
mkdir -p "$AGENT_DIR/quarantine"
mkdir -p "$DATA_DIR"
mkdir -p "/etc/diagnostic-agent"
mkdir -p "/etc/nginx/sites-available"
mkdir -p "/etc/nginx/sites-enabled"

if [ "$SCRIPT_DIR" != "$INSTALL_DIR" ]; then
  echo -e "${CYAN}[INFO] Syncing files to $INSTALL_DIR...${NC}"
  rsync -a --exclude='.git' --exclude='node_modules' "$SCRIPT_DIR/" "$INSTALL_DIR/" || cp -r "$SCRIPT_DIR"/* "$INSTALL_DIR/"
fi

# 5. Compile Go Server & Agent
echo -e "\n${GREEN}[5/7] Compiling Production Binaries...${NC}"
cd "$INSTALL_DIR"
go build -o "$INSTALL_DIR/bin/server" "$INSTALL_DIR/cmd/server/main.go"
chmod +x "$INSTALL_DIR/bin/server"

cd "$INSTALL_DIR/diagnostic-agent"
go build -o "$AGENT_DIR/bin/diagnostic-agent" .
chmod +x "$AGENT_DIR/bin/diagnostic-agent"
cd "$INSTALL_DIR"

# 6. Configure Systemd Services
echo -e "\n${GREEN}[6/7] Installing & Enabling Systemd Services...${NC}"
cp "$INSTALL_DIR/systemd/hoatzingenz-server.service" /etc/systemd/system/
cp "$INSTALL_DIR/systemd/hoatzingenz-agent.service" /etc/systemd/system/

if command -v systemctl &> /dev/null; then
  systemctl daemon-reload
  systemctl enable --now hoatzingenz-server
  systemctl enable --now hoatzingenz-agent
fi

# 7. Configure Firewall (UFW)
echo -e "\n${GREEN}[7/7] Configuring Firewall Ports...${NC}"
if command -v ufw &> /dev/null; then
  ufw allow 22/tcp >/dev/null 2>&1 || true
  ufw allow 80/tcp >/dev/null 2>&1 || true
  ufw allow 443/tcp >/dev/null 2>&1 || true
  ufw allow 8080/tcp >/dev/null 2>&1 || true
fi

# Detect Public Server IP
SERVER_IP=$(curl -s -m 4 https://ifconfig.me || curl -s -m 4 https://api.ipify.org || hostname -I | awk '{print $1}')

echo -e "\n${CYAN}===================================================================${NC}"
echo -e "${GREEN}  HoatzinGenz Protection Suite successfully installed & running!   ${NC}"
echo -e "${CYAN}===================================================================${NC}"
echo -e " Panel Access URL:        ${YELLOW}http://${SERVER_IP}:8080${NC}"
echo -e " Master Username:         ${GREEN}admin${NC}"
echo -e " Default Master Password: ${GREEN}admin123${NC}"
echo -e " SQLite Database:         ${CYAN}/var/lib/hoatzingenz/controlpanel.db${NC}"
echo -e " System Service:          ${CYAN}systemctl status hoatzingenz-server${NC}"
echo -e "${CYAN}-------------------------------------------------------------------${NC}"
echo -e "${YELLOW} IMPORTANT NEXT STEPS FOR PRODUCTION SECURITY:${NC}"
echo -e " 1. Open the URL in your browser and sign in."
echo -e " 2. Change the default password immediately via Super Admin Profile."
echo -e " 3. Enable Google Authenticator (TOTP 2FA) in Profile -> Security."
echo -e " 4. Point your domain (e.g. cp.yourdomain.com) to ${SERVER_IP} and"
echo -e "    configure it under Profile -> Panel Domain for automated SSL (HTTPS)."
echo -e "${CYAN}===================================================================${NC}\n"
