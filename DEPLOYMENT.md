# HoatzinGenz Protection Suite & Web Control Panel — VPS Deployment Guide

This guide walks you through deploying **HoatzinGenz Protection Suite & Web Control Panel** on a clean Virtual Private Server (VPS) such as DigitalOcean, Hetzner, Linode, AWS EC2, Vultr, or any bare-metal Ubuntu/Debian server.

---

## 1. System Requirements

| Specification | Minimum | Recommended |
|---|---|---|
| **Operating System** | Ubuntu 22.04 LTS or 24.04 LTS (Debian 11/12 also supported) | Ubuntu 24.04 LTS |
| **CPU Architecture** | 1 vCPU (x86_64 or ARM64) | 2+ vCPUs |
| **RAM** | 1 GB (with 1GB swap) | 2 GB+ |
| **Disk Space** | 10 GB SSD / NVMe | 25 GB+ SSD |
| **Privileges** | Root / sudo access | Root access |

### Required Open Ports
Ensure these ports are allowed in your VPS cloud provider firewall (Security Group / Cloud Firewall):
- **`22` (SSH)**: Remote server administration
- **`80` (HTTP)**: Web traffic & Let's Encrypt automated challenge validation
- **`443` (HTTPS)**: Encrypted SSL web traffic
- **`8080` (TCP)**: Direct HoatzinGenz Control Panel port (can also be routed through port 443 via reverse proxy)

---

## 2. Fast 1-Command Automated Installation

Connect to your VPS via SSH as `root`:

```bash
ssh root@<YOUR-VPS-IP>
```

Clone or transfer your repository to `/opt/hoatzingenz-protection`:

```bash
git clone https://github.com/<your-org>/hoatzingenz-protection.git /opt/hoatzingenz-protection
cd /opt/hoatzingenz-protection
chmod +x install.sh
sudo ./install.sh
```

### What `install.sh` Does Automatically:
1. Updates package indices and installs required packages (`sqlite3`, `nginx`, `ufw`, `fail2ban`, `certbot`, `build-essential`).
2. Checks for Golang runtime and automatically installs Go 1.22+ if not present.
3. Checks for precompiled web assets, installing Node.js LTS and compiling the React/Vite UI bundle if missing.
4. Compiles the Go server (`/opt/hoatzingenz-protection/bin/server`) and Security Diagnostic Agent (`/opt/diagnostic-agent/bin/diagnostic-agent`).
5. Configures and starts systemd background services (`hoatzingenz-server` and `hoatzingenz-agent`) with automated auto-restart.
6. Opens necessary firewall ports (`22`, `80`, `443`, `8080`) in UFW.
7. Detects your server's public IP address and outputs your exact login link.

---

## 3. Post-Installation: Initial Access & Security Checklist

Once the installer finishes, follow these 4 essential security steps:

### Step 1: Open the Control Panel
Navigate in your web browser to:
```
http://<YOUR-VPS-IP>:8080
```
- **Default Username:** `admin`
- **Default Password:** `admin123`

### Step 2: Change Master Password
1. In the left sidebar, click **Profile**.
2. Go to the **Security & API Key** sub-tab.
3. Enter your current password (`admin123`) and choose a strong new password (minimum 8 characters, uppercase, lowercase, numbers).
4. Click **Update Master Password**.

### Step 3: Enable Google Authenticator (TOTP 2FA)
1. On the same **Security** sub-tab, locate the **Google Authenticator (2FA)** card.
2. Click **Set Up Google Authenticator**.
3. Scan the generated QR code using Google Authenticator, Authy, or 1Password.
4. Enter the 6-digit passcode displayed in your app to verify and activate 2FA.
5. All future sign-ins will require this 2-step verification.

### Step 4: Configure Custom Domain & Free SSL (HTTPS)
To access your panel securely over `https://cp.yourdomain.com` without port `:8080`:
1. In your domain DNS manager (Cloudflare, Namecheap, Route53, etc.), create an **A-Record**:
   - **Type:** `A`
   - **Name:** `cp` (or `@` for root domain)
   - **Target / Value:** `<YOUR-VPS-IP>`
2. In the HoatzinGenz Control Panel, click **Profile &rarr; Panel Domain**.
3. Enter your domain (e.g., `cp.yourdomain.com`) and click **Verify DNS & Activate Domain**.
4. The panel will automatically generate the Nginx reverse-proxy configuration at `/etc/nginx/sites-available/panel-domain.conf`, reload Nginx, and request an official Let's Encrypt SSL certificate via Certbot.

---

## 4. Managing Services (Systemd)

The server and background agent run as persistent systemd services:

```bash
# Check Server Status
systemctl status hoatzingenz-server

# Check Security Diagnostic Agent Status
systemctl status hoatzingenz-agent

# Restart Server
systemctl restart hoatzingenz-server

# View Live Server Logs
journalctl -u hoatzingenz-server -f

# View Live Agent Telemetry Logs
journalctl -u hoatzingenz-agent -f
```

---

## 5. File & Directory Reference

| Path | Purpose |
|---|---|
| `/opt/hoatzingenz-protection/bin/server` | Compiled Go server binary |
| `/opt/hoatzingenz-protection/web/dist` | Production compiled React/Vite UI frontend assets |
| `/var/lib/hoatzingenz/controlpanel.db` | SQLite database storing users, websites, databases, sessions, audit events |
| `/opt/diagnostic-agent/bin/diagnostic-agent` | Security diagnostic daemon binary |
| `/etc/systemd/system/hoatzingenz-server.service` | Systemd service unit for the API server |
| `/etc/systemd/system/hoatzingenz-agent.service` | Systemd service unit for the diagnostic agent |
| `/etc/nginx/sites-available/` | Nginx virtual host configurations generated for websites |

---

## 6. Upgrading in the Future

To deploy code updates on your VPS:

```bash
cd /opt/hoatzingenz-protection
git pull
sudo ./install.sh
```
The installer will recompile the binaries and restart the systemd services with zero configuration loss (your SQLite database in `/var/lib/hoatzingenz/` is preserved).
