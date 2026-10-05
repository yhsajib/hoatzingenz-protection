# Production Server Setup & Installation Guide

This document provides step-by-step instructions for deploying the **Diagnostic & Security Protection Agent** across **Shared Hosting Environments** and **VPS / Dedicated Linux Servers**.

---

## Architecture Overview

The system operates in two modes:

1. **Shared Hosting Mode (Pure PHP SDK)**: Application-layer request monitoring, error handling, local FIM (File Integrity Monitoring), and security event detection.
2. **VPS / Dedicated Server Mode (PHP SDK + Go Linux Daemon)**: System metrics (CPU, RAM, Load), kernel-level `inotify` file tracking, process execution monitoring (`www-data` shell tracking), and auto-quarantine capabilities.

---

## Part 1: Shared Hosting Production Setup

### 1. Requirements
- PHP 7.4+ or 8.0+
- `cURL` extension enabled
- `json` extension enabled
- Read/Write permissions on application `tmp/` or cache directory for local event spooling.

### 2. SDK Installation via Composer
In your PHP application root directory:

```bash
composer require hoatzingenz/diagnostic-sdk
```

Or download the release tarball and extract `diagnostic-sdk` into your vendor directory.

### 3. Application Initialization

#### Generic PHP Application
Add the following snippet at the very entry point of your application (e.g., `index.php` or bootstrap file):

```php
<?php
use Hoatzingenz\Diagnostic\DiagnosticSDK;

require_once __DIR__ . '/vendor/autoload.php';

$sdk = DiagnosticSDK::init([
    'project_key' => 'YOUR_PROJECT_KEY',
    'environment' => 'production',
    'security' => [
        'fim_enabled' => true,
        'auto_quarantine' => false, // Set true only if safe sandbox path is writable
    ],
    'spool_path' => __DIR__ . '/storage/diagnostic_spool',
]);

// Automatically registers error, exception, and shutdown handlers
```

#### WordPress Integration
1. Upload the `hoatzingenz-protection` plugin folder to `/wp-content/plugins/`.
2. Activate the plugin in WP Admin.
3. Enter your `Project Key` and `API Endpoint` in **Settings $\rightarrow$ Protection Agent**.

#### Laravel Integration
Add the service provider in `config/app.php` or let Package Discovery load it automatically.

Publish configuration:
```bash
php artisan vendor:publish --provider="Hoatzingenz\Diagnostic\Adapters\Laravel\DiagnosticServiceProvider"
```

Set environment variables in `.env`:
```env
DIAGNOSTIC_ENABLED=true
DIAGNOSTIC_PROJECT_KEY=your_project_key_here
DIAGNOSTIC_ENVIRONMENT=production
```

---

## Part 2: VPS / Dedicated Server Production Setup

### 1. System Requirements
- Linux (Ubuntu 20.04+, Debian 11+, RHEL/CentOS 8+, AlmaLinux/Rocky Linux)
- `systemd` init manager
- `inotify` support enabled in kernel (`fs.inotify.max_user_watches` $\ge$ 524288)

### 2. Kernel Inotify Optimization
To ensure real-time file monitoring across thousands of website files, update system limits:

```bash
echo "fs.inotify.max_user_watches=524288" | sudo tee -a /etc/sysctl.d/99-diagnostic-agent.conf
echo "fs.inotify.max_user_instances=512" | sudo tee -a /etc/sysctl.d/99-diagnostic-agent.conf
sudo sysctl -p /etc/sysctl.d/99-diagnostic-agent.conf
```

### 3. Create Service User & Directory Hierarchy
Create a dedicated non-root user and system directories:

```bash
sudo useradd -r -s /bin/false -d /opt/diagnostic-agent diag-agent

sudo mkdir -p /opt/diagnostic-agent/bin
sudo mkdir -p /opt/diagnostic-agent/config
sudo mkdir -p /opt/diagnostic-agent/data
sudo mkdir -p /opt/diagnostic-agent/logs
sudo mkdir -p /opt/diagnostic-agent/spool
sudo mkdir -p /opt/diagnostic-agent/quarantine
sudo mkdir -p /etc/diagnostic-agent
```

### 4. Install Agent Binary
Download or compile the Go daemon binary:

```bash
sudo cp diagnostic-agent /opt/diagnostic-agent/bin/
sudo chmod 755 /opt/diagnostic-agent/bin/diagnostic-agent
```

### 5. Create Agent Configuration (`/etc/diagnostic-agent/config.yaml`)

```yaml
agent:
  server_id: "srv_prod_01"
  environment: "production"
  log_level: "info"
  log_path: "/opt/diagnostic-agent/logs/agent.log"

cloud:
  endpoint: "https://api.hoatzingenz-protection.io"
  api_key: "YOUR_SERVER_API_KEY"
  upload_interval_seconds: 10
  timeout_seconds: 5

spool:
  directory: "/opt/diagnostic-agent/spool"
  max_size_mb: 50
  ttl_days: 7

monitors:
  system_metrics:
    enabled: true
    interval_seconds: 15

  process_watcher:
    enabled: true
    web_users: ["www-data", "nginx", "apache", "nobody"]
    suspicious_binaries: ["sh", "bash", "curl", "wget", "nc", "netcat", "python", "perl", "gcc"]

  file_integrity:
    enabled: true
    watch_paths:
      - "/var/www/html"
    exclude_extensions: [".log", ".tmp", ".cache"]
    alert_extensions: [".php", ".phtml", ".sh", ".so", ".exe"]

security:
  auto_containment: false # Set true to enable auto-quarantine of dropped PHP files
  quarantine_dir: "/opt/diagnostic-agent/quarantine"
```

Set permissions:
```bash
sudo chown -R diag-agent:diag-agent /opt/diagnostic-agent
sudo chown -R diag-agent:diag-agent /etc/diagnostic-agent
sudo chmod 600 /etc/diagnostic-agent/config.yaml
```

### 6. Install Systemd Service (`/etc/systemd/system/diagnostic-agent.service`)

Create the systemd unit file:

```ini
[Unit]
Description=Hoatzingenz Diagnostic & Security Protection Agent
After=network.target syslog.target

[Service]
Type=simple
User=diag-agent
Group=diag-agent
ExecStart=/opt/diagnostic-agent/bin/diagnostic-agent --config /etc/diagnostic-agent/config.yaml
Restart=always
RestartSec=5s
LimitNOFILE=65536
CapabilityBoundingSet=CAP_DAC_READ_SEARCH CAP_SYS_PTRACE
AmbientCapabilities=CAP_DAC_READ_SEARCH

# Security isolation
ProtectSystem=full
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

### 7. Enable and Start Daemon
```bash
sudo systemctl daemon-reload
sudo systemctl enable diagnostic-agent
sudo systemctl start diagnostic-agent
sudo systemctl status diagnostic-agent
```

---

## Part 3: Verification & Health Checks

### 1. Verify Local Agent Log
```bash
tail -f /opt/diagnostic-agent/logs/agent.log
```

Expected log output:
```
[INFO] Agent initialized. ServerID: srv_prod_01 Environment: production
[INFO] Inotify file watcher started on 1 paths.
[INFO] Process watcher monitoring web users: [www-data nginx apache nobody]
[INFO] Spool manager ready. Max capacity: 50 MB
[INFO] Connectivity check to Cloud API successful.
```

### 2. Verify PHP SDK Fail-Open & Telemetry Emission
Test SDK initialization by calling a dummy test endpoint or running:

```bash
php -r "require 'vendor/autoload.php'; \$sdk = \Hoatzingenz\Diagnostic\DiagnosticSDK::init(['project_key'=>'test']); echo 'SDK initialized cleanly';"
```

### 3. Test Security Detection (Dry-Run / Sandbox)
Create a test file in your web uploads folder:
```bash
touch /var/www/html/wp-content/uploads/test_scan.php
```

Check `/opt/diagnostic-agent/logs/agent.log`. You should see an immediate security alert log:
```
[WARN] [SECURITY_ALERT] [WEBSHELL_DETECTED] Executable file dropped in writable path: /var/www/html/wp-content/uploads/test_scan.php
```
Clean up the test file:
```bash
rm /var/www/html/wp-content/uploads/test_scan.php
```

---

## Production Security Checklist

- [x] Secrets scrubbed (`SecretRedactor` enabled for passwords, authorization headers, cookies).
- [x] Fail-open mode active (SDK does not crash host PHP script if storage/network is full).
- [x] Non-root user execution (`diag-agent`).
- [x] TLS 1.3 encrypted HTTPS transmission to Cloud Ingestion API.
- [x] Inotify limits updated (`sysctl`).
- [x] Log rotation configured for `/opt/diagnostic-agent/logs/agent.log`.
