# HoatzinGenz Protection — High-Performance Go Server & Control Panel

Welcome to **HoatzinGenz Protection**, an enterprise-grade, ultra-fast, and secure server management panel and diagnostic security suite built entirely in **Go (Golang)** with a modern **React 19 + Tailwind CSS** frontend.

By using Go as the core server language instead of heavy frameworks, the entire control panel operates as a single compiled binary consuming less than **20MB of RAM** with sub-millisecond API response times.

---

## 🚀 Key Advantages of the Go Architecture

1. **Ultra-Fast & Lightweight**: Sub-millisecond execution speeds, ~15-20MB RAM usage total.
2. **Single Compiled Binary**: No PHP-FPM, Python runtime, or heavy dependencies required for the control panel itself.
3. **Native Kernel Integration**: Linux `inotify` file integrity monitoring (FIM), shell process execution tracking (`www-data` shell monitoring), and hardware telemetry direct from the system.
4. **Embedded Web UI**: React single-page dashboard embedded into the Go binary for 1-file distribution.

---

## 📂 Project Architecture

```
hoatzingenz-protection/
├── api/                       # Go High-Performance REST API Server
│   ├── handlers/              # Handlers (Websites, Security, Telemetry, Databases, Email)
│   ├── models/                # Struct schemas for Websites, SecurityEvents, Metrics
│   └── services/              # Memory/SQLite Store & VPS automation engine
├── cmd/
│   ├── server/                # Go Main Server binary (Main Control Panel & API)
│   └── agent/                 # Go Security Daemon binary (Inotify FIM + Process Watcher)
├── config/                    # YAML configuration files
├── diagnostic-agent/          # Native Go Linux Kernel Daemon
├── diagnostic-sdk/            # PHP Telemetry SDK
├── wordpress-plugin/          # Pre-installed WordPress Security Plugin
├── web/                       # React 19 + TypeScript + Tailwind CSS Web UI
│   ├── src/
│   │   ├── App.tsx            # Control Panel UI Dashboard
│   │   └── main.tsx
│   ├── package.json
│   └── vite.config.ts
├── go.mod                     # Go Module configuration
└── features.md                # Feature & Architecture documentation
```

---

## 🌟 Core Features

### 🌐 CloudPanel-Style Website & VHost Manager
* **Virtual Hosts Management**: Create and manage domain virtual hosts (`/api/v1/websites`).
* **Multi-PHP Support**: Assign PHP versions (PHP 8.1, 8.2, 8.3, 8.4) with isolated FPM sockets.
* **Stack Presets**: Presets for WordPress, Laravel, Generic PHP, and Node.js reverse proxy apps.
* **Let's Encrypt SSL**: Automatic ACME SSL issuance and renewal.

### 🛡️ Kernel-Level Security & FIM Engine
* **File Integrity Monitoring (FIM)**: Real-time Linux kernel `inotify` alerts for file drops or edits across `/var/www/`.
* **Process Watcher**: Detects suspicious shell executions (`sh`, `bash`, `curl`, `wget`, `netcat`) spawned by web servers (`www-data`).
* **Webshell Auto-Quarantine**: Automatically isolates uploaded PHP web shells into `/opt/diagnostic-agent/quarantine`.

### 📈 Real-Time Server Monitoring
* **Hardware Telemetry**: Live CPU Load %, Memory (RAM) %, and Disk Storage gauges.
* **System Load Averages**: Linux 1-min, 5-min, and 15-min load average collection.

### 📧 Mail & Database Management
* **Database Manager**: MariaDB / MySQL database creation, size tracking, user privileges.
* **Mail Server Manager**: Postfix + Dovecot virtual domain mailboxes, aliases, and Maildir storage management.

---

## 💻 How to Run & Test Locally in WSL (Ubuntu / Debian)

Open your **WSL terminal** and follow these steps:

### Step 1: Open WSL Project Folder
```bash
cd /mnt/d/SajibPro/Server/hoatzingenz-protection
```

### Step 2: Run the Go Control Panel Engine
```bash
# Start the Go REST API Server on port 8080
go run cmd/server/main.go
```

The Go server will start listening at **http://localhost:8080**.

### Step 3: Run the React Web UI Dev Server
In a second WSL terminal:
```bash
cd /mnt/d/SajibPro/Server/hoatzingenz-protection/web
npm install
npm run dev
```

Open **http://localhost:3000** in your browser to view the Control Panel UI!

---

## 🧪 Test Real-Time Security Alerts via CLI

Run this `curl` command in WSL to send a simulated Security Alert to the Go engine:

```bash
curl -X POST http://localhost:8080/api/v1/security/telemetry \
  -H "Content-Type: application/json" \
  -d '{
    "event_type": "WEBSHELL_DETECTED",
    "severity": "critical",
    "source": "go-inotify-daemon",
    "target_path": "/var/www/html/wp-content/uploads/c99_shell.php",
    "is_quarantined": true
  }'
```

Click on **Security Center** in the React UI at **http://localhost:3000** to see the alert recorded live!
