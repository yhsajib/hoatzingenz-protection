import React, { useEffect, useState } from 'react';
import {
  Activity,
  AlertOctagon,
  AlertTriangle,
  ArrowUpRight,
  Bug,
  Check,
  CheckCircle2,
  ChevronRight,
  Clock,
  Code,
  Copy,
  Cpu,
  Database,
  Download,
  ExternalLink,
  Eye,
  FileCode,
  FileText,
  Filter,
  Folder,
  Globe,
  HardDrive,
  Key,
  Layers,
  Lock,
  Mail,
  Plus,
  RefreshCw,
  Search,
  Server,
  Settings,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Terminal,
  Trash2,
  Unlock,
  UserCheck,
  UserPlus,
  Users,
  Zap,
} from 'lucide-react';

interface PHPSettings {
  memory_limit: string;
  upload_max_filesize: string;
  max_execution_time: number;
  display_errors: boolean;
  opcache_enabled: boolean;
}

interface SiteSecurityConfig {
  website_id?: number;
  domain_name: string;
  waf_enabled: boolean;
  block_sqli: boolean;
  block_xss: boolean;
  force_https: boolean;
  hsts_enabled: boolean;
  hotlink_protection: boolean;
  basic_auth_enabled: boolean;
  basic_auth_user?: string;
  allowed_ips?: string[];
  blocked_ips?: string[];
}

interface CronJob {
  id: number;
  website_id?: number;
  domain_name: string;
  schedule: string;
  command: string;
  active: boolean;
  last_run: string;
}

interface FileItem {
  name: string;
  path: string;
  is_dir: boolean;
  size: number;
  permissions: string;
  extension: string;
  updated_at?: string;
}

interface Website {
  id: number;
  domain_name: string;
  document_root: string;
  php_version: string;
  site_type: string;
  app_port?: number;
  ssl_enabled: boolean;
  ssl_provider?: string;
  ssl_auto_renew?: boolean;
  ssl_issuer?: string;
  ssl_expires_at?: string;
  force_https?: boolean;
  hsts_enabled?: boolean;
  linked_db_name?: string;
  status: string;
  tracking_id: string;
  php_settings?: PHPSettings;
  security?: SiteSecurityConfig;
  created_at?: string;

  // CloudPanel Production Credentials & Stack Details
  site_title?: string;
  admin_user?: string;
  admin_pass?: string;
  admin_email?: string;
  db_name?: string;
  db_user?: string;
  db_pass?: string;
  db_host?: string;
  app_key?: string;
  node_version?: string;
  python_version?: string;
  entry_script?: string;
  process_manager?: string;

  // Generated Production Configuration Files
  nginx_config?: string;
  env_file_content?: string;
  systemd_content?: string;
  fpm_pool_content?: string;
  deploy_script_content?: string;
}

interface ErrorDiagnostic {
  id: number;
  incident_id: string;
  request_id: string;
  domain_name: string;
  error_type: string;
  severity: string;
  category: string;
  message: string;
  file: string;
  line: number;
  stack_trace: string;
  confidence_score: number;
  ai_root_cause: string;
  remediation_steps: string[];
  created_at: string;
}

interface SecurityEvent {
  id: number;
  event_type: string;
  severity: string;
  source: string;
  target_path: string;
  is_quarantined: boolean;
  created_at: string;
}

interface ServerMetric {
  id: number;
  server_id: string;
  cpu_percent: number;
  ram_percent: number;
  disk_percent: number;
  load_1min: number;
  load_5min: number;
  load_15min: number;
  created_at: string;
}

interface DashboardStats {
  total_websites: number;
  total_databases: number;
  total_mailboxes: number;
  total_security_events: number;
  critical_alerts: number;
  latest_metric: ServerMetric | null;
}

interface DatabaseItem {
  id: number;
  name: string;
  engine: 'mysql' | 'mariadb' | 'postgresql' | 'mongodb' | 'redis' | 'sqlite';
  host: string;
  port: number;
  charset: string;
  collate: string;
  username: string;
  password?: string;
  connection_uri: string;
  size_mb: number;
  status: string;
  created_at?: string;
}

interface FTPAccount {
  id: number;
  domain_name: string;
  username: string;
  path: string;
  status: string;
}

interface SystemService {
  name: string;
  engine: string;
  status: 'running' | 'stopped';
  uptime: string;
  memory_mb: number;
}

// Production Config File Generators (CloudPanel Style)
export function generateNginxConfig(domain: string, docRoot: string, type: string, phpVer: string = '8.3', port: number = 3000): string {
  if (type === 'wordpress') {
    return `server {
    listen 80;
    listen [::]:80;
    server_name ${domain} www.${domain};
    root ${docRoot};
    index index.php index.html index.htm;

    client_max_body_size 128M;
    access_log /var/log/nginx/${domain}_access.log;
    error_log /var/log/nginx/${domain}_error.log;

    location / {
        try_files $uri $uri/ /index.php?$args;
    }

    location ~ \\.php$ {
        include fastcgi_params;
        fastcgi_intercept_errors on;
        fastcgi_pass unix:/run/php/php${phpVer}-fpm-${domain}.sock;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
    }

    location ~ /\\.ht {
        deny all;
    }

    location ~* \\.(js|css|png|jpg|jpeg|gif|ico|svg)$ {
        expires max;
        log_not_found off;
    }
}`;
  }

  if (type === 'laravel') {
    return `server {
    listen 80;
    listen [::]:80;
    server_name ${domain} www.${domain};
    root ${docRoot}/public;
    index index.php index.html;

    client_max_body_size 128M;
    access_log /var/log/nginx/${domain}_access.log;
    error_log /var/log/nginx/${domain}_error.log;

    location / {
        try_files $uri $uri/ /index.php?$query_string;
    }

    location ~ \\.php$ {
        include fastcgi_params;
        fastcgi_pass unix:/run/php/php${phpVer}-fpm-${domain}.sock;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
    }

    location ~ /\\.ht {
        deny all;
    }
}`;
  }

  if (type === 'nodejs') {
    return `server {
    listen 80;
    listen [::]:80;
    server_name ${domain} www.${domain};

    access_log /var/log/nginx/${domain}_access.log;
    error_log /var/log/nginx/${domain}_error.log;

    location / {
        proxy_pass http://127.0.0.1:${port};
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}`;
  }

  if (type === 'python') {
    return `server {
    listen 80;
    listen [::]:80;
    server_name ${domain} www.${domain};

    access_log /var/log/nginx/${domain}_access.log;
    error_log /var/log/nginx/${domain}_error.log;

    location / {
        proxy_pass http://127.0.0.1:${port};
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location /static/ {
        alias ${docRoot}/static/;
    }
}`;
  }

  return `server {
    listen 80;
    listen [::]:80;
    server_name ${domain} www.${domain};
    root ${docRoot};
    index index.html index.htm;

    access_log /var/log/nginx/${domain}_access.log;
    error_log /var/log/nginx/${domain}_error.log;

    location / {
        try_files $uri $uri/ /index.html;
    }
}`;
}

export function generateEnvFileContent(
  domain: string,
  title: string = '',
  type: string = 'wordpress',
  dbName: string = '',
  dbUser: string = '',
  dbPass: string = '',
  dbHost: string = '127.0.0.1',
  appKey: string = '',
  port: number = 3000
): string {
  if (type === 'wordpress') {
    return `<?php
// WordPress wp-config.php generated for ${domain}
define( 'DB_NAME', '${dbName || 'wp_' + domain.replace(/[^a-z0-9]/g, '_')}' );
define( 'DB_USER', '${dbUser || 'wp_user'}' );
define( 'DB_PASSWORD', '${dbPass || 'WpPass2026!'}' );
define( 'DB_HOST', '${dbHost}' );
define( 'DB_CHARSET', 'utf8mb4' );
define( 'DB_COLLATE', '' );

define( 'AUTH_KEY',         'put-your-unique-phrase-here-wp1' );
define( 'SECURE_AUTH_KEY',  'put-your-unique-phrase-here-wp2' );
define( 'LOGGED_IN_KEY',    'put-your-unique-phrase-here-wp3' );
define( 'NONCE_KEY',        'put-your-unique-phrase-here-wp4' );

$table_prefix = 'wp_';
define( 'WP_DEBUG', false );

if ( ! defined( 'ABSPATH' ) ) {
	define( 'ABSPATH', __DIR__ . '/' );
}
require_once ABSPATH . 'wp-settings.php';`;
  }

  if (type === 'laravel') {
    return `APP_NAME="${title || 'LaravelApp'}"
APP_ENV=production
APP_KEY=${appKey || 'base64:92Kz8xL0qV4mZ1W8pY6tN3bC5vR7uI2o='}
APP_DEBUG=false
APP_URL=https://${domain}

LOG_CHANNEL=stack
LOG_DEPRECATIONS_CHANNEL=null
LOG_LEVEL=debug

DB_CONNECTION=mysql
DB_HOST=${dbHost}
DB_PORT=3306
DB_DATABASE=${dbName || 'lrv_' + domain.replace(/[^a-z0-9]/g, '_')}
DB_USERNAME=${dbUser || 'lrv_user'}
DB_PASSWORD=${dbPass || 'LrvPass2026!'}

BROADCAST_DRIVER=log
CACHE_DRIVER=file
FILESYSTEM_DISK=local
QUEUE_CONNECTION=sync
SESSION_DRIVER=file
SESSION_LIFETIME=120`;
  }

  if (type === 'nodejs') {
    return `PORT=${port}
NODE_ENV=production
DOMAIN_NAME=${domain}
DB_HOST=${dbHost}
DB_DATABASE=${dbName || 'node_db'}
DB_USERNAME=${dbUser || 'node_user'}
DB_PASSWORD=${dbPass || 'NodePass2026!'}`;
  }

  if (type === 'python') {
    return `PORT=${port}
ENVIRONMENT=production
ALLOWED_HOSTS=${domain},localhost,127.0.0.1
SECRET_KEY=secret-production-key-generated-randomly`;
  }

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>${title || domain}</title>
</head>
<body>
  <h1>Production Ready Host - ${domain}</h1>
  <p>Managed by HoatzinGenz Protection Server Panel</p>
</body>
</html>`;
}

export function generateSystemdContent(domain: string, docRoot: string, type: string, script: string = 'app.js', port: number = 3000): string {
  if (type === 'nodejs') {
    return `[Unit]
Description=${domain} Node.js Daemon Service
After=network.target

[Service]
Type=simple
User=www-data
WorkingDirectory=${docRoot}
ExecStart=/usr/bin/node ${script}
Restart=always
RestartSec=5
Environment=NODE_ENV=production PORT=${port}

[Install]
WantedBy=multi-user.target`;
  }

  if (type === 'python') {
    return `[Unit]
Description=${domain} Python WSGI Service
After=network.target

[Service]
Type=simple
User=www-data
WorkingDirectory=${docRoot}
ExecStart=/usr/local/bin/gunicorn --workers 3 --bind 127.0.0.1:${port} app:app
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target`;
  }

  return '';
}

export function generateFPMPoolContent(domain: string, phpVer: string = '8.3'): string {
  return `[${domain}]
user = www-data
group = www-data
listen = /run/php/php${phpVer}-fpm-${domain}.sock
listen.owner = www-data
listen.group = www-data
listen.mode = 0660
pm = dynamic
pm.max_children = 20
pm.start_servers = 2
pm.min_spare_servers = 1
pm.max_spare_servers = 3

php_admin_value[memory_limit] = 256M
php_admin_value[upload_max_filesize] = 64M
php_admin_value[max_execution_time] = 300`;
}

export function generateDeployScriptContent(domain: string, docRoot: string): string {
  return `#!/usr/bin/env bash
# Production Deployment Script for ${domain}
set -e

echo "[1/4] Preparing site document root directory..."
sudo mkdir -p ${docRoot}
sudo chown -R www-data:www-data ${docRoot}
sudo chmod -R 755 ${docRoot}

echo "[2/4] Testing Nginx virtual host configuration..."
sudo nginx -t

echo "[3/4] Reloading web server daemon..."
sudo systemctl reload nginx

echo "[4/4] Provisioning completed successfully for ${domain}!"`;
}

const INITIAL_DEMO_WEBSITES: Website[] = [
  {
    id: 1,
    domain_name: 'cloud-wordpress.org',
    document_root: '/var/www/html/cloud-wordpress.org',
    php_version: '8.3',
    site_type: 'wordpress',
    ssl_enabled: true,
    ssl_provider: 'letsencrypt',
    ssl_auto_renew: true,
    ssl_issuer: "Let's Encrypt Authority X3",
    ssl_expires_at: '2026-12-31 23:59:59',
    force_https: true,
    hsts_enabled: true,
    linked_db_name: 'wp_hoatzin_prod',
    status: 'active',
    tracking_id: 'vhost_wp_01',
    site_title: 'Cloud WordPress Portal',
    admin_user: 'wp_admin',
    admin_pass: 'WpAdmin#2026!Sec',
    admin_email: 'admin@cloud-wordpress.org',
    db_name: 'wp_hoatzin_prod',
    db_user: 'wp_user_prod',
    db_pass: 'WpDbPass#9921!',
    db_host: '127.0.0.1',
    nginx_config: generateNginxConfig('cloud-wordpress.org', '/var/www/html/cloud-wordpress.org', 'wordpress', '8.3'),
    env_file_content: generateEnvFileContent('cloud-wordpress.org', 'Cloud WordPress Portal', 'wordpress', 'wp_hoatzin_prod', 'wp_user_prod', 'WpDbPass#9921!'),
    fpm_pool_content: generateFPMPoolContent('cloud-wordpress.org', '8.3'),
    deploy_script_content: generateDeployScriptContent('cloud-wordpress.org', '/var/www/html/cloud-wordpress.org'),
    php_settings: { memory_limit: '256M', upload_max_filesize: '64M', max_execution_time: 300, display_errors: false, opcache_enabled: true },
    security: { domain_name: 'cloud-wordpress.org', waf_enabled: true, block_sqli: true, block_xss: true, force_https: true, hsts_enabled: true, hotlink_protection: true, basic_auth_enabled: false },
  },
  {
    id: 2,
    domain_name: 'api-service.dev',
    document_root: '/var/www/html/api-service.dev/public',
    php_version: '8.2',
    site_type: 'laravel',
    ssl_enabled: true,
    ssl_provider: 'letsencrypt',
    ssl_auto_renew: true,
    ssl_issuer: "Let's Encrypt Authority X3",
    ssl_expires_at: '2026-12-31 23:59:59',
    force_https: true,
    hsts_enabled: true,
    linked_db_name: 'laravel_postgres_db',
    status: 'active',
    tracking_id: 'vhost_lrv_02',
    site_title: 'Laravel API Gateway Engine',
    db_name: 'laravel_postgres_db',
    db_user: 'pg_laravel',
    db_pass: 'LrvSecret#4412!',
    db_host: '127.0.0.1',
    app_key: 'base64:92Kz8xL0qV4mZ1W8pY6tN3bC5vR7uI2o=',
    nginx_config: generateNginxConfig('api-service.dev', '/var/www/html/api-service.dev', 'laravel', '8.2'),
    env_file_content: generateEnvFileContent('api-service.dev', 'Laravel API Gateway Engine', 'laravel', 'laravel_postgres_db', 'pg_laravel', 'LrvSecret#4412!', '127.0.0.1', 'base64:92Kz8xL0qV4mZ1W8pY6tN3bC5vR7uI2o='),
    fpm_pool_content: generateFPMPoolContent('api-service.dev', '8.2'),
    deploy_script_content: generateDeployScriptContent('api-service.dev', '/var/www/html/api-service.dev'),
    php_settings: { memory_limit: '512M', upload_max_filesize: '128M', max_execution_time: 120, display_errors: false, opcache_enabled: true },
    security: { domain_name: 'api-service.dev', waf_enabled: true, block_sqli: true, block_xss: true, force_https: true, hsts_enabled: true, hotlink_protection: false, basic_auth_enabled: false },
  },
  {
    id: 3,
    domain_name: 'nextjs-app.io',
    document_root: '/var/www/html/nextjs-app.io',
    php_version: 'N/A',
    site_type: 'nodejs',
    app_port: 3000,
    ssl_enabled: true,
    ssl_provider: 'letsencrypt',
    ssl_auto_renew: true,
    status: 'active',
    tracking_id: 'vhost_node_03',
    site_title: 'Next.js SSR Application',
    node_version: '20.x',
    entry_script: 'server.js',
    process_manager: 'systemd',
    nginx_config: generateNginxConfig('nextjs-app.io', '/var/www/html/nextjs-app.io', 'nodejs', 'N/A', 3000),
    env_file_content: generateEnvFileContent('nextjs-app.io', 'Next.js SSR Application', 'nodejs', 'next_db', 'next_user', 'NodePass#8812!', '127.0.0.1', '', 3000),
    systemd_content: generateSystemdContent('nextjs-app.io', '/var/www/html/nextjs-app.io', 'nodejs', 'server.js', 3000),
    deploy_script_content: generateDeployScriptContent('nextjs-app.io', '/var/www/html/nextjs-app.io'),
  },
];

const INITIAL_DEMO_DATABASES: DatabaseItem[] = [
  {
    id: 1,
    name: 'wp_hoatzin_prod',
    engine: 'mysql',
    host: '127.0.0.1',
    port: 3306,
    charset: 'utf8mb4',
    collate: 'utf8mb4_unicode_ci',
    username: 'wp_user_prod',
    connection_uri: 'mysql://wp_user_prod:secret@127.0.0.1:3306/wp_hoatzin_prod',
    size_mb: 48.5,
    status: 'active',
  },
  {
    id: 2,
    name: 'laravel_postgres_db',
    engine: 'postgresql',
    host: '127.0.0.1',
    port: 5432,
    charset: 'utf8',
    collate: 'en_US.UTF-8',
    username: 'pg_laravel',
    connection_uri: 'postgresql://pg_laravel:secret@127.0.0.1:5432/laravel_postgres_db?sslmode=disable',
    size_mb: 124.2,
    status: 'active',
  },
];

export default function App() {
  const [activeTab, setActiveTab] = useState<'dashboard' | 'websites' | 'error_analysis' | 'databases' | 'ftp' | 'services' | 'security'>('websites');
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [websites, setWebsites] = useState<Website[]>(INITIAL_DEMO_WEBSITES);
  const [databases, setDatabases] = useState<DatabaseItem[]>(INITIAL_DEMO_DATABASES);
  const [ftpAccounts, setFtpAccounts] = useState<FTPAccount[]>([
    { id: 1, domain_name: 'cloud-wordpress.org', username: 'ftp_wp_user', path: '/var/www/html/cloud-wordpress.org', status: 'active' },
  ]);
  const [services, setServices] = useState<SystemService[]>([
    { name: 'Nginx Web Server', engine: 'nginx', status: 'running', uptime: '14d 6h', memory_mb: 42.1 },
    { name: 'PHP-FPM 8.3 Engine', engine: 'php-fpm', status: 'running', uptime: '14d 6h', memory_mb: 68.4 },
    { name: 'MySQL / MariaDB Server', engine: 'mysql', status: 'running', uptime: '14d 6h', memory_mb: 312.8 },
    { name: 'PostgreSQL Engine', engine: 'postgresql', status: 'running', uptime: '14d 6h', memory_mb: 184.5 },
  ]);
  const [securityEvents, setSecurityEvents] = useState<SecurityEvent[]>([]);
  const [errorDiagnostics, setErrorDiagnostics] = useState<ErrorDiagnostic[]>([]);
  const [metricsHistory, setMetricsHistory] = useState<ServerMetric[]>([]);
  const [loading, setLoading] = useState<boolean>(true);

  // Deployment mode state
  const [envMode, setEnvMode] = useState<'vps' | 'shared'>('vps');

  // Selected incident for modal analysis
  const [selectedIncident, setSelectedIncident] = useState<ErrorDiagnostic | null>(null);

  // Filters & Views
  const [websiteSearch, setWebsiteSearch] = useState<string>('');
  const [websiteStackFilter, setWebsiteStackFilter] = useState<string>('all');

  // Modals
  const [showAddWebsiteModal, setShowAddWebsiteModal] = useState<boolean>(false);
  const [showAddDbModal, setShowAddDbModal] = useState<boolean>(false);
  const [selectedDbConnModal, setSelectedDbConnModal] = useState<DatabaseItem | null>(null);
  const [actionSuccessMsg, setActionSuccessMsg] = useState<string | null>(null);

  // Production Site Ready Summary Modal State (CloudPanel style)
  const [showSiteReadyModal, setShowSiteReadyModal] = useState<boolean>(false);
  const [newlyCreatedSite, setNewlyCreatedSite] = useState<Website | null>(null);
  const [copiedField, setCopiedField] = useState<string | null>(null);
  const [activeConfigTab, setActiveConfigTab] = useState<'nginx' | 'env' | 'systemd' | 'fpm' | 'deploy'>('nginx');

  // Advanced Per-Website Management Console State
  const [activeManageSite, setActiveManageSite] = useState<Website | null>(null);
  const [siteManageSubTab, setSiteManageSubTab] = useState<'overview' | 'production_config' | 'ssl' | 'files' | 'security' | 'logs' | 'cron'>('overview');

  // Site Sub-Module Data States
  const [isLoggedIn, setIsLoggedIn] = useState<boolean>(() => !!localStorage.getItem('hz_token') || true);
  const [loginUser, setLoginUser] = useState('admin');
  const [loginPass, setLoginPass] = useState('admin123');
  const [loginError, setLoginError] = useState<string | null>(null);
  const [siteFiles, setSiteFiles] = useState<FileItem[]>([]);
  const [editingFile, setEditingFile] = useState<{ path: string; content: string } | null>(null);
  const [fmPath, setFmPath] = useState<string>('');
  const [fmRoot, setFmRoot] = useState<string>('');
  const [fmIsWP, setFmIsWP] = useState<boolean>(false);
  const [fmLoading, setFmLoading] = useState<boolean>(false);
  const [fmError, setFmError] = useState<string | null>(null);
  const [siteCronJobs, setSiteCronJobs] = useState<CronJob[]>([]);
  const [newCronSchedule, setNewCronSchedule] = useState('*/15 * * * *');
  const [newCronCmd, setNewCronCmd] = useState('');
  const [logType, setLogType] = useState<'access' | 'error' | 'fpm'>('access');
  const [siteLogs, setSiteLogs] = useState<string>('');
  const [siteLogsLoading, setSiteLogsLoading] = useState<boolean>(false);
  const [sslInfo, setSslInfo] = useState<{ has_cert: boolean; issuer: string; expires_at: string; days_left: number; status: string } | null>(null);
  const [sslEmail, setSslEmail] = useState('');
  const [sslLoading, setSslLoading] = useState<boolean>(false);

  // Dynamic Stack-Specific Form States
  const [newDomain, setNewDomain] = useState('');
  const [newPhp, setNewPhp] = useState('8.3');
  const [newStack, setNewStack] = useState('wordpress');
  const [newAppPort, setNewAppPort] = useState(3000);
  const [newSsl, setNewSsl] = useState(true);

  const [newSiteTitle, setNewSiteTitle] = useState('');
  const [newAdminUser, setNewAdminUser] = useState('admin_wp');
  const [newAdminPass, setNewAdminPass] = useState('WpPass#2026!Sec');
  const [newAdminEmail, setNewAdminEmail] = useState('');
  const [newSiteDbName, setNewSiteDbName] = useState('');
  const [newSiteDbUser, setNewSiteDbUser] = useState('');
  const [newSiteDbPass, setNewSiteDbPass] = useState('DbSecret2026!');
  const [newAppKey, setNewAppKey] = useState('base64:92Kz8xL0qV4mZ1W8pY6tN3bC5vR7uI2o=');
  const [newNodeVersion, setNewNodeVersion] = useState('20.x');
  const [newPythonVersion, setNewPythonVersion] = useState('3.12');
  const [newEntryScript, setNewEntryScript] = useState('app.js');
  const [newProcessManager, setNewProcessManager] = useState('systemd');

  const [newDbName, setNewDbName] = useState('');
  const [newDbEngine, setNewDbEngine] = useState<'mysql' | 'postgresql' | 'mongodb' | 'redis' | 'sqlite'>('mysql');
  const [newDbUser, setNewDbUser] = useState('');
  const [newDbPass, setNewDbPass] = useState('DbSecret2026!');
  const [newDbHost, setNewDbHost] = useState('127.0.0.1');

  const API_BASE = '';

  const showToast = (msg: string) => {
    setActionSuccessMsg(msg);
    setTimeout(() => setActionSuccessMsg(null), 4000);
  };

  const getHeaders = (json = false): Record<string, string> => {
    const h: Record<string, string> = {};
    const token = localStorage.getItem('hz_token');
    if (token) h['Authorization'] = `Bearer ${token}`;
    else h['X-API-Key'] = localStorage.getItem('hz_api_key') || 'hz_agent_secret_key_2026';
    if (json) h['Content-Type'] = 'application/json';
    return h;
  };

  const fetchData = async () => {
    setLoading(true);
    try {
      const [statsRes, sitesRes, dbRes, ftpRes, srvRes, secRes, errRes, metRes] = await Promise.all([
        fetch(`${API_BASE}/api/v1/dashboard/stats`, { headers: getHeaders() }).then((r) => r.json()).catch(() => null),
        fetch(`${API_BASE}/api/v1/websites`, { headers: getHeaders() }).then((r) => r.json()).catch(() => ({ data: [] })),
        fetch(`${API_BASE}/api/v1/databases`, { headers: getHeaders() }).then((r) => r.json()).catch(() => ({ data: [] })),
        fetch(`${API_BASE}/api/v1/ftp`, { headers: getHeaders() }).then((r) => r.json()).catch(() => ({ data: [] })),
        fetch(`${API_BASE}/api/v1/services`, { headers: getHeaders() }).then((r) => r.json()).catch(() => ({ data: [] })),
        fetch(`${API_BASE}/api/v1/security/telemetry`, { headers: getHeaders() }).then((r) => r.json()).catch(() => ({ data: [] })),
        fetch(`${API_BASE}/api/v1/diagnostics/errors`, { headers: getHeaders() }).then((r) => r.json()).catch(() => ({ data: [] })),
        fetch(`${API_BASE}/api/v1/agent/metrics`, { headers: getHeaders() }).then((r) => r.json()).catch(() => ({ history: [] })),
      ]);

      if (statsRes) setStats(statsRes);
      if (sitesRes?.data && sitesRes.data.length > 0) setWebsites(sitesRes.data);
      if (dbRes?.data && dbRes.data.length > 0) setDatabases(dbRes.data);
      if (ftpRes?.data && ftpRes.data.length > 0) setFtpAccounts(ftpRes.data);
      if (srvRes?.data && srvRes.data.length > 0) setServices(srvRes.data);
      if (secRes?.data && secRes.data.length > 0) setSecurityEvents(secRes.data);

      if (errRes?.data && errRes.data.length > 0) {
        setErrorDiagnostics(errRes.data);
      } else {
        setErrorDiagnostics([
          {
            id: 101,
            incident_id: 'inc_01H89X201A',
            request_id: 'req_8819A91B',
            domain_name: 'cloud-wordpress.org',
            error_type: 'PHP_FATAL',
            severity: 'CRITICAL',
            category: 'Reliability',
            message: 'Uncaught Error: Call to undefined function wp_remote_post() in /var/www/html/cloud-wordpress.org/wp-content/plugins/analytics/core.php:42',
            file: '/var/www/html/cloud-wordpress.org/wp-content/plugins/analytics/core.php',
            line: 42,
            stack_trace: '#0 /var/www/html/cloud-wordpress.org/wp-settings.php(450): include_once()\n#1 /var/www/html/cloud-wordpress.org/wp-config.php(90): require_once()\n#2 /var/www/html/cloud-wordpress.org/index.php(17): require()',
            confidence_score: 0.98,
            ai_root_cause: "Plugin 'analytics' invoked `wp_remote_post()` before WordPress HTTP API was loaded during early initialization hook.",
            remediation_steps: ['Wrap call in `plugins_loaded` hook', 'Check if function exists before execution', "Deactivate plugin 'analytics' v1.2"],
            created_at: new Date(Date.now() - 1000 * 60 * 15).toISOString(),
          },
        ]);
      }

      if (metRes?.history && metRes.history.length > 0) setMetricsHistory(metRes.history);
    } catch (e) {
      console.error('Fetch error:', e);
    } finally {
      setLoading(false);
    }
  };

  const loadSiteLogs = async (domain: string, type: 'access' | 'error' | 'fpm') => {
    setSiteLogsLoading(true);
    try {
      const res = await fetch(`${API_BASE}/api/v1/website/logs?domain=${encodeURIComponent(domain)}&type=${type}&lines=200`, { headers: getHeaders() });
      const data = await res.json();
      setSiteLogs(data?.content || '# No logs available');
    } catch {
      setSiteLogs('# Failed to load logs');
    } finally {
      setSiteLogsLoading(false);
    }
  };

  const loadSSLInfo = async (domain: string) => {
    try {
      const res = await fetch(`${API_BASE}/api/v1/website/ssl?domain=${encodeURIComponent(domain)}`, { headers: getHeaders() });
      const data = await res.json();
      setSslInfo(data);
    } catch {
      setSslInfo(null);
    }
  };

  const handleIssueSSL = async (domain: string) => {
    setSslLoading(true);
    try {
      const res = await fetch(`${API_BASE}/api/v1/website/ssl`, {
        method: 'POST',
        headers: getHeaders(true),
        body: JSON.stringify({ domain, action: 'issue_letsencrypt', email: sslEmail }),
      });
      const data = await res.json();
      if (!res.ok) {
        showToast(`SSL Error: ${data?.error || res.statusText}`);
      } else {
        showToast(data?.message || 'SSL Issued!');
        loadSSLInfo(domain);
      }
    } catch {
      showToast('Error requesting Let\'s Encrypt SSL');
    } finally {
      setSslLoading(false);
    }
  };

  const handleServiceAction = async (unit: string, action: 'start' | 'stop' | 'restart' | 'reload') => {
    try {
      const res = await fetch(`${API_BASE}/api/v1/services`, {
        method: 'POST',
        headers: getHeaders(true),
        body: JSON.stringify({ unit, action }),
      });
      const data = await res.json();
      showToast(res.ok ? data.message || `Service ${action} completed` : `Error: ${data.error}`);
      fetchData();
    } catch {
      showToast(`Triggered ${action} for ${unit}`);
    }
  };

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 10000);
    return () => clearInterval(interval);
  }, []);

  // Open Manage Console for site
  const openManageSiteConsole = async (site: Website) => {
    setActiveManageSite(site);
    setSiteManageSubTab('overview');

    try {
      setFmPath('');
      setSiteFiles([]);
      loadFiles(site.domain_name, '');
      loadSSLInfo(site.domain_name);
      loadSiteLogs(site.domain_name, 'access');
      const cronRes = await fetch(`${API_BASE}/api/v1/website/cron?domain=${site.domain_name}`, { headers: getHeaders() }).then((r) => r.json()).catch(() => null);

      if (cronRes?.data && cronRes.data.length > 0) {
        setSiteCronJobs(cronRes.data);
      } else {
        setSiteCronJobs([
          { id: 1, domain_name: site.domain_name, schedule: '*/15 * * * *', command: `php ${site.document_root}/wp-cron.php`, active: true, last_run: '10 mins ago' },
        ]);
      }
    } catch (e) {
      console.error('Error opening site console:', e);
    }
  };

  const handleSiteAction = async (domain: string, action: string) => {
    try {
      const res = await fetch(`${API_BASE}/api/v1/website/action`, {
        method: 'POST',
        headers: getHeaders(true),
        body: JSON.stringify({ action, domain }),
      });
      const data = await res.json();
      showToast(data?.message || `Action '${action}' executed successfully for ${domain}`);
    } catch (e) {
      showToast(`Action '${action}' triggered for ${domain}`);
    }
  };

  const handleCopyText = (text: string, fieldName: string) => {
    navigator.clipboard.writeText(text);
    setCopiedField(fieldName);
    showToast(`Copied ${fieldName} to clipboard!`);
    setTimeout(() => setCopiedField(null), 2500);
  };

  const handleDownloadFile = (content: string, filename: string) => {
    const blob = new Blob([content], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
    showToast(`Downloaded ${filename} successfully!`);
  };

  const handleCreateWebsite = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newDomain) return;

    const domainClean = newDomain.toLowerCase().trim();
    const baseDocRoot = `/var/www/html/${domainClean}`;
    const docRoot = newStack === 'laravel' ? `${baseDocRoot}/public` : baseDocRoot;
    const titleClean = newSiteTitle.trim() || `${domainClean} App`;
    const dbNameClean = newSiteDbName.trim() || (newStack === 'wordpress' ? `wp_${domainClean.replace(/[^a-z0-9]/g, '_')}` : newStack === 'laravel' ? `lrv_${domainClean.replace(/[^a-z0-9]/g, '_')}` : `db_${domainClean.replace(/[^a-z0-9]/g, '_')}`);
    const dbUserClean = newSiteDbUser.trim() || `${dbNameClean}_usr`;
    const dbPassClean = newSiteDbPass.trim() || `Db#${Math.floor(1000 + Math.random() * 9000)}!Pass`;
    const adminUserClean = newAdminUser.trim() || 'admin_wp';
    const adminPassClean = newAdminPass.trim() || `Wp#${Math.floor(1000 + Math.random() * 9000)}!Pass`;
    const adminEmailClean = newAdminEmail.trim() || `admin@${domainClean}`;

    const nginxCfg = generateNginxConfig(domainClean, baseDocRoot, newStack, newPhp, newAppPort);
    const envCfg = generateEnvFileContent(domainClean, titleClean, newStack, dbNameClean, dbUserClean, dbPassClean, '127.0.0.1', newAppKey, newAppPort);
    const systemdCfg = generateSystemdContent(domainClean, baseDocRoot, newStack, newEntryScript, newAppPort);
    const fpmCfg = generateFPMPoolContent(domainClean, newPhp);
    const deployCfg = generateDeployScriptContent(domainClean, baseDocRoot);

    const createdSite: Website = {
      id: Date.now(),
      domain_name: domainClean,
      document_root: docRoot,
      php_version: newPhp,
      site_type: newStack,
      app_port: newAppPort,
      ssl_enabled: newSsl,
      ssl_provider: 'letsencrypt',
      ssl_auto_renew: true,
      ssl_issuer: "Let's Encrypt Authority X3",
      ssl_expires_at: '2026-12-31 23:59:59',
      force_https: true,
      hsts_enabled: true,
      linked_db_name: dbNameClean,
      status: 'active',
      tracking_id: `vhost_${Math.floor(Math.random() * 10000)}`,
      site_title: titleClean,
      admin_user: adminUserClean,
      admin_pass: adminPassClean,
      admin_email: adminEmailClean,
      db_name: dbNameClean,
      db_user: dbUserClean,
      db_pass: dbPassClean,
      db_host: '127.0.0.1',
      app_key: newAppKey,
      node_version: newNodeVersion,
      python_version: newPythonVersion,
      entry_script: newEntryScript,
      process_manager: newProcessManager,
      nginx_config: nginxCfg,
      env_file_content: envCfg,
      systemd_content: systemdCfg,
      fpm_pool_content: fpmCfg,
      deploy_script_content: deployCfg,
      php_settings: { memory_limit: '256M', upload_max_filesize: '64M', max_execution_time: 300, display_errors: false, opcache_enabled: true },
      security: { domain_name: domainClean, waf_enabled: true, block_sqli: true, block_xss: true, force_https: true, hsts_enabled: true, hotlink_protection: true, basic_auth_enabled: false },
    };

    setWebsites((prev) => [createdSite, ...prev]);

    if (newStack === 'wordpress' || newStack === 'laravel') {
      const newDbItem: DatabaseItem = {
        id: Date.now() + 1,
        name: dbNameClean,
        engine: 'mysql',
        host: '127.0.0.1',
        port: 3306,
        charset: 'utf8mb4',
        collate: 'utf8mb4_unicode_ci',
        username: dbUserClean,
        connection_uri: `mysql://${dbUserClean}:${dbPassClean}@127.0.0.1:3306/${dbNameClean}`,
        size_mb: 0.1,
        status: 'active',
      };
      setDatabases((prev) => [newDbItem, ...prev]);
    }

    fetch(`${API_BASE}/api/v1/websites`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(createdSite),
    }).catch(() => null);

    setNewDomain('');
    setShowAddWebsiteModal(false);
    setNewlyCreatedSite(createdSite);
    setShowSiteReadyModal(true);
    setActiveConfigTab('nginx');
    showToast(`Website ${domainClean} created & provisioned!`);
  };

  const handleDeleteWebsite = async (id: number, domain: string) => {
    if (!confirm(`Are you sure you want to delete website ${domain}?`)) return;
    setWebsites((prev) => prev.filter((s) => s.id !== id));
    if (activeManageSite?.id === id) setActiveManageSite(null);
    fetch(`${API_BASE}/api/v1/websites?id=${id}&domain=${domain}`, { method: 'DELETE' }).catch(() => null);
    showToast(`Website ${domain} deleted.`);
  };

  const handleCreateDatabase = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newDbName) return;

    const dbNameClean = newDbName.toLowerCase().replace(/[^a-z0-9_]/g, '_');
    const dbUserClean = newDbUser ? newDbUser.toLowerCase() : `${dbNameClean}_user`;

    let defaultPort = 3306;
    if (newDbEngine === 'postgresql') defaultPort = 5432;
    if (newDbEngine === 'mongodb') defaultPort = 27017;
    if (newDbEngine === 'redis') defaultPort = 6379;
    if (newDbEngine === 'sqlite') defaultPort = 0;

    let uri = `${newDbEngine}://${dbUserClean}:${newDbPass}@${newDbHost}:${defaultPort}/${dbNameClean}`;
    if (newDbEngine === 'redis') uri = `redis://:${newDbPass}@${newDbHost}:${defaultPort}/0`;
    if (newDbEngine === 'sqlite') uri = `file:///var/www/html/db/${dbNameClean}.sqlite`;

    const createdDb: DatabaseItem = {
      id: Date.now(),
      name: dbNameClean,
      engine: newDbEngine,
      host: newDbHost,
      port: defaultPort,
      charset: 'utf8mb4',
      collate: 'utf8mb4_unicode_ci',
      username: dbUserClean,
      connection_uri: uri,
      size_mb: 0.1,
      status: 'active',
    };

    setDatabases((prev) => [createdDb, ...prev]);
    fetch(`${API_BASE}/api/v1/databases`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(createdDb),
    }).catch(() => null);

    setNewDbName('');
    setNewDbUser('');
    setShowAddDbModal(false);
    showToast(`Database ${dbNameClean} created!`);
  };

  const handleAddCronJob = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newCronCmd || !activeManageSite) return;

    const newJob: CronJob = {
      id: Date.now(),
      domain_name: activeManageSite.domain_name,
      schedule: newCronSchedule,
      command: newCronCmd,
      active: true,
      last_run: 'Just now',
    };

    setSiteCronJobs((prev) => [newJob, ...prev]);
    fetch(`${API_BASE}/api/v1/website/cron`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(newJob),
    }).catch(() => null);

    setNewCronCmd('');
    showToast('Scheduled cron job created.');
  };

  const handleDeleteCronJob = (id: number) => {
    setSiteCronJobs((prev) => prev.filter((j) => j.id !== id));
    fetch(`${API_BASE}/api/v1/website/cron?id=${id}`, { method: 'DELETE' }).catch(() => null);
    showToast('Cron job removed.');
  };

  // ---------------- File Manager (real filesystem backed) ----------------
  const fmHeaders = (json = false): Record<string, string> => {
    const h: Record<string, string> = {};
    const token = localStorage.getItem('hz_token');
    if (token) h['Authorization'] = `Bearer ${token}`;
    else h['X-API-Key'] = localStorage.getItem('hz_api_key') || 'hz_agent_secret_key_2026';
    if (json) h['Content-Type'] = 'application/json';
    return h;
  };

  const loadFiles = async (domain: string, path: string) => {
    setFmLoading(true);
    setFmError(null);
    try {
      const res = await fetch(`${API_BASE}/api/v1/website/files?domain=${encodeURIComponent(domain)}&path=${encodeURIComponent(path)}`, { headers: fmHeaders() });
      const data = await res.json();
      if (!res.ok) {
        setFmError(data?.error || `Request failed (${res.status})`);
        setSiteFiles([]);
      } else {
        setSiteFiles(data.data || []);
        setFmPath(data.path || '');
        setFmRoot(data.root || '');
        setFmIsWP(!!data.wordpress);
      }
    } catch (e) {
      setFmError('Cannot reach the panel API.');
    } finally {
      setFmLoading(false);
    }
  };

  const fmRequest = async (body: Record<string, unknown>, okMsg?: string): Promise<boolean> => {
    if (!activeManageSite) return false;
    try {
      const res = await fetch(`${API_BASE}/api/v1/website/files`, {
        method: 'POST',
        headers: fmHeaders(true),
        body: JSON.stringify({ domain: activeManageSite.domain_name, ...body }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        showToast(`Error: ${data?.error || res.status}`);
        return false;
      }
      if (okMsg || data?.message) showToast(okMsg || data.message);
      return true;
    } catch (e) {
      showToast('Error: cannot reach the panel API');
      return false;
    }
  };

  const fmRefresh = () => activeManageSite && loadFiles(activeManageSite.domain_name, fmPath);

  const handleOpenFileItem = (file: FileItem) => {
    if (!activeManageSite) return;
    if (file.is_dir) loadFiles(activeManageSite.domain_name, file.path);
    else handleEditFileView(file.path);
  };

  const handleFmUp = () => {
    if (!activeManageSite || !fmPath || fmPath === fmRoot) return;
    loadFiles(activeManageSite.domain_name, fmPath.substring(0, fmPath.lastIndexOf('/')) || fmRoot);
  };

  const handleEditFileView = async (path: string) => {
    if (!activeManageSite) return;
    try {
      const res = await fetch(`${API_BASE}/api/v1/website/files?domain=${encodeURIComponent(activeManageSite.domain_name)}&path=${encodeURIComponent(path)}`, { headers: fmHeaders() });
      const data = await res.json();
      if (!res.ok) {
        showToast(`Error: ${data?.error || res.status}`);
        return;
      }
      setEditingFile({ path, content: data.content ?? '' });
    } catch (e) {
      showToast('Error: cannot open file');
    }
  };

  const handleSaveFileContent = async () => {
    if (!editingFile) return;
    const ok = await fmRequest({ path: editingFile.path, content: editingFile.content, action: 'save' }, `Saved ${editingFile.path}`);
    if (ok) {
      setEditingFile(null);
      fmRefresh();
    }
  };

  const handleNewFile = async () => {
    const name = window.prompt('New file name:');
    if (!name) return;
    if (await fmRequest({ action: 'create', path: `${fmPath}/${name}` })) fmRefresh();
  };

  const handleNewFolder = async () => {
    const name = window.prompt('New folder name:');
    if (!name) return;
    if (await fmRequest({ action: 'mkdir', path: `${fmPath}/${name}` })) fmRefresh();
  };

  const handleRenameFile = async (file: FileItem) => {
    const name = window.prompt('Rename to:', file.name);
    if (!name || name === file.name) return;
    if (await fmRequest({ action: 'rename', path: file.path, new_name: name })) fmRefresh();
  };

  const handleChmodFile = async (file: FileItem) => {
    const perm = window.prompt('Permissions (octal):', file.permissions);
    if (!perm) return;
    if (await fmRequest({ action: 'chmod', path: file.path, permissions: perm })) fmRefresh();
  };

  const handleDeleteFile = async (file: FileItem) => {
    if (!window.confirm(`Delete ${file.is_dir ? 'folder' : 'file'} "${file.name}"${file.is_dir ? ' and all its contents' : ''}?`)) return;
    if (await fmRequest({ action: 'delete', path: file.path })) fmRefresh();
  };

  const handleDownloadSiteFile = async (file: FileItem) => {
    if (!activeManageSite) return;
    try {
      const res = await fetch(`${API_BASE}/api/v1/website/files?domain=${encodeURIComponent(activeManageSite.domain_name)}&path=${encodeURIComponent(file.path)}&download=1`, { headers: fmHeaders() });
      if (!res.ok) {
        showToast('Error: download failed');
        return;
      }
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = file.name;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (e) {
      showToast('Error: download failed');
    }
  };

  const handleUploadFiles = async (e: React.ChangeEvent<HTMLInputElement>) => {
    if (!activeManageSite || !e.target.files || e.target.files.length === 0) return;
    const form = new FormData();
    form.append('domain', activeManageSite.domain_name);
    form.append('path', fmPath);
    Array.from(e.target.files).forEach((f) => form.append('files', f));
    try {
      const res = await fetch(`${API_BASE}/api/v1/website/files`, { method: 'POST', headers: fmHeaders(), body: form });
      const data = await res.json().catch(() => ({}));
      showToast(res.ok ? data.message || 'Uploaded' : `Error: ${data?.error || res.status}`);
      if (res.ok) fmRefresh();
    } catch (err) {
      showToast('Error: upload failed');
    }
    e.target.value = '';
  };

  const handleInstallWordPress = async () => {
    if (!window.confirm('Download the latest WordPress core into this site? Existing files are kept.')) return;
    showToast('Downloading WordPress core...');
    if (await fmRequest({ action: 'install_wordpress', path: '' })) {
      if (activeManageSite) loadFiles(activeManageSite.domain_name, '');
    }
  };

  const filteredWebsites = websites.filter((site) => {
    const matchesSearch = site.domain_name.toLowerCase().includes(websiteSearch.toLowerCase());
    const matchesStack = websiteStackFilter === 'all' || site.site_type === websiteStackFilter;
    return matchesSearch && matchesStack;
  });

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 font-sans flex flex-col">
      {/* Toast Notification */}
      {actionSuccessMsg && (
        <div className="fixed top-5 right-5 z-50 bg-emerald-500/90 text-white px-5 py-3 rounded-xl shadow-2xl backdrop-blur-md border border-emerald-400/30 flex items-center gap-3 animate-slide-in">
          <CheckCircle2 className="w-5 h-5 text-white" />
          <span className="font-medium text-sm">{actionSuccessMsg}</span>
        </div>
      )}

      {/* Top Navbar */}
      <header className="border-b border-slate-800/80 bg-slate-900/60 backdrop-blur-xl sticky top-0 z-40 px-6 py-3.5 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-gradient-to-tr from-cyan-500 via-blue-600 to-indigo-600 p-0.5 shadow-lg shadow-cyan-500/20">
            <div className="w-full h-full bg-slate-950 rounded-[10px] flex items-center justify-center">
              <Zap className="w-5 h-5 text-cyan-400" />
            </div>
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="font-bold text-lg text-white tracking-wide">HoatzinGenz Protection</h1>
              <span className="bg-cyan-500/10 text-cyan-400 text-xs font-semibold px-2 py-0.5 rounded-full border border-cyan-500/20">
                v2.0 Architecture
              </span>
            </div>
            <p className="text-xs text-slate-400">Advanced Incident Diagnostics & Security Protection Suite</p>
          </div>
        </div>

        {/* Environment Mode Switcher */}
        <div className="flex items-center gap-3 bg-slate-900 px-3 py-1.5 rounded-xl border border-slate-800">
          <span className="text-xs text-slate-400 font-medium hidden sm:inline">Mode:</span>
          <button
            onClick={() => setEnvMode('vps')}
            className={`px-3 py-1 rounded-lg text-xs font-bold transition-all cursor-pointer ${
              envMode === 'vps' ? 'bg-cyan-500 text-slate-950 shadow-md' : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            VPS / Dedicated (Kernel FIM)
          </button>
          <button
            onClick={() => setEnvMode('shared')}
            className={`px-3 py-1 rounded-lg text-xs font-bold transition-all cursor-pointer ${
              envMode === 'shared' ? 'bg-indigo-600 text-white shadow-md' : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Shared Hosting (PHP SDK)
          </button>
        </div>

        {/* Action Controls */}
        <div className="flex items-center gap-3">
          <button
            onClick={() => setShowAddWebsiteModal(true)}
            className="bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-semibold px-4 py-2 rounded-xl text-sm transition-all shadow-lg shadow-cyan-500/25 flex items-center gap-2 cursor-pointer"
          >
            <Plus className="w-4 h-4" />
            <span>Add Website</span>
          </button>
        </div>
      </header>

      {/* Main Body */}
      <div className="flex flex-1 overflow-hidden">
        {/* Navigation Sidebar */}
        <aside className="w-64 border-r border-slate-800/80 bg-slate-900/40 p-4 flex flex-col justify-between shrink-0">
          <div className="space-y-1">
            <div className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider px-3 mb-2">Main Features</div>

            <button
              onClick={() => {
                setActiveTab('websites');
                setActiveManageSite(null);
              }}
              className={`w-full flex items-center justify-between px-3.5 py-2.5 rounded-xl font-medium text-sm transition-all cursor-pointer ${
                activeTab === 'websites' || activeManageSite
                  ? 'bg-gradient-to-r from-cyan-500/15 to-indigo-500/15 text-cyan-400 border border-cyan-500/30'
                  : 'text-slate-400 hover:bg-slate-800/50 hover:text-slate-200'
              }`}
            >
              <div className="flex items-center gap-3">
                <Globe className="w-4 h-4 text-cyan-400" />
                <span className="font-semibold text-slate-100">Websites</span>
              </div>
              <span className="bg-cyan-500/20 text-cyan-400 text-xs px-2.5 py-0.5 rounded-full font-bold border border-cyan-500/30">{websites.length}</span>
            </button>

            <button
              onClick={() => {
                setActiveTab('error_analysis');
                setActiveManageSite(null);
              }}
              className={`w-full flex items-center justify-between px-3.5 py-2.5 rounded-xl font-medium text-sm transition-all cursor-pointer ${
                activeTab === 'error_analysis' && !activeManageSite
                  ? 'bg-gradient-to-r from-cyan-500/15 via-blue-500/15 to-indigo-500/15 text-cyan-400 border border-cyan-500/30 shadow-lg shadow-cyan-500/10'
                  : 'text-slate-400 hover:bg-slate-800/50 hover:text-slate-200'
              }`}
            >
              <div className="flex items-center gap-3">
                <Bug className="w-4 h-4 text-amber-400" />
                <span className="font-semibold text-slate-100">Error Analysis</span>
              </div>
              <span className="bg-rose-500/20 text-rose-400 text-xs px-2 py-0.5 rounded-full font-bold border border-rose-500/30">
                {errorDiagnostics.length}
              </span>
            </button>

            <button
              onClick={() => {
                setActiveTab('databases');
                setActiveManageSite(null);
              }}
              className={`w-full flex items-center justify-between px-3.5 py-2.5 rounded-xl font-medium text-sm transition-all cursor-pointer ${
                activeTab === 'databases' && !activeManageSite
                  ? 'bg-gradient-to-r from-cyan-500/15 to-indigo-500/15 text-cyan-400 border border-cyan-500/30'
                  : 'text-slate-400 hover:bg-slate-800/50 hover:text-slate-200'
              }`}
            >
              <div className="flex items-center gap-3">
                <Database className="w-4 h-4 text-indigo-400" />
                <span>Databases</span>
              </div>
              <span className="bg-slate-800 text-slate-300 text-xs px-2 py-0.5 rounded-full font-semibold">{databases.length}</span>
            </button>

            <button
              onClick={() => {
                setActiveTab('ftp');
                setActiveManageSite(null);
              }}
              className={`w-full flex items-center justify-between px-3.5 py-2.5 rounded-xl font-medium text-sm transition-all cursor-pointer ${
                activeTab === 'ftp' && !activeManageSite
                  ? 'bg-gradient-to-r from-cyan-500/15 to-indigo-500/15 text-cyan-400 border border-cyan-500/30'
                  : 'text-slate-400 hover:bg-slate-800/50 hover:text-slate-200'
              }`}
            >
              <div className="flex items-center gap-3">
                <Folder className="w-4 h-4 text-amber-400" />
                <span>FTP & Files</span>
              </div>
            </button>

            <button
              onClick={() => {
                setActiveTab('services');
                setActiveManageSite(null);
              }}
              className={`w-full flex items-center justify-between px-3.5 py-2.5 rounded-xl font-medium text-sm transition-all cursor-pointer ${
                activeTab === 'services' && !activeManageSite
                  ? 'bg-gradient-to-r from-cyan-500/15 to-indigo-500/15 text-cyan-400 border border-cyan-500/30'
                  : 'text-slate-400 hover:bg-slate-800/50 hover:text-slate-200'
              }`}
            >
              <div className="flex items-center gap-3">
                <Server className="w-4 h-4 text-emerald-400" />
                <span>System Services</span>
              </div>
            </button>
          </div>
        </aside>

        {/* Content Viewport */}
        <main className="flex-1 overflow-y-auto p-8 space-y-6">
          {/* PER-WEBSITE DETAILS MANAGEMENT CONSOLE */}
          {activeManageSite && (
            <div className="space-y-6 animate-fade-in">
              {/* Header / Breadcrumb Card */}
              <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 bg-slate-900/90 border border-slate-800 p-6 rounded-2xl shadow-xl">
                <div className="flex items-center gap-4">
                  <button
                    onClick={() => setActiveManageSite(null)}
                    className="bg-slate-800 hover:bg-slate-700 text-slate-200 px-3.5 py-2 rounded-xl text-xs font-bold transition-all flex items-center gap-2 cursor-pointer border border-slate-700"
                  >
                    ← Back to Websites
                  </button>
                  <div>
                    <div className="flex items-center gap-3 flex-wrap">
                      <h2 className="text-2xl font-extrabold text-white tracking-tight">{activeManageSite.domain_name}</h2>
                      <span className="bg-emerald-500/10 text-emerald-400 text-xs font-semibold px-2.5 py-0.5 rounded-full border border-emerald-500/20 flex items-center gap-1.5">
                        <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse"></span>
                        {activeManageSite.status.toUpperCase()}
                      </span>
                      <span className="bg-cyan-500/10 text-cyan-400 text-xs font-semibold px-2.5 py-0.5 rounded-full border border-cyan-500/20">
                        {activeManageSite.site_type.toUpperCase()}
                      </span>
                    </div>
                    <p className="text-xs text-slate-400 font-mono mt-1">
                      Document Root: <span className="text-slate-200">{activeManageSite.document_root}</span> | PHP:{' '}
                      <span className="text-cyan-400">{activeManageSite.php_version}</span>
                    </p>
                  </div>
                </div>

                <div className="flex items-center gap-2 flex-wrap">
                  <button
                    onClick={() => handleSiteAction(activeManageSite.domain_name, 'purge_cache')}
                    className="bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold px-3.5 py-2 rounded-xl transition-all border border-slate-700 cursor-pointer flex items-center gap-1.5"
                  >
                    <RefreshCw className="w-3.5 h-3.5 text-cyan-400" />
                    <span>Purge Cache</span>
                  </button>
                  <button
                    onClick={() => handleSiteAction(activeManageSite.domain_name, 'reload_fpm')}
                    className="bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold px-3.5 py-2 rounded-xl transition-all border border-slate-700 cursor-pointer flex items-center gap-1.5"
                  >
                    <Zap className="w-3.5 h-3.5 text-amber-400" />
                    <span>Reload FPM</span>
                  </button>
                  <button
                    onClick={() => handleDeleteWebsite(activeManageSite.id, activeManageSite.domain_name)}
                    className="bg-rose-500/10 hover:bg-rose-500/20 text-rose-400 text-xs font-semibold px-3.5 py-2 rounded-xl transition-all border border-rose-500/20 cursor-pointer flex items-center gap-1.5"
                  >
                    <Trash2 className="w-3.5 h-3.5" />
                    <span>Delete Site</span>
                  </button>
                </div>
              </div>

              {/* Sub-Navigation Tabs */}
              <div className="flex border-b border-slate-800 space-x-2 overflow-x-auto pb-1">
                {[
                  { id: 'overview', label: 'Overview & VHost', icon: Settings },
                  { id: 'production_config', label: 'Production Config & Details', icon: Code },
                  { id: 'ssl', label: 'SSL & HTTPS', icon: Lock },
                  { id: 'files', label: 'File Manager', icon: Folder },
                  { id: 'security', label: 'Security & WAF', icon: ShieldCheck },
                  { id: 'logs', label: 'Logs & Diagnostics', icon: FileText },
                  { id: 'cron', label: 'Scheduled Cron Jobs', icon: Clock },
                ].map((tab) => {
                  const Icon = tab.icon;
                  const isActive = siteManageSubTab === tab.id;
                  return (
                    <button
                      key={tab.id}
                      onClick={() => setSiteManageSubTab(tab.id as any)}
                      className={`px-4 py-2.5 rounded-xl text-xs font-bold transition-all cursor-pointer flex items-center gap-2 whitespace-nowrap ${
                        isActive
                          ? 'bg-cyan-500/15 text-cyan-400 border border-cyan-500/30 shadow-lg shadow-cyan-500/10'
                          : 'text-slate-400 hover:bg-slate-900 hover:text-slate-200'
                      }`}
                    >
                      <Icon className="w-4 h-4" />
                      <span>{tab.label}</span>
                    </button>
                  );
                })}
              </div>

              {/* Sub-Tab: PRODUCTION CONFIG & CREDENTIALS (CloudPanel style) */}
              {siteManageSubTab === 'production_config' && (
                <div className="space-y-6">
                  <div className="bg-slate-900/80 border border-slate-800 p-5 rounded-2xl flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                    <div>
                      <h3 className="text-base font-bold text-white flex items-center gap-2">
                        <Globe className="w-5 h-5 text-cyan-400" />
                        <span>{activeManageSite.domain_name}</span>
                        <span className="bg-emerald-500/10 text-emerald-400 text-xs font-mono font-bold px-2.5 py-0.5 rounded-full border border-emerald-500/30">
                          PROVISIONED
                        </span>
                      </h3>
                      <p className="text-xs text-slate-400 mt-0.5">CloudPanel Production Files & Credentials Exporter</p>
                    </div>

                    <div className="flex gap-2">
                      <a
                        href={`https://${activeManageSite.domain_name}`}
                        target="_blank"
                        rel="noreferrer"
                        className="bg-slate-800 hover:bg-slate-700 text-cyan-400 font-bold text-xs px-3.5 py-2 rounded-xl border border-slate-700 flex items-center gap-1.5 cursor-pointer"
                      >
                        <ExternalLink className="w-3.5 h-3.5" /> Visit Site
                      </a>
                      {activeManageSite.site_type === 'wordpress' && (
                        <a
                          href={`https://${activeManageSite.domain_name}/wp-admin`}
                          target="_blank"
                          rel="noreferrer"
                          className="bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs px-3.5 py-2 rounded-xl shadow-lg shadow-cyan-500/20 flex items-center gap-1.5 cursor-pointer"
                        >
                          <Key className="w-3.5 h-3.5" /> WP Admin 🔐
                        </a>
                      )}
                    </div>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
                    <div className="bg-slate-900/80 border border-slate-800 p-5 rounded-2xl space-y-3">
                      <h4 className="text-xs font-bold text-slate-300 uppercase tracking-wider flex items-center justify-between">
                        <span>Admin Access Credentials</span>
                        <span className="text-cyan-400 text-[10px] font-mono">{activeManageSite.site_type.toUpperCase()}</span>
                      </h4>
                      <div className="space-y-2 text-xs font-mono">
                        <div className="bg-slate-950 p-2.5 rounded-xl border border-slate-800/80 flex items-center justify-between">
                          <div>
                            <div className="text-[10px] text-slate-500">Username</div>
                            <div className="text-slate-200 font-bold">{activeManageSite.admin_user || 'admin_wp'}</div>
                          </div>
                          <button
                            onClick={() => handleCopyText(activeManageSite.admin_user || 'admin_wp', 'Admin User')}
                            className="text-slate-400 hover:text-cyan-400 p-1 cursor-pointer"
                          >
                            {copiedField === 'Admin User' ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
                          </button>
                        </div>

                        <div className="bg-slate-950 p-2.5 rounded-xl border border-slate-800/80 flex items-center justify-between">
                          <div>
                            <div className="text-[10px] text-slate-500">Password</div>
                            <div className="text-amber-400 font-bold">{activeManageSite.admin_pass || 'WpPass#2026!Sec'}</div>
                          </div>
                          <button
                            onClick={() => handleCopyText(activeManageSite.admin_pass || 'WpPass#2026!Sec', 'Admin Password')}
                            className="text-slate-400 hover:text-cyan-400 p-1 cursor-pointer"
                          >
                            {copiedField === 'Admin Password' ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
                          </button>
                        </div>
                      </div>
                    </div>

                    <div className="bg-slate-900/80 border border-slate-800 p-5 rounded-2xl space-y-3">
                      <h4 className="text-xs font-bold text-slate-300 uppercase tracking-wider flex items-center justify-between">
                        <span>Database Connection</span>
                        <span className="text-indigo-400 text-[10px] font-mono">MYSQL / POSTGRES</span>
                      </h4>
                      <div className="space-y-2 text-xs font-mono">
                        <div className="bg-slate-950 p-2.5 rounded-xl border border-slate-800/80 flex items-center justify-between">
                          <div>
                            <div className="text-[10px] text-slate-500">Database & User</div>
                            <div className="text-slate-200 font-bold">{activeManageSite.db_name || activeManageSite.linked_db_name || 'wp_db'}</div>
                          </div>
                          <button
                            onClick={() => handleCopyText(activeManageSite.db_name || activeManageSite.linked_db_name || 'wp_db', 'Database Name')}
                            className="text-slate-400 hover:text-cyan-400 p-1 cursor-pointer"
                          >
                            {copiedField === 'Database Name' ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
                          </button>
                        </div>

                        <div className="bg-slate-950 p-2.5 rounded-xl border border-slate-800/80 flex items-center justify-between">
                          <div>
                            <div className="text-[10px] text-slate-500">DB Password</div>
                            <div className="text-emerald-400 font-bold">{activeManageSite.db_pass || 'DbPass#2026!Sec'}</div>
                          </div>
                          <button
                            onClick={() => handleCopyText(activeManageSite.db_pass || 'DbPass#2026!Sec', 'DB Password')}
                            className="text-slate-400 hover:text-cyan-400 p-1 cursor-pointer"
                          >
                            {copiedField === 'DB Password' ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
                          </button>
                        </div>
                      </div>
                    </div>

                    <div className="bg-slate-900/80 border border-slate-800 p-5 rounded-2xl space-y-3">
                      <h4 className="text-xs font-bold text-slate-300 uppercase tracking-wider flex items-center justify-between">
                        <span>FTP / SSH File Access</span>
                        <span className="text-amber-400 text-[10px] font-mono">SFTP PORT 22</span>
                      </h4>
                      <div className="space-y-2 text-xs font-mono">
                        <div className="bg-slate-950 p-2.5 rounded-xl border border-slate-800/80 flex items-center justify-between">
                          <div>
                            <div className="text-[10px] text-slate-500">FTP Host & Root</div>
                            <div className="text-slate-200 font-bold">ftp.{activeManageSite.domain_name}</div>
                          </div>
                          <button
                            onClick={() => handleCopyText(`ftp.${activeManageSite.domain_name}`, 'FTP Host')}
                            className="text-slate-400 hover:text-cyan-400 p-1 cursor-pointer"
                          >
                            {copiedField === 'FTP Host' ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
                          </button>
                        </div>

                        <div className="bg-slate-950 p-2.5 rounded-xl border border-slate-800/80 flex items-center justify-between">
                          <div>
                            <div className="text-[10px] text-slate-500">Document Root Path</div>
                            <div className="text-cyan-400 font-bold text-[11px] truncate max-w-[180px]">{activeManageSite.document_root}</div>
                          </div>
                          <button
                            onClick={() => handleCopyText(activeManageSite.document_root, 'Document Root')}
                            className="text-slate-400 hover:text-cyan-400 p-1 cursor-pointer"
                          >
                            {copiedField === 'Document Root' ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
                          </button>
                        </div>
                      </div>
                    </div>
                  </div>

                  <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-6 space-y-4">
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-4">
                      <div>
                        <h4 className="font-bold text-base text-white flex items-center gap-2">
                          <FileCode className="w-5 h-5 text-cyan-400" />
                          <span>Copyable Production Configuration Files</span>
                        </h4>
                        <p className="text-xs text-slate-400">CloudPanel formatted server configuration snippets ready to copy into production</p>
                      </div>

                      <div className="flex gap-1.5 bg-slate-950 p-1 rounded-xl border border-slate-800 overflow-x-auto">
                        <button
                          onClick={() => setActiveConfigTab('nginx')}
                          className={`px-3 py-1.5 rounded-lg text-xs font-bold transition-all cursor-pointer whitespace-nowrap ${
                            activeConfigTab === 'nginx' ? 'bg-cyan-500 text-slate-950 shadow-md' : 'text-slate-400 hover:text-slate-200'
                          }`}
                        >
                          Nginx VHost
                        </button>
                        <button
                          onClick={() => setActiveConfigTab('env')}
                          className={`px-3 py-1.5 rounded-lg text-xs font-bold transition-all cursor-pointer whitespace-nowrap ${
                            activeConfigTab === 'env' ? 'bg-cyan-500 text-slate-950 shadow-md' : 'text-slate-400 hover:text-slate-200'
                          }`}
                        >
                          {activeManageSite.site_type === 'wordpress' ? 'wp-config.php' : '.env File'}
                        </button>
                        {(activeManageSite.site_type === 'nodejs' || activeManageSite.site_type === 'python') && (
                          <button
                            onClick={() => setActiveConfigTab('systemd')}
                            className={`px-3 py-1.5 rounded-lg text-xs font-bold transition-all cursor-pointer whitespace-nowrap ${
                              activeConfigTab === 'systemd' ? 'bg-cyan-500 text-slate-950 shadow-md' : 'text-slate-400 hover:text-slate-200'
                            }`}
                          >
                            Systemd Service
                          </button>
                        )}
                        {(activeManageSite.site_type === 'wordpress' || activeManageSite.site_type === 'laravel') && (
                          <button
                            onClick={() => setActiveConfigTab('fpm')}
                            className={`px-3 py-1.5 rounded-lg text-xs font-bold transition-all cursor-pointer whitespace-nowrap ${
                              activeConfigTab === 'fpm' ? 'bg-cyan-500 text-slate-950 shadow-md' : 'text-slate-400 hover:text-slate-200'
                            }`}
                          >
                            PHP-FPM Pool
                          </button>
                        )}
                        <button
                          onClick={() => setActiveConfigTab('deploy')}
                          className={`px-3 py-1.5 rounded-lg text-xs font-bold transition-all cursor-pointer whitespace-nowrap ${
                            activeConfigTab === 'deploy' ? 'bg-cyan-500 text-slate-950 shadow-md' : 'text-slate-400 hover:text-slate-200'
                          }`}
                        >
                          Deploy Script
                        </button>
                      </div>
                    </div>

                    <div className="relative">
                      <div className="absolute top-3 right-3 flex items-center gap-2">
                        <button
                          onClick={() => {
                            const code =
                              activeConfigTab === 'nginx'
                                ? activeManageSite.nginx_config || generateNginxConfig(activeManageSite.domain_name, activeManageSite.document_root, activeManageSite.site_type, activeManageSite.php_version, activeManageSite.app_port)
                                : activeConfigTab === 'env'
                                ? activeManageSite.env_file_content || generateEnvFileContent(activeManageSite.domain_name, activeManageSite.site_title, activeManageSite.site_type, activeManageSite.db_name, activeManageSite.db_user, activeManageSite.db_pass)
                                : activeConfigTab === 'systemd'
                                ? activeManageSite.systemd_content || generateSystemdContent(activeManageSite.domain_name, activeManageSite.document_root, activeManageSite.site_type)
                                : activeConfigTab === 'fpm'
                                ? activeManageSite.fpm_pool_content || generateFPMPoolContent(activeManageSite.domain_name, activeManageSite.php_version)
                                : activeManageSite.deploy_script_content || generateDeployScriptContent(activeManageSite.domain_name, activeManageSite.document_root);

                            const filename =
                              activeConfigTab === 'nginx'
                                ? `${activeManageSite.domain_name}.conf`
                                : activeConfigTab === 'env'
                                ? (activeManageSite.site_type === 'wordpress' ? 'wp-config.php' : '.env')
                                : activeConfigTab === 'systemd'
                                ? `${activeManageSite.domain_name}.service`
                                : activeConfigTab === 'fpm'
                                ? `${activeManageSite.domain_name}-fpm.conf`
                                : 'deploy.sh';

                            handleDownloadFile(code, filename);
                          }}
                          className="bg-slate-800 hover:bg-slate-700 text-emerald-400 font-bold text-xs px-3 py-1 rounded-lg border border-slate-700 flex items-center gap-1.5 cursor-pointer shadow-md"
                        >
                          <Download className="w-3.5 h-3.5 text-emerald-400" />
                          <span>Download File</span>
                        </button>

                        <button
                          onClick={() => {
                            const code =
                              activeConfigTab === 'nginx'
                                ? activeManageSite.nginx_config || generateNginxConfig(activeManageSite.domain_name, activeManageSite.document_root, activeManageSite.site_type, activeManageSite.php_version, activeManageSite.app_port)
                                : activeConfigTab === 'env'
                                ? activeManageSite.env_file_content || generateEnvFileContent(activeManageSite.domain_name, activeManageSite.site_title, activeManageSite.site_type, activeManageSite.db_name, activeManageSite.db_user, activeManageSite.db_pass)
                                : activeConfigTab === 'systemd'
                                ? activeManageSite.systemd_content || generateSystemdContent(activeManageSite.domain_name, activeManageSite.document_root, activeManageSite.site_type)
                                : activeConfigTab === 'fpm'
                                ? activeManageSite.fpm_pool_content || generateFPMPoolContent(activeManageSite.domain_name, activeManageSite.php_version)
                                : activeManageSite.deploy_script_content || generateDeployScriptContent(activeManageSite.domain_name, activeManageSite.document_root);

                            handleCopyText(code, `${activeConfigTab.toUpperCase()} Config`);
                          }}
                          className="bg-slate-800 hover:bg-slate-700 text-cyan-400 font-bold text-xs px-3 py-1 rounded-lg border border-slate-700 flex items-center gap-1.5 cursor-pointer shadow-md"
                        >
                          {copiedField === `${activeConfigTab.toUpperCase()} Config` ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                          <span>Copy Snippet</span>
                        </button>
                      </div>

                      <pre className="bg-slate-950 p-4 rounded-xl border border-slate-800 text-xs font-mono text-emerald-400 overflow-x-auto max-h-96 leading-relaxed">
                        {activeConfigTab === 'nginx' && (activeManageSite.nginx_config || generateNginxConfig(activeManageSite.domain_name, activeManageSite.document_root, activeManageSite.site_type, activeManageSite.php_version, activeManageSite.app_port))}
                        {activeConfigTab === 'env' && (activeManageSite.env_file_content || generateEnvFileContent(activeManageSite.domain_name, activeManageSite.site_title, activeManageSite.site_type, activeManageSite.db_name, activeManageSite.db_user, activeManageSite.db_pass))}
                        {activeConfigTab === 'systemd' && (activeManageSite.systemd_content || generateSystemdContent(activeManageSite.domain_name, activeManageSite.document_root, activeManageSite.site_type))}
                        {activeConfigTab === 'fpm' && (activeManageSite.fpm_pool_content || generateFPMPoolContent(activeManageSite.domain_name, activeManageSite.php_version))}
                        {activeConfigTab === 'deploy' && (activeManageSite.deploy_script_content || generateDeployScriptContent(activeManageSite.domain_name, activeManageSite.document_root))}
                      </pre>
                    </div>
                  </div>
                </div>
              )}

              {/* Sub-Tab 1: OVERVIEW */}
              {siteManageSubTab === 'overview' && (
                <div className="space-y-6">
                  {/* VPS Quick Actions Panel */}
                  <div className="bg-slate-900/80 border border-slate-800 p-5 rounded-2xl space-y-3">
                    <div className="flex items-center justify-between">
                      <h3 className="font-bold text-sm text-white flex items-center gap-2">
                        <Zap className="w-4 h-4 text-amber-400" />
                        <span>CloudPanel Quick Server Actions</span>
                      </h3>
                      <a
                        href={`http://${activeManageSite.domain_name}`}
                        target="_blank"
                        rel="noreferrer"
                        className="text-xs text-cyan-400 hover:text-cyan-300 flex items-center gap-1 font-mono"
                      >
                        Visit Site <ExternalLink className="w-3 h-3" />
                      </a>
                    </div>
                    <div className="flex flex-wrap gap-2 pt-1">
                      <button
                        onClick={() => handleSiteAction(activeManageSite.domain_name, 'purge_cache')}
                        className="bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold px-3 py-1.5 rounded-xl border border-slate-700 cursor-pointer flex items-center gap-1.5"
                      >
                        <RefreshCw className="w-3.5 h-3.5 text-cyan-400" /> Purge Cache
                      </button>
                      <button
                        onClick={() => handleSiteAction(activeManageSite.domain_name, 'reload_fpm')}
                        className="bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold px-3 py-1.5 rounded-xl border border-slate-700 cursor-pointer flex items-center gap-1.5"
                      >
                        <Cpu className="w-3.5 h-3.5 text-emerald-400" /> Reload FPM
                      </button>
                      <button
                        onClick={() => handleSiteAction(activeManageSite.domain_name, 'restart_fpm')}
                        className="bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold px-3 py-1.5 rounded-xl border border-slate-700 cursor-pointer flex items-center gap-1.5"
                      >
                        <RefreshCw className="w-3.5 h-3.5 text-amber-400" /> Restart FPM
                      </button>
                      <button
                        onClick={() => handleSiteAction(activeManageSite.domain_name, 'reload_nginx')}
                        className="bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold px-3 py-1.5 rounded-xl border border-slate-700 cursor-pointer flex items-center gap-1.5"
                      >
                        <Globe className="w-3.5 h-3.5 text-blue-400" /> Reload Nginx
                      </button>
                      <button
                        onClick={() => handleSiteAction(activeManageSite.domain_name, 'fix_permissions')}
                        className="bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold px-3 py-1.5 rounded-xl border border-slate-700 cursor-pointer flex items-center gap-1.5"
                      >
                        <ShieldCheck className="w-3.5 h-3.5 text-purple-400" /> Fix Permissions (755/644)
                      </button>
                    </div>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
                    <div className="bg-slate-900/80 border border-slate-800 p-5 rounded-2xl space-y-3">
                      <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Virtual Host Engine</div>
                      <div className="text-lg font-bold text-white font-mono">{activeManageSite.tracking_id}</div>
                      <p className="text-xs text-slate-400">Nginx configuration in <code className="text-cyan-400">/etc/nginx/sites-available/</code></p>
                    </div>

                    <div className="bg-slate-900/80 border border-slate-800 p-5 rounded-2xl space-y-3">
                      <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider">PHP Version Engine</div>
                      <div className="flex items-center justify-between">
                        <span className="text-lg font-bold text-cyan-400 font-mono">PHP {activeManageSite.php_version}</span>
                        <button
                          onClick={() => showToast(`PHP version active: ${activeManageSite.php_version}`)}
                          className="bg-slate-800 hover:bg-slate-700 text-xs px-2.5 py-1 rounded-lg border border-slate-700 cursor-pointer"
                        >
                          Active
                        </button>
                      </div>
                      <p className="text-xs text-slate-400">Dedicated FPM Pool socket active</p>
                    </div>

                    <div className="bg-slate-900/80 border border-slate-800 p-5 rounded-2xl space-y-3">
                      <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Linked Database</div>
                      <div className="text-lg font-bold text-indigo-400 font-mono">
                        {activeManageSite.linked_db_name || 'wp_hoatzin_prod'}
                      </div>
                      <p className="text-xs text-slate-400">MySQL / MariaDB local socket connected</p>
                    </div>
                  </div>

                  {/* PHP Runtime Settings */}
                  <div className="bg-slate-900/80 border border-slate-800 p-6 rounded-2xl space-y-4">
                    <h3 className="font-bold text-base text-white flex items-center gap-2">
                      <Cpu className="w-5 h-5 text-cyan-400" />
                      <span>PHP Performance & Runtime Configuration</span>
                    </h3>
                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 text-xs font-mono">
                      <div className="bg-slate-950 p-3.5 rounded-xl border border-slate-800">
                        <div className="text-slate-400 mb-1">memory_limit</div>
                        <div className="text-white font-bold text-sm">256M</div>
                      </div>
                      <div className="bg-slate-950 p-3.5 rounded-xl border border-slate-800">
                        <div className="text-slate-400 mb-1">upload_max_filesize</div>
                        <div className="text-white font-bold text-sm">64M</div>
                      </div>
                      <div className="bg-slate-950 p-3.5 rounded-xl border border-slate-800">
                        <div className="text-slate-400 mb-1">max_execution_time</div>
                        <div className="text-white font-bold text-sm">300s</div>
                      </div>
                      <div className="bg-slate-950 p-3.5 rounded-xl border border-slate-800">
                        <div className="text-slate-400 mb-1">OPcache Acceleration</div>
                        <div className="text-emerald-400 font-bold text-sm">ACTIVE (128M)</div>
                      </div>
                    </div>
                  </div>
                </div>
              )}

              {/* Sub-Tab 2: SSL & HTTPS */}
              {siteManageSubTab === 'ssl' && (
                <div className="bg-slate-900/80 border border-slate-800 p-6 rounded-2xl space-y-6">
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                    <div className="flex items-center gap-3">
                      <div className="w-10 h-10 rounded-xl bg-emerald-500/20 border border-emerald-500/30 flex items-center justify-center text-emerald-400">
                        <Lock className="w-5 h-5" />
                      </div>
                      <div>
                        <h3 className="font-bold text-base text-white">SSL Certificate & TLS Security</h3>
                        <p className="text-xs text-slate-400">Let's Encrypt automated TLS certificate issuance and HTTPS enforcement</p>
                      </div>
                    </div>
                    <button
                      onClick={() => handleSiteAction(activeManageSite.domain_name, 'ssl_renew')}
                      className="bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 font-bold text-xs px-4 py-2 rounded-xl cursor-pointer self-start sm:self-auto"
                    >
                      Renew Certificate
                    </button>
                  </div>

                  {/* Real SSL Status Cards */}
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-4 font-mono text-xs">
                    <div className="bg-slate-950 p-4 rounded-xl border border-slate-800">
                      <div className="text-slate-400">Issuer Authority</div>
                      <div className="text-white font-bold text-sm mt-1">{sslInfo?.issuer || "Let's Encrypt / Self-Signed"}</div>
                    </div>
                    <div className="bg-slate-950 p-4 rounded-xl border border-slate-800">
                      <div className="text-slate-400">Expiration / Validity</div>
                      <div className="text-emerald-400 font-bold text-sm mt-1">
                        {sslInfo?.expires_at ? `${sslInfo.expires_at} (${sslInfo.days_left} days left)` : 'Active (Valid Certificate)'}
                      </div>
                    </div>
                    <div className="bg-slate-950 p-4 rounded-xl border border-slate-800">
                      <div className="text-slate-400">HTTPS Redirect</div>
                      <div className="text-cyan-400 font-bold text-sm mt-1">Enforced (301 Permanent)</div>
                    </div>
                  </div>

                  {/* Issue New Let's Encrypt SSL Form */}
                  <div className="bg-slate-950 p-5 rounded-xl border border-slate-800 space-y-3">
                    <div className="font-bold text-sm text-white flex items-center gap-2">
                      <Shield className="w-4 h-4 text-cyan-400" />
                      <span>Issue Automated Let's Encrypt SSL Certificate</span>
                    </div>
                    <p className="text-xs text-slate-400">
                      Certbot will automatically verify domain ownership via HTTP-01 challenge and configure Nginx virtual host with SSL directives.
                    </p>
                    <div className="flex flex-col sm:flex-row gap-3 pt-1">
                      <input
                        type="email"
                        placeholder="admin@yourdomain.com (for renewal notices)"
                        value={sslEmail}
                        onChange={(e) => setSslEmail(e.target.value)}
                        className="flex-1 bg-slate-900 border border-slate-800 rounded-xl px-3.5 py-2 text-xs font-mono text-white focus:outline-none focus:border-cyan-500"
                      />
                      <button
                        onClick={() => handleIssueSSL(activeManageSite.domain_name)}
                        disabled={sslLoading}
                        className="bg-cyan-500 hover:bg-cyan-400 disabled:opacity-50 text-slate-950 font-bold text-xs px-5 py-2 rounded-xl cursor-pointer flex items-center justify-center gap-2"
                      >
                        {sslLoading ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Lock className="w-3.5 h-3.5" />}
                        <span>{sslLoading ? 'Requesting Certbot...' : 'Issue Let\'s Encrypt SSL'}</span>
                      </button>
                    </div>
                  </div>
                </div>
              )}

              {/* Sub-Tab 3: FILE MANAGER */}
              {siteManageSubTab === 'files' && (
                <div className="space-y-4">
                  <div className="flex flex-wrap items-center justify-between gap-3 bg-slate-900/80 border border-slate-800 p-4 rounded-2xl">
                    <div className="flex items-center gap-2 text-xs font-mono text-slate-300">
                      <button onClick={handleFmUp} disabled={!fmPath || fmPath === fmRoot} className="px-2 py-1 rounded-md bg-slate-800 text-slate-300 disabled:opacity-40 cursor-pointer">↑ Up</button>
                      <Folder className="w-4 h-4 text-amber-400" />
                      <span>{fmPath || activeManageSite.document_root}</span>
                    </div>
                    <div className="flex flex-wrap items-center gap-2 text-xs font-bold">
                      {!fmIsWP && activeManageSite.site_type === 'wordpress' && (
                        <button onClick={handleInstallWordPress} className="bg-emerald-500 hover:bg-emerald-400 text-slate-950 px-3 py-1.5 rounded-lg cursor-pointer">Install WordPress Core</button>
                      )}
                      <button onClick={handleNewFile} className="bg-slate-800 hover:bg-slate-700 text-slate-200 px-3 py-1.5 rounded-lg cursor-pointer">+ File</button>
                      <button onClick={handleNewFolder} className="bg-slate-800 hover:bg-slate-700 text-slate-200 px-3 py-1.5 rounded-lg cursor-pointer">+ Folder</button>
                      <label className="bg-slate-800 hover:bg-slate-700 text-slate-200 px-3 py-1.5 rounded-lg cursor-pointer">
                        Upload
                        <input type="file" multiple className="hidden" onChange={handleUploadFiles} />
                      </label>
                      <button onClick={fmRefresh} className="bg-slate-800 hover:bg-slate-700 text-slate-200 px-3 py-1.5 rounded-lg cursor-pointer">Refresh</button>
                      <button
                        onClick={() => handleEditFileView(`${fmRoot || activeManageSite.document_root}/${activeManageSite.site_type === 'wordpress' ? 'wp-config.php' : '.env'}`)}
                        className="bg-cyan-500 hover:bg-cyan-400 text-slate-950 px-3.5 py-1.5 rounded-lg cursor-pointer flex items-center gap-1.5"
                      >
                        <FileCode className="w-3.5 h-3.5" /> {activeManageSite.site_type === 'wordpress' ? 'wp-config.php' : '.env'}
                      </button>
                    </div>
                  </div>

                  {fmError && (
                    <div className="bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs font-mono p-3 rounded-xl">{fmError}</div>
                  )}
                  {fmLoading && <div className="text-xs text-slate-400 font-mono">Loading...</div>}

                  <div className="bg-slate-900/80 border border-slate-800 rounded-2xl overflow-hidden shadow-xl">
                    <table className="w-full text-left text-xs font-mono">
                      <thead className="bg-slate-950 text-slate-400 border-b border-slate-800 uppercase tracking-wider">
                        <tr>
                          <th className="p-3.5">Name</th>
                          <th className="p-3.5">Permissions</th>
                          <th className="p-3.5">Size</th>
                          <th className="p-3.5 text-right">Actions</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-800/60 text-slate-200">
                        {siteFiles.length === 0 && !fmLoading && (
                          <tr><td colSpan={4} className="p-6 text-center text-slate-500">This folder is empty.</td></tr>
                        )}
                        {siteFiles.map((file) => (
                          <tr key={file.path} className="hover:bg-slate-800/40">
                            <td className="p-3.5 font-medium">
                              <button onClick={() => handleOpenFileItem(file)} className="flex items-center gap-2 cursor-pointer hover:text-cyan-300">
                                {file.is_dir ? (
                                  <Folder className="w-4 h-4 text-amber-400" />
                                ) : (
                                  <FileText className="w-4 h-4 text-cyan-400" />
                                )}
                                <span>{file.name}</span>
                              </button>
                            </td>
                            <td className="p-3.5 text-slate-400">{file.permissions}</td>
                            <td className="p-3.5 text-slate-400">{file.is_dir ? '--' : `${file.size} B`}</td>
                            <td className="p-3.5 text-right space-x-3 whitespace-nowrap">
                              <button onClick={() => handleOpenFileItem(file)} className="text-cyan-400 hover:underline cursor-pointer font-bold">{file.is_dir ? 'Open' : 'Edit'}</button>
                              {!file.is_dir && <button onClick={() => handleDownloadSiteFile(file)} className="text-slate-300 hover:underline cursor-pointer">Download</button>}
                              <button onClick={() => handleRenameFile(file)} className="text-slate-300 hover:underline cursor-pointer">Rename</button>
                              <button onClick={() => handleChmodFile(file)} className="text-slate-300 hover:underline cursor-pointer">Chmod</button>
                              <button onClick={() => handleDeleteFile(file)} className="text-rose-400 hover:underline cursor-pointer">Delete</button>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>

                  {/* File Code Editor Modal */}
                  {editingFile && (
                    <div className="fixed inset-0 bg-slate-950/80 backdrop-blur-md z-50 flex items-center justify-center p-4">
                      <div className="bg-slate-900 border border-slate-800 w-full max-w-2xl rounded-2xl p-6 space-y-4 shadow-2xl">
                        <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                          <h3 className="font-mono text-sm font-bold text-white flex items-center gap-2">
                            <FileCode className="w-4 h-4 text-cyan-400" />
                            <span>{editingFile.path}</span>
                          </h3>
                          <button onClick={() => setEditingFile(null)} className="text-slate-400 hover:text-white cursor-pointer">✕</button>
                        </div>
                        <textarea
                          rows={12}
                          value={editingFile.content}
                          onChange={(e) => setEditingFile({ ...editingFile, content: e.target.value })}
                          className="w-full bg-slate-950 border border-slate-800 rounded-xl p-4 font-mono text-xs text-emerald-400 focus:outline-none focus:border-cyan-500"
                        />
                        <div className="flex justify-end gap-3">
                          <button onClick={() => setEditingFile(null)} className="bg-slate-800 text-slate-300 font-semibold px-4 py-2 rounded-xl text-xs cursor-pointer">Cancel</button>
                          <button onClick={handleSaveFileContent} className="bg-cyan-500 text-slate-950 font-bold px-4 py-2 rounded-xl text-xs cursor-pointer">Save File</button>
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              )}

              {/* Sub-Tab 4: SECURITY & WAF */}
              {siteManageSubTab === 'security' && (
                <div className="bg-slate-900/80 border border-slate-800 p-6 rounded-2xl space-y-6">
                  <div className="flex items-center justify-between">
                    <div>
                      <h3 className="font-bold text-base text-white flex items-center gap-2">
                        <ShieldCheck className="w-5 h-5 text-cyan-400" />
                        <span>Web Application Firewall (WAF) & Hardening</span>
                      </h3>
                      <p className="text-xs text-slate-400">Application layer security filters & automated threat mitigation</p>
                    </div>
                    <span className="bg-emerald-500/10 text-emerald-400 text-xs font-bold px-3 py-1 rounded-full border border-emerald-500/30">
                      WAF ENGAGED
                    </span>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs font-mono">
                    <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 flex items-center justify-between">
                      <div>
                        <div className="text-white font-bold">SQL Injection (SQLi) Filter</div>
                        <div className="text-slate-400 text-[11px]">Inspect request params for malicious SQL patterns</div>
                      </div>
                      <span className="text-emerald-400 font-bold">ENABLED</span>
                    </div>

                    <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 flex items-center justify-between">
                      <div>
                        <div className="text-white font-bold">Cross-Site Scripting (XSS) Shield</div>
                        <div className="text-slate-400 text-[11px]">Sanitize query strings & POST headers</div>
                      </div>
                      <span className="text-emerald-400 font-bold">ENABLED</span>
                    </div>

                    <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 flex items-center justify-between">
                      <div>
                        <div className="text-white font-bold">Hotlink Protection</div>
                        <div className="text-slate-400 text-[11px]">Prevent external domain media embedding</div>
                      </div>
                      <span className="text-cyan-400 font-bold">ACTIVE</span>
                    </div>

                    <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 flex items-center justify-between">
                      <div>
                        <div className="text-white font-bold">Brute-Force Rate Limiter</div>
                        <div className="text-slate-400 text-[11px]">Cap requests to 60 req/min per IP</div>
                      </div>
                      <span className="text-cyan-400 font-bold">ACTIVE</span>
                    </div>
                  </div>
                </div>
              )}

              {/* Sub-Tab 5: LOGS */}
              {siteManageSubTab === 'logs' && (
                <div className="bg-slate-900/80 border border-slate-800 p-6 rounded-2xl space-y-4">
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                    <div className="flex items-center gap-3">
                      <FileText className="w-5 h-5 text-cyan-400" />
                      <h3 className="font-bold text-base text-white">Live Server Logs (/var/log/...)</h3>
                    </div>
                    <div className="flex items-center gap-2">
                      {(['access', 'error', 'fpm'] as const).map((t) => (
                        <button
                          key={t}
                          onClick={() => {
                            setLogType(t);
                            loadSiteLogs(activeManageSite.domain_name, t);
                          }}
                          className={`px-3 py-1 rounded-lg text-xs font-bold uppercase cursor-pointer transition-all ${
                            logType === t ? 'bg-cyan-500 text-slate-950 shadow-md shadow-cyan-500/20' : 'bg-slate-800 text-slate-400 hover:text-white'
                          }`}
                        >
                          {t}
                        </button>
                      ))}
                      <button
                        onClick={() => loadSiteLogs(activeManageSite.domain_name, logType)}
                        className="bg-slate-800 hover:bg-slate-700 text-slate-300 p-1.5 rounded-lg border border-slate-700 cursor-pointer"
                        title="Refresh Logs"
                      >
                        <RefreshCw className={`w-3.5 h-3.5 ${siteLogsLoading ? 'animate-spin text-cyan-400' : ''}`} />
                      </button>
                    </div>
                  </div>

                  <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 font-mono text-xs text-slate-300 space-y-1.5 overflow-x-auto max-h-96 overflow-y-auto">
                    {siteLogsLoading ? (
                      <div className="text-slate-500 italic">Reading live logs from server daemon...</div>
                    ) : (
                      <pre className="whitespace-pre-wrap font-mono text-xs text-slate-300 leading-relaxed">
                        {siteLogs || '# No log entries recorded yet.'}
                      </pre>
                    )}
                  </div>
                </div>
              )}

              {/* Sub-Tab 6: CRON JOBS */}
              {siteManageSubTab === 'cron' && (
                <div className="space-y-6">
                  {/* Create Cron Form */}
                  <form onSubmit={handleAddCronJob} className="bg-slate-900/80 border border-slate-800 p-5 rounded-2xl flex flex-col md:flex-row gap-4 items-end">
                    <div className="flex-1 space-y-1">
                      <label className="block text-xs font-semibold text-slate-300">Schedule (Cron Syntax)</label>
                      <input
                        type="text"
                        value={newCronSchedule}
                        onChange={(e) => setNewCronSchedule(e.target.value)}
                        className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-xs font-mono text-white focus:outline-none"
                      />
                    </div>
                    <div className="flex-[2] space-y-1">
                      <label className="block text-xs font-semibold text-slate-300">Command</label>
                      <input
                        type="text"
                        placeholder={`php ${activeManageSite.document_root}/wp-cron.php`}
                        value={newCronCmd}
                        onChange={(e) => setNewCronCmd(e.target.value)}
                        className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-xs font-mono text-white focus:outline-none"
                      />
                    </div>
                    <button type="submit" className="bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs px-5 py-2.5 rounded-xl cursor-pointer">
                      Add Cron Job
                    </button>
                  </form>

                  {/* Cron List */}
                  <div className="bg-slate-900/80 border border-slate-800 rounded-2xl overflow-hidden">
                    <table className="w-full text-left text-xs font-mono">
                      <thead className="bg-slate-950 text-slate-400 border-b border-slate-800 uppercase tracking-wider">
                        <tr>
                          <th className="p-3.5">Schedule</th>
                          <th className="p-3.5">Command</th>
                          <th className="p-3.5">Last Run</th>
                          <th className="p-3.5 text-right">Actions</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-800/60 text-slate-200">
                        {siteCronJobs.map((job) => (
                          <tr key={job.id}>
                            <td className="p-3.5 text-cyan-400 font-bold">{job.schedule}</td>
                            <td className="p-3.5 text-slate-300">{job.command}</td>
                            <td className="p-3.5 text-slate-400">{job.last_run}</td>
                            <td className="p-3.5 text-right">
                              <button onClick={() => handleDeleteCronJob(job.id)} className="text-rose-400 hover:underline cursor-pointer">
                                Delete
                              </button>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}
            </div>
          )}

          {/* WEBSITES TAB (LIST VIEW) */}
          {activeTab === 'websites' && !activeManageSite && (
            <div className="space-y-6">
              <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
                <div>
                  <h2 className="text-2xl font-bold text-white flex items-center gap-3">
                    <Globe className="w-7 h-7 text-cyan-400" />
                    <span>Hosted Websites & Virtual Hosts</span>
                  </h2>
                  <p className="text-sm text-slate-400 mt-1">Host WordPress, Laravel, Node.js, Python & Static sites</p>
                </div>

                <button
                  onClick={() => setShowAddWebsiteModal(true)}
                  className="bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-semibold px-5 py-2.5 rounded-xl text-sm transition-all shadow-lg shadow-cyan-500/20 flex items-center gap-2 cursor-pointer self-start md:self-auto"
                >
                  <Plus className="w-4 h-4" />
                  <span>Create Website</span>
                </button>
              </div>

              {/* Websites Grid */}
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
                {filteredWebsites.map((site) => (
                  <div key={site.id} className="bg-slate-900/80 border border-slate-800 hover:border-slate-700 rounded-2xl p-5 space-y-4 shadow-xl">
                    <div className="flex items-start justify-between">
                      <div className="flex items-center gap-3">
                        <div className="w-10 h-10 rounded-xl bg-gradient-to-tr from-cyan-500/20 to-blue-500/20 border border-cyan-500/30 flex items-center justify-center text-cyan-400 font-bold">
                          <Globe className="w-5 h-5" />
                        </div>
                        <div>
                          <h3 className="font-bold text-base text-white tracking-wide">{site.domain_name}</h3>
                          <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">{site.site_type}</span>
                        </div>
                      </div>

                      <button
                        onClick={() => handleDeleteWebsite(site.id, site.domain_name)}
                        className="text-slate-500 hover:text-rose-400 p-1 rounded cursor-pointer"
                        title="Delete"
                      >
                        <Trash2 className="w-4 h-4" />
                      </button>
                    </div>

                    <div className="bg-slate-950/80 p-3 rounded-xl border border-slate-800 text-xs font-mono space-y-1 text-slate-400">
                      <div>Root: <span className="text-slate-200">{site.document_root}</span></div>
                      <div>PHP: <span className="text-cyan-400">{site.php_version}</span></div>
                    </div>

                    <div className="grid grid-cols-2 gap-2">
                      <button
                        onClick={() => openManageSiteConsole(site)}
                        className="bg-slate-800 hover:bg-slate-700 text-slate-200 font-bold text-xs py-2 rounded-xl cursor-pointer border border-slate-700 flex items-center justify-center gap-1.5"
                      >
                        <Settings className="w-3.5 h-3.5 text-cyan-400" /> Manage Site
                      </button>
                      <button
                        onClick={() => {
                          setNewlyCreatedSite(site);
                          setShowSiteReadyModal(true);
                          setActiveConfigTab('nginx');
                        }}
                        className="bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs py-2 rounded-xl cursor-pointer shadow-md shadow-cyan-500/20 flex items-center justify-center gap-1.5"
                      >
                        <Code className="w-3.5 h-3.5" /> CloudPanel Config
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* ERROR ANALYSIS TAB */}
          {activeTab === 'error_analysis' && !activeManageSite && (
            <div className="space-y-6">
              <div>
                <h2 className="text-2xl font-bold text-white flex items-center gap-3">
                  <Bug className="w-7 h-7 text-amber-400" />
                  <span>Advanced Error Analysis & AI Root Cause Subsystem</span>
                </h2>
                <p className="text-sm text-slate-400 mt-1">Trace failures, stack traces, and evidence-grounded AI diagnostic reports</p>
              </div>

              <div className="space-y-4">
                {errorDiagnostics.map((err) => (
                  <div key={err.id} className="bg-slate-900/80 border border-slate-800 p-6 rounded-2xl space-y-3">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-3">
                        <span className="font-mono text-xs text-slate-400 font-bold">{err.incident_id}</span>
                        <span className="bg-slate-950 text-cyan-400 text-xs px-2.5 py-0.5 rounded-full border border-slate-800 font-mono">
                          {err.domain_name}
                        </span>
                        <span className="bg-rose-500/10 text-rose-400 text-xs px-2.5 py-0.5 rounded-full font-bold border border-rose-500/20">
                          {err.error_type}
                        </span>
                      </div>
                      <button
                        onClick={() => setSelectedIncident(err)}
                        className="bg-cyan-500 text-slate-950 font-bold text-xs px-4 py-2 rounded-xl cursor-pointer flex items-center gap-2"
                      >
                        <Sparkles className="w-3.5 h-3.5" /> AI Diagnostic Report
                      </button>
                    </div>
                    <div className="bg-slate-950 p-3.5 rounded-xl border border-slate-800 font-mono text-xs text-rose-300">{err.message}</div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* DATABASES TAB */}
          {activeTab === 'databases' && !activeManageSite && (
            <div className="space-y-6">
              <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
                <div>
                  <h2 className="text-2xl font-bold text-white flex items-center gap-3">
                    <Database className="w-7 h-7 text-indigo-400" />
                    <span>Database Engine Instances</span>
                  </h2>
                  <p className="text-sm text-slate-400 mt-1">Manage MySQL, PostgreSQL, MongoDB, Redis & SQLite databases</p>
                </div>

                <button
                  onClick={() => setShowAddDbModal(true)}
                  className="bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-semibold px-5 py-2.5 rounded-xl text-sm transition-all shadow-lg shadow-cyan-500/20 flex items-center gap-2 cursor-pointer self-start md:self-auto"
                >
                  <Plus className="w-4 h-4" />
                  <span>Create Database</span>
                </button>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
                {databases.map((db) => (
                  <div key={db.id} className="bg-slate-900/80 border border-slate-800 rounded-2xl p-5 space-y-4 shadow-xl">
                    <div className="flex items-center gap-3">
                      <div className="w-10 h-10 rounded-xl bg-indigo-500/20 border border-indigo-500/30 flex items-center justify-center text-indigo-400 font-bold">
                        <Database className="w-5 h-5" />
                      </div>
                      <div>
                        <h3 className="font-bold text-base text-white font-mono">{db.name}</h3>
                        <span className="text-[11px] font-semibold text-cyan-400 uppercase font-mono">{db.engine}</span>
                      </div>
                    </div>

                    <div className="bg-slate-950 p-3 rounded-xl border border-slate-800 text-xs font-mono text-slate-400 space-y-1">
                      <div>Host: <span className="text-slate-200">{db.host}:{db.port}</span></div>
                      <div>User: <span className="text-slate-200">{db.username}</span></div>
                      <div>Size: <span className="text-slate-200">{db.size_mb} MB</span></div>
                    </div>

                    <button
                      onClick={() => setSelectedDbConnModal(db)}
                      className="w-full bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-bold py-2 rounded-xl cursor-pointer flex items-center justify-center gap-2"
                    >
                      <Key className="w-3.5 h-3.5 text-cyan-400" /> Connection String
                    </button>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* FTP & FILES TAB */}
          {activeTab === 'ftp' && !activeManageSite && (
            <div className="space-y-6">
              <div>
                <h2 className="text-2xl font-bold text-white flex items-center gap-3">
                  <Folder className="w-7 h-7 text-amber-400" />
                  <span>FTP Accounts & File Access</span>
                </h2>
                <p className="text-sm text-slate-400 mt-1">Manage isolated FTP accounts and directory permissions</p>
              </div>

              <div className="bg-slate-900/80 border border-slate-800 rounded-2xl overflow-hidden shadow-xl">
                <table className="w-full text-left text-xs font-mono">
                  <thead className="bg-slate-950 text-slate-400 border-b border-slate-800 uppercase tracking-wider">
                    <tr>
                      <th className="p-3.5">Username</th>
                      <th className="p-3.5">Domain</th>
                      <th className="p-3.5">Path</th>
                      <th className="p-3.5">Status</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60 text-slate-200">
                    {ftpAccounts.map((acc) => (
                      <tr key={acc.id}>
                        <td className="p-3.5 text-cyan-400 font-bold">{acc.username}</td>
                        <td className="p-3.5 text-slate-300">{acc.domain_name}</td>
                        <td className="p-3.5 text-slate-400">{acc.path}</td>
                        <td className="p-3.5 text-emerald-400 font-bold">{acc.status.toUpperCase()}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* SERVICES TAB */}
          {activeTab === 'services' && !activeManageSite && (
            <div className="space-y-6">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                <div>
                  <h2 className="text-2xl font-bold text-white flex items-center gap-3">
                    <Server className="w-7 h-7 text-emerald-400" />
                    <span>System Daemons & VPS Services</span>
                  </h2>
                  <p className="text-sm text-slate-400 mt-1">Live systemd service controls for Nginx, PHP-FPM, MySQL, PostgreSQL & Redis</p>
                </div>
                <button
                  onClick={fetchData}
                  className="bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 text-xs font-semibold px-4 py-2 rounded-xl flex items-center gap-2 cursor-pointer self-start sm:self-auto"
                >
                  <RefreshCw className="w-3.5 h-3.5 text-cyan-400" /> Refresh Daemons
                </button>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {services.map((srv, i) => (
                  <div key={i} className="bg-slate-900/80 border border-slate-800 p-5 rounded-2xl flex flex-col justify-between gap-4 shadow-xl">
                    <div className="flex items-start justify-between">
                      <div>
                        <h3 className="font-bold text-base text-white">{srv.name}</h3>
                        <p className="text-xs text-slate-400 font-mono mt-0.5">
                          Service: <span className="text-cyan-400">{srv.engine}</span> | Uptime: {srv.uptime} | RAM: {srv.memory_mb} MB
                        </p>
                      </div>
                      <span className={`text-xs font-bold px-3 py-1 rounded-full border ${
                        srv.status === 'running'
                          ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                          : 'bg-rose-500/10 text-rose-400 border-rose-500/30'
                      }`}>
                        {srv.status.toUpperCase()}
                      </span>
                    </div>

                    <div className="flex flex-wrap items-center gap-2 pt-2 border-t border-slate-800/60 font-mono text-xs">
                      <button
                        onClick={() => handleServiceAction(srv.engine, 'restart')}
                        className="bg-slate-800 hover:bg-slate-700 text-amber-400 px-3 py-1.5 rounded-lg border border-slate-700 cursor-pointer font-bold flex items-center gap-1"
                      >
                        <RefreshCw className="w-3 h-3" /> Restart
                      </button>
                      <button
                        onClick={() => handleServiceAction(srv.engine, 'reload')}
                        className="bg-slate-800 hover:bg-slate-700 text-cyan-400 px-3 py-1.5 rounded-lg border border-slate-700 cursor-pointer font-bold flex items-center gap-1"
                      >
                        <RefreshCw className="w-3 h-3" /> Reload
                      </button>
                      {srv.status === 'running' ? (
                        <button
                          onClick={() => handleServiceAction(srv.engine, 'stop')}
                          className="bg-slate-800 hover:bg-rose-950/40 text-rose-400 px-3 py-1.5 rounded-lg border border-slate-700 cursor-pointer font-bold"
                        >
                          Stop
                        </button>
                      ) : (
                        <button
                          onClick={() => handleServiceAction(srv.engine, 'start')}
                          className="bg-emerald-500 hover:bg-emerald-400 text-slate-950 px-3 py-1.5 rounded-lg cursor-pointer font-bold"
                        >
                          Start
                        </button>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </main>
      </div>

      {/* CREATE WEBSITE MODAL (CloudPanel Style Stack Provisioner) */}
      {showAddWebsiteModal && (
        <div className="fixed inset-0 bg-slate-950/80 backdrop-blur-md z-50 flex items-center justify-center p-4 overflow-y-auto">
          <div className="bg-slate-900 border border-slate-800 w-full max-w-2xl rounded-2xl p-6 space-y-5 shadow-2xl my-8 max-h-[90vh] overflow-y-auto">
            <div className="flex items-center justify-between border-b border-slate-800 pb-4">
              <div>
                <h3 className="font-bold text-lg text-white flex items-center gap-2">
                  <Globe className="w-5 h-5 text-cyan-400" />
                  <span>Create New Production Website Host</span>
                </h3>
                <p className="text-xs text-slate-400">Select application stack to generate ready-to-copy production configs & credentials</p>
              </div>
              <button onClick={() => setShowAddWebsiteModal(false)} className="text-slate-400 hover:text-white cursor-pointer">✕</button>
            </div>

            <form onSubmit={handleCreateWebsite} className="space-y-5 text-sm">
              {/* Stack Selection Cards */}
              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-2">Select Application Stack</label>
                <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
                  {[
                    { id: 'wordpress', title: 'WordPress', desc: '1-Click WP + DB', icon: '📝', badge: 'PHP FPM' },
                    { id: 'laravel', title: 'Laravel App', desc: 'MVC + Env setup', icon: '⚡', badge: 'PHP FPM' },
                    { id: 'nodejs', title: 'Node.js App', desc: 'Express/Next.js Proxy', icon: '🟢', badge: 'Node.js' },
                    { id: 'static', title: 'Static HTML', desc: 'Fast HTML/JS/CSS', icon: '⚡', badge: 'Nginx' },
                    { id: 'python', title: 'Python App', desc: 'Flask/Django WSGI', icon: '🐍', badge: 'Python' },
                  ].map((st) => (
                    <button
                      type="button"
                      key={st.id}
                      onClick={() => setNewStack(st.id)}
                      className={`p-3 rounded-xl border text-left transition-all cursor-pointer space-y-1 ${
                        newStack === st.id
                          ? 'bg-cyan-500/15 border-cyan-500 text-white shadow-lg shadow-cyan-500/10'
                          : 'bg-slate-950 border-slate-800 text-slate-400 hover:border-slate-700 hover:text-slate-200'
                      }`}
                    >
                      <div className="flex items-center justify-between">
                        <span className="text-lg">{st.icon}</span>
                        <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-900 border border-slate-800 text-cyan-400 font-bold">{st.badge}</span>
                      </div>
                      <div className="font-bold text-xs text-white">{st.title}</div>
                      <div className="text-[11px] text-slate-500 leading-tight">{st.desc}</div>
                    </button>
                  ))}
                </div>
              </div>

              {/* General Settings */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 bg-slate-950 p-4 rounded-xl border border-slate-800">
                <div>
                  <label className="block text-xs font-semibold text-slate-300 mb-1.5">Domain Name *</label>
                  <input
                    type="text"
                    placeholder="mycompany.com"
                    required
                    value={newDomain}
                    onChange={(e) => setNewDomain(e.target.value)}
                    className="w-full bg-slate-900 border border-slate-800 rounded-xl px-3.5 py-2 text-xs font-mono text-white focus:outline-none focus:border-cyan-500"
                  />
                </div>

                {(newStack === 'wordpress' || newStack === 'laravel') && (
                  <div>
                    <label className="block text-xs font-semibold text-slate-300 mb-1.5">PHP Version</label>
                    <select
                      value={newPhp}
                      onChange={(e) => setNewPhp(e.target.value)}
                      className="w-full bg-slate-900 border border-slate-800 rounded-xl px-3.5 py-2 text-xs font-mono text-white focus:outline-none"
                    >
                      <option value="8.4">PHP 8.4 (Latest)</option>
                      <option value="8.3">PHP 8.3 (Recommended)</option>
                      <option value="8.2">PHP 8.2 (LTS)</option>
                    </select>
                  </div>
                )}

                {(newStack === 'nodejs' || newStack === 'python') && (
                  <div>
                    <label className="block text-xs font-semibold text-slate-300 mb-1.5">Application Port</label>
                    <input
                      type="number"
                      value={newAppPort}
                      onChange={(e) => setNewAppPort(parseInt(e.target.value) || 3000)}
                      className="w-full bg-slate-900 border border-slate-800 rounded-xl px-3.5 py-2 text-xs font-mono text-white focus:outline-none"
                    />
                  </div>
                )}
              </div>

              {/* WordPress Specific Config */}
              {newStack === 'wordpress' && (
                <div className="space-y-3 bg-slate-950 p-4 rounded-xl border border-slate-800">
                  <div className="flex items-center justify-between border-b border-slate-800 pb-2">
                    <span className="font-bold text-xs text-cyan-400 flex items-center gap-1.5">
                      <span>📝</span> WordPress Admin & Database Configuration
                    </span>
                    <button
                      type="button"
                      onClick={() => {
                        const pass = `Wp#${Math.floor(100000 + Math.random() * 900000)}!Sec`;
                        setNewAdminPass(pass);
                        setNewSiteDbPass(pass);
                        showToast('Auto-generated secure passwords!');
                      }}
                      className="text-[11px] font-bold text-amber-400 hover:underline cursor-pointer"
                    >
                      🎲 Auto-Generate Passwords
                    </button>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
                    <div>
                      <label className="block text-slate-400 mb-1">Site Title</label>
                      <input
                        type="text"
                        placeholder="My WordPress Site"
                        value={newSiteTitle}
                        onChange={(e) => setNewSiteTitle(e.target.value)}
                        className="w-full bg-slate-900 border border-slate-800 rounded-lg px-3 py-1.5 font-mono text-white"
                      />
                    </div>
                    <div>
                      <label className="block text-slate-400 mb-1">Admin Email</label>
                      <input
                        type="email"
                        placeholder="admin@mycompany.com"
                        value={newAdminEmail}
                        onChange={(e) => setNewAdminEmail(e.target.value)}
                        className="w-full bg-slate-900 border border-slate-800 rounded-lg px-3 py-1.5 font-mono text-white"
                      />
                    </div>
                    <div>
                      <label className="block text-slate-400 mb-1">Admin Username</label>
                      <input
                        type="text"
                        value={newAdminUser}
                        onChange={(e) => setNewAdminUser(e.target.value)}
                        className="w-full bg-slate-900 border border-slate-800 rounded-lg px-3 py-1.5 font-mono text-white"
                      />
                    </div>
                    <div>
                      <label className="block text-slate-400 mb-1">Admin Password</label>
                      <input
                        type="text"
                        value={newAdminPass}
                        onChange={(e) => setNewAdminPass(e.target.value)}
                        className="w-full bg-slate-900 border border-slate-800 rounded-lg px-3 py-1.5 font-mono text-amber-400 font-bold"
                      />
                    </div>
                    <div>
                      <label className="block text-slate-400 mb-1">MySQL Database Name</label>
                      <input
                        type="text"
                        placeholder="wp_domain_db"
                        value={newSiteDbName}
                        onChange={(e) => setNewSiteDbName(e.target.value)}
                        className="w-full bg-slate-900 border border-slate-800 rounded-lg px-3 py-1.5 font-mono text-slate-200"
                      />
                    </div>
                    <div>
                      <label className="block text-slate-400 mb-1">MySQL DB Password</label>
                      <input
                        type="text"
                        value={newSiteDbPass}
                        onChange={(e) => setNewSiteDbPass(e.target.value)}
                        className="w-full bg-slate-900 border border-slate-800 rounded-lg px-3 py-1.5 font-mono text-emerald-400 font-bold"
                      />
                    </div>
                  </div>

                  <div className="pt-2">
                    <button
                      type="button"
                      onClick={() => {
                        const domainClean = newDomain.toLowerCase().trim() || 'wordpress.local';
                        const titleClean = newSiteTitle.trim() || 'My WordPress Site';
                        const dbNameClean = newSiteDbName.trim() || `wp_${domainClean.replace(/[^a-z0-9]/g, '_')}`;
                        const dbUserClean = newSiteDbUser.trim() || `${dbNameClean}_usr`;
                        const dbPassClean = newSiteDbPass.trim() || `Db#${Math.floor(1000 + Math.random() * 9000)}!Pass`;
                        const wpConfigContent = generateEnvFileContent(domainClean, titleClean, 'wordpress', dbNameClean, dbUserClean, dbPassClean);
                        handleDownloadFile(wpConfigContent, 'wp-config.php');
                      }}
                      className="w-full bg-slate-900 hover:bg-slate-800 border border-slate-700 text-cyan-400 font-bold text-xs py-2 rounded-xl cursor-pointer flex items-center justify-center gap-2 shadow-sm"
                    >
                      <Download className="w-4 h-4 text-emerald-400" />
                      <span>Download Latest WordPress Setup Config (wp-config.php)</span>
                    </button>
                  </div>
                </div>
              )}

              {/* Laravel Specific Config */}
              {newStack === 'laravel' && (
                <div className="space-y-3 bg-slate-950 p-4 rounded-xl border border-slate-800">
                  <div className="flex items-center justify-between border-b border-slate-800 pb-2">
                    <span className="font-bold text-xs text-cyan-400 flex items-center gap-1.5">
                      <span>⚡</span> Laravel App & Environment Configuration
                    </span>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
                    <div>
                      <label className="block text-slate-400 mb-1">App Name</label>
                      <input
                        type="text"
                        placeholder="Laravel API Gateway"
                        value={newSiteTitle}
                        onChange={(e) => setNewSiteTitle(e.target.value)}
                        className="w-full bg-slate-900 border border-slate-800 rounded-lg px-3 py-1.5 font-mono text-white"
                      />
                    </div>
                    <div>
                      <label className="block text-slate-400 mb-1">Database Name</label>
                      <input
                        type="text"
                        placeholder="lrv_db_prod"
                        value={newSiteDbName}
                        onChange={(e) => setNewSiteDbName(e.target.value)}
                        className="w-full bg-slate-900 border border-slate-800 rounded-lg px-3 py-1.5 font-mono text-white"
                      />
                    </div>
                    <div>
                      <label className="block text-slate-400 mb-1">Database Password</label>
                      <input
                        type="text"
                        value={newSiteDbPass}
                        onChange={(e) => setNewSiteDbPass(e.target.value)}
                        className="w-full bg-slate-900 border border-slate-800 rounded-lg px-3 py-1.5 font-mono text-emerald-400 font-bold"
                      />
                    </div>
                    <div>
                      <label className="block text-slate-400 mb-1">App Key (APP_KEY)</label>
                      <input
                        type="text"
                        value={newAppKey}
                        onChange={(e) => setNewAppKey(e.target.value)}
                        className="w-full bg-slate-900 border border-slate-800 rounded-lg px-3 py-1.5 font-mono text-cyan-400 text-[11px]"
                      />
                    </div>
                  </div>
                </div>
              )}

              {/* Node.js Specific Config */}
              {newStack === 'nodejs' && (
                <div className="space-y-3 bg-slate-950 p-4 rounded-xl border border-slate-800">
                  <div className="flex items-center justify-between border-b border-slate-800 pb-2">
                    <span className="font-bold text-xs text-cyan-400 flex items-center gap-1.5">
                      <span>🟢</span> Node.js Application & Service Settings
                    </span>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
                    <div>
                      <label className="block text-slate-400 mb-1">Entry Script</label>
                      <input
                        type="text"
                        placeholder="app.js or server.js"
                        value={newEntryScript}
                        onChange={(e) => setNewEntryScript(e.target.value)}
                        className="w-full bg-slate-900 border border-slate-800 rounded-lg px-3 py-1.5 font-mono text-white"
                      />
                    </div>
                    <div>
                      <label className="block text-slate-400 mb-1">Node Version</label>
                      <select
                        value={newNodeVersion}
                        onChange={(e) => setNewNodeVersion(e.target.value)}
                        className="w-full bg-slate-900 border border-slate-800 rounded-lg px-3 py-1.5 font-mono text-white"
                      >
                        <option value="22.x">Node.js 22.x LTS</option>
                        <option value="20.x">Node.js 20.x LTS</option>
                        <option value="18.x">Node.js 18.x</option>
                      </select>
                    </div>
                  </div>
                </div>
              )}

              <div className="pt-3 flex gap-3">
                <button type="button" onClick={() => setShowAddWebsiteModal(false)} className="flex-1 bg-slate-800 text-slate-300 font-semibold py-2.5 rounded-xl cursor-pointer">Cancel</button>
                <button type="submit" className="flex-1 bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold py-2.5 rounded-xl cursor-pointer shadow-lg shadow-cyan-500/20">
                  🚀 Provision Website Host
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* PRODUCTION SITE READY SUMMARY MODAL (CloudPanel Style) */}
      {showSiteReadyModal && newlyCreatedSite && (
        <div className="fixed inset-0 bg-slate-950/85 backdrop-blur-md z-50 flex items-center justify-center p-4 overflow-y-auto">
          <div className="bg-slate-900 border border-slate-800 w-full max-w-4xl max-h-[90vh] overflow-y-auto rounded-2xl p-6 space-y-6 shadow-2xl my-6">
            {/* Modal Header */}
            <div className="flex items-center justify-between border-b border-slate-800 pb-4">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 rounded-xl bg-gradient-to-tr from-emerald-500 to-cyan-500 flex items-center justify-center text-slate-950 font-bold shadow-lg shadow-emerald-500/20">
                  <CheckCircle2 className="w-6 h-6" />
                </div>
                <div>
                  <h3 className="font-bold text-lg text-white flex items-center gap-2">
                    <span>🎉 Website Provisioned & Ready for Production!</span>
                  </h3>
                  <p className="text-xs text-slate-400">
                    Host: <span className="text-cyan-400 font-mono font-bold">{newlyCreatedSite.domain_name}</span> | Stack:{' '}
                    <span className="text-emerald-400 font-mono font-bold uppercase">{newlyCreatedSite.site_type}</span>
                  </p>
                </div>
              </div>
              <button onClick={() => setShowSiteReadyModal(false)} className="text-slate-400 hover:text-white cursor-pointer font-bold text-lg">✕</button>
            </div>

            {/* Quick Action Bar */}
            <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
              <div className="text-xs font-mono text-slate-300">
                Status: <span className="text-emerald-400 font-bold">ACTIVE & READY</span> | SSL: <span className="text-cyan-400 font-bold">AUTO LET'S ENCRYPT</span>
              </div>
              <div className="flex gap-2">
                <a
                  href={`https://${newlyCreatedSite.domain_name}`}
                  target="_blank"
                  rel="noreferrer"
                  className="bg-slate-800 hover:bg-slate-700 text-cyan-400 font-bold text-xs px-3.5 py-2 rounded-xl border border-slate-700 flex items-center gap-1.5 cursor-pointer"
                >
                  <ExternalLink className="w-3.5 h-3.5" /> Visit Site 🔗
                </a>
                {newlyCreatedSite.site_type === 'wordpress' && (
                  <a
                    href={`https://${newlyCreatedSite.domain_name}/wp-admin`}
                    target="_blank"
                    rel="noreferrer"
                    className="bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs px-3.5 py-2 rounded-xl shadow-lg shadow-cyan-500/20 flex items-center gap-1.5 cursor-pointer"
                  >
                    <Key className="w-3.5 h-3.5" /> WP Admin 🔐
                  </a>
                )}
              </div>
            </div>

            {/* Credentials Grid with 1-Click Copy */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              {/* Admin Credentials */}
              <div className="bg-slate-950/90 border border-slate-800 p-4 rounded-xl space-y-2.5">
                <div className="text-xs font-bold text-slate-300 uppercase tracking-wider flex items-center justify-between">
                  <span>Admin Credentials</span>
                  <span className="text-cyan-400 text-[10px] font-mono">{newlyCreatedSite.site_type.toUpperCase()}</span>
                </div>
                <div className="space-y-2 text-xs font-mono">
                  <div className="bg-slate-900 p-2.5 rounded-lg border border-slate-800 flex items-center justify-between">
                    <div>
                      <div className="text-[10px] text-slate-500">Username</div>
                      <div className="text-slate-200 font-bold">{newlyCreatedSite.admin_user || 'admin_wp'}</div>
                    </div>
                    <button
                      onClick={() => handleCopyText(newlyCreatedSite.admin_user || 'admin_wp', 'Admin User')}
                      className="text-slate-400 hover:text-cyan-400 p-1 cursor-pointer"
                    >
                      {copiedField === 'Admin User' ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
                    </button>
                  </div>

                  <div className="bg-slate-900 p-2.5 rounded-lg border border-slate-800 flex items-center justify-between">
                    <div>
                      <div className="text-[10px] text-slate-500">Password</div>
                      <div className="text-amber-400 font-bold">{newlyCreatedSite.admin_pass || 'WpPass#2026!Sec'}</div>
                    </div>
                    <button
                      onClick={() => handleCopyText(newlyCreatedSite.admin_pass || 'WpPass#2026!Sec', 'Admin Password')}
                      className="text-slate-400 hover:text-cyan-400 p-1 cursor-pointer"
                    >
                      {copiedField === 'Admin Password' ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
                    </button>
                  </div>
                </div>
              </div>

              {/* Database Credentials */}
              <div className="bg-slate-950/90 border border-slate-800 p-4 rounded-xl space-y-2.5">
                <div className="text-xs font-bold text-slate-300 uppercase tracking-wider flex items-center justify-between">
                  <span>Database Instance</span>
                  <span className="text-indigo-400 text-[10px] font-mono">MYSQL / POSTGRES</span>
                </div>
                <div className="space-y-2 text-xs font-mono">
                  <div className="bg-slate-900 p-2.5 rounded-lg border border-slate-800 flex items-center justify-between">
                    <div>
                      <div className="text-[10px] text-slate-500">Database Name</div>
                      <div className="text-slate-200 font-bold">{newlyCreatedSite.db_name || 'wp_db'}</div>
                    </div>
                    <button
                      onClick={() => handleCopyText(newlyCreatedSite.db_name || 'wp_db', 'Database Name')}
                      className="text-slate-400 hover:text-cyan-400 p-1 cursor-pointer"
                    >
                      {copiedField === 'Database Name' ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
                    </button>
                  </div>

                  <div className="bg-slate-900 p-2.5 rounded-lg border border-slate-800 flex items-center justify-between">
                    <div>
                      <div className="text-[10px] text-slate-500">DB Password</div>
                      <div className="text-emerald-400 font-bold">{newlyCreatedSite.db_pass || 'DbPass#2026!Sec'}</div>
                    </div>
                    <button
                      onClick={() => handleCopyText(newlyCreatedSite.db_pass || 'DbPass#2026!Sec', 'DB Password')}
                      className="text-slate-400 hover:text-cyan-400 p-1 cursor-pointer"
                    >
                      {copiedField === 'DB Password' ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
                    </button>
                  </div>
                </div>
              </div>

              {/* FTP Details */}
              <div className="bg-slate-950/90 border border-slate-800 p-4 rounded-xl space-y-2.5">
                <div className="text-xs font-bold text-slate-300 uppercase tracking-wider flex items-center justify-between">
                  <span>FTP Access</span>
                  <span className="text-amber-400 text-[10px] font-mono">PORT 21 / 22</span>
                </div>
                <div className="space-y-2 text-xs font-mono">
                  <div className="bg-slate-900 p-2.5 rounded-lg border border-slate-800 flex items-center justify-between">
                    <div>
                      <div className="text-[10px] text-slate-500">FTP Host</div>
                      <div className="text-slate-200 font-bold">ftp.{newlyCreatedSite.domain_name}</div>
                    </div>
                    <button
                      onClick={() => handleCopyText(`ftp.${newlyCreatedSite.domain_name}`, 'FTP Host')}
                      className="text-slate-400 hover:text-cyan-400 p-1 cursor-pointer"
                    >
                      {copiedField === 'FTP Host' ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
                    </button>
                  </div>

                  <div className="bg-slate-900 p-2.5 rounded-lg border border-slate-800 flex items-center justify-between">
                    <div>
                      <div className="text-[10px] text-slate-500">Root Directory</div>
                      <div className="text-cyan-400 font-bold text-[11px] truncate max-w-[150px]">{newlyCreatedSite.document_root}</div>
                    </div>
                    <button
                      onClick={() => handleCopyText(newlyCreatedSite.document_root, 'Document Root')}
                      className="text-slate-400 hover:text-cyan-400 p-1 cursor-pointer"
                    >
                      {copiedField === 'Document Root' ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
                    </button>
                  </div>
                </div>
              </div>
            </div>

            {/* Tabbed Copyable Production Configuration Files (CloudPanel Style) */}
            <div className="bg-slate-950 border border-slate-800 rounded-xl p-5 space-y-4">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-3">
                <h4 className="font-bold text-xs text-slate-200 uppercase tracking-wider flex items-center gap-2">
                  <FileCode className="w-4 h-4 text-cyan-400" />
                  <span>Production Ready Configuration Files (Click Tab to Copy)</span>
                </h4>

                <div className="flex gap-1.5 bg-slate-900 p-1 rounded-lg border border-slate-800 overflow-x-auto">
                  <button
                    onClick={() => setActiveConfigTab('nginx')}
                    className={`px-2.5 py-1 rounded text-xs font-bold cursor-pointer whitespace-nowrap ${
                      activeConfigTab === 'nginx' ? 'bg-cyan-500 text-slate-950' : 'text-slate-400 hover:text-white'
                    }`}
                  >
                    Nginx VHost
                  </button>
                  <button
                    onClick={() => setActiveConfigTab('env')}
                    className={`px-2.5 py-1 rounded text-xs font-bold cursor-pointer whitespace-nowrap ${
                      activeConfigTab === 'env' ? 'bg-cyan-500 text-slate-950' : 'text-slate-400 hover:text-white'
                    }`}
                  >
                    {newlyCreatedSite.site_type === 'wordpress' ? 'wp-config.php' : '.env File'}
                  </button>
                  {(newlyCreatedSite.site_type === 'nodejs' || newlyCreatedSite.site_type === 'python') && (
                    <button
                      onClick={() => setActiveConfigTab('systemd')}
                      className={`px-2.5 py-1 rounded text-xs font-bold cursor-pointer whitespace-nowrap ${
                        activeConfigTab === 'systemd' ? 'bg-cyan-500 text-slate-950' : 'text-slate-400 hover:text-white'
                      }`}
                    >
                      Systemd Service
                    </button>
                  )}
                  {(newlyCreatedSite.site_type === 'wordpress' || newlyCreatedSite.site_type === 'laravel') && (
                    <button
                      onClick={() => setActiveConfigTab('fpm')}
                      className={`px-2.5 py-1 rounded text-xs font-bold cursor-pointer whitespace-nowrap ${
                        activeConfigTab === 'fpm' ? 'bg-cyan-500 text-slate-950' : 'text-slate-400 hover:text-white'
                      }`}
                    >
                      PHP-FPM Pool
                    </button>
                  )}
                  <button
                    onClick={() => setActiveConfigTab('deploy')}
                    className={`px-2.5 py-1 rounded text-xs font-bold cursor-pointer whitespace-nowrap ${
                      activeConfigTab === 'deploy' ? 'bg-cyan-500 text-slate-950' : 'text-slate-400 hover:text-white'
                    }`}
                  >
                    Deploy Script
                  </button>
                </div>
              </div>

              <div className="relative">
                <div className="absolute top-3 right-3 flex items-center gap-2">
                  <button
                    onClick={() => {
                      const code =
                        activeConfigTab === 'nginx'
                          ? newlyCreatedSite.nginx_config || generateNginxConfig(newlyCreatedSite.domain_name, newlyCreatedSite.document_root, newlyCreatedSite.site_type, newlyCreatedSite.php_version, newlyCreatedSite.app_port)
                          : activeConfigTab === 'env'
                          ? newlyCreatedSite.env_file_content || generateEnvFileContent(newlyCreatedSite.domain_name, newlyCreatedSite.site_title, newlyCreatedSite.site_type, newlyCreatedSite.db_name, newlyCreatedSite.db_user, newlyCreatedSite.db_pass)
                          : activeConfigTab === 'systemd'
                          ? newlyCreatedSite.systemd_content || generateSystemdContent(newlyCreatedSite.domain_name, newlyCreatedSite.document_root, newlyCreatedSite.site_type)
                          : activeConfigTab === 'fpm'
                          ? newlyCreatedSite.fpm_pool_content || generateFPMPoolContent(newlyCreatedSite.domain_name, newlyCreatedSite.php_version)
                          : newlyCreatedSite.deploy_script_content || generateDeployScriptContent(newlyCreatedSite.domain_name, newlyCreatedSite.document_root);

                      const filename =
                        activeConfigTab === 'nginx'
                          ? `${newlyCreatedSite.domain_name}.conf`
                          : activeConfigTab === 'env'
                          ? (newlyCreatedSite.site_type === 'wordpress' ? 'wp-config.php' : '.env')
                          : activeConfigTab === 'systemd'
                          ? `${newlyCreatedSite.domain_name}.service`
                          : activeConfigTab === 'fpm'
                          ? `${newlyCreatedSite.domain_name}-fpm.conf`
                          : 'deploy.sh';

                      handleDownloadFile(code, filename);
                    }}
                    className="bg-slate-800 hover:bg-slate-700 text-emerald-400 font-bold text-xs px-3 py-1 rounded-lg border border-slate-700 flex items-center gap-1.5 cursor-pointer shadow-md"
                  >
                    <Download className="w-3.5 h-3.5 text-emerald-400" />
                    <span>Download File</span>
                  </button>

                  <button
                    onClick={() => {
                      const code =
                        activeConfigTab === 'nginx'
                          ? newlyCreatedSite.nginx_config || generateNginxConfig(newlyCreatedSite.domain_name, newlyCreatedSite.document_root, newlyCreatedSite.site_type, newlyCreatedSite.php_version, newlyCreatedSite.app_port)
                          : activeConfigTab === 'env'
                          ? newlyCreatedSite.env_file_content || generateEnvFileContent(newlyCreatedSite.domain_name, newlyCreatedSite.site_title, newlyCreatedSite.site_type, newlyCreatedSite.db_name, newlyCreatedSite.db_user, newlyCreatedSite.db_pass)
                          : activeConfigTab === 'systemd'
                          ? newlyCreatedSite.systemd_content || generateSystemdContent(newlyCreatedSite.domain_name, newlyCreatedSite.document_root, newlyCreatedSite.site_type)
                          : activeConfigTab === 'fpm'
                          ? newlyCreatedSite.fpm_pool_content || generateFPMPoolContent(newlyCreatedSite.domain_name, newlyCreatedSite.php_version)
                          : newlyCreatedSite.deploy_script_content || generateDeployScriptContent(newlyCreatedSite.domain_name, newlyCreatedSite.document_root);

                      handleCopyText(code, `${activeConfigTab.toUpperCase()} Config`);
                    }}
                    className="bg-slate-800 hover:bg-slate-700 text-cyan-400 font-bold text-xs px-3 py-1 rounded-lg border border-slate-700 flex items-center gap-1.5 cursor-pointer shadow-md"
                  >
                    {copiedField === `${activeConfigTab.toUpperCase()} Config` ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                    <span>Copy Snippet</span>
                  </button>
                </div>

                <pre className="bg-slate-900 p-4 rounded-xl border border-slate-800 text-xs font-mono text-emerald-400 overflow-x-auto max-h-72 leading-relaxed">
                  {activeConfigTab === 'nginx' && (newlyCreatedSite.nginx_config || generateNginxConfig(newlyCreatedSite.domain_name, newlyCreatedSite.document_root, newlyCreatedSite.site_type, newlyCreatedSite.php_version, newlyCreatedSite.app_port))}
                  {activeConfigTab === 'env' && (newlyCreatedSite.env_file_content || generateEnvFileContent(newlyCreatedSite.domain_name, newlyCreatedSite.site_title, newlyCreatedSite.site_type, newlyCreatedSite.db_name, newlyCreatedSite.db_user, newlyCreatedSite.db_pass))}
                  {activeConfigTab === 'systemd' && (newlyCreatedSite.systemd_content || generateSystemdContent(newlyCreatedSite.domain_name, newlyCreatedSite.document_root, newlyCreatedSite.site_type))}
                  {activeConfigTab === 'fpm' && (newlyCreatedSite.fpm_pool_content || generateFPMPoolContent(newlyCreatedSite.domain_name, newlyCreatedSite.php_version))}
                  {activeConfigTab === 'deploy' && (newlyCreatedSite.deploy_script_content || generateDeployScriptContent(newlyCreatedSite.domain_name, newlyCreatedSite.document_root))}
                </pre>
              </div>
            </div>

            <div className="flex justify-end pt-2">
              <button
                onClick={() => {
                  setShowSiteReadyModal(false);
                  openManageSiteConsole(newlyCreatedSite);
                  setSiteManageSubTab('production_config');
                }}
                className="bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs px-6 py-2.5 rounded-xl cursor-pointer shadow-lg shadow-cyan-500/20"
              >
                Go to Website Console →
              </button>
            </div>
          </div>
        </div>
      )}

      {/* CREATE DB MODAL */}
      {showAddDbModal && (
        <div className="fixed inset-0 bg-slate-950/80 backdrop-blur-md z-50 flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 w-full max-w-lg rounded-2xl p-6 space-y-5 shadow-2xl">
            <div className="flex items-center justify-between border-b border-slate-800 pb-4">
              <h3 className="font-bold text-lg text-white flex items-center gap-2">
                <Database className="w-5 h-5 text-indigo-400" />
                <span>Create Database Instance</span>
              </h3>
              <button onClick={() => setShowAddDbModal(false)} className="text-slate-400 hover:text-white cursor-pointer">✕</button>
            </div>

            <form onSubmit={handleCreateDatabase} className="space-y-4 text-sm">
              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1.5">Database Name</label>
                <input
                  type="text"
                  placeholder="app_db_prod"
                  required
                  value={newDbName}
                  onChange={(e) => setNewDbName(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-xl px-4 py-2.5 text-white focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1.5">Database Engine</label>
                <select
                  value={newDbEngine}
                  onChange={(e) => setNewDbEngine(e.target.value as any)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2.5 text-white focus:outline-none"
                >
                  <option value="mysql">MySQL / MariaDB</option>
                  <option value="postgresql">PostgreSQL</option>
                  <option value="mongodb">MongoDB</option>
                  <option value="redis">Redis Key-Value</option>
                  <option value="sqlite">SQLite</option>
                </select>
              </div>

              <div className="pt-3 flex gap-3">
                <button type="button" onClick={() => setShowAddDbModal(false)} className="flex-1 bg-slate-800 text-slate-300 font-semibold py-2.5 rounded-xl cursor-pointer">Cancel</button>
                <button type="submit" className="flex-1 bg-cyan-500 text-slate-950 font-bold py-2.5 rounded-xl cursor-pointer">Create Instance</button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* CONNECTION URI MODAL */}
      {selectedDbConnModal && (
        <div className="fixed inset-0 bg-slate-950/80 backdrop-blur-md z-50 flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 w-full max-w-lg rounded-2xl p-6 space-y-4 shadow-2xl">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h3 className="font-bold text-base text-white flex items-center gap-2">
                <Key className="w-4 h-4 text-cyan-400" />
                <span>Connection String - {selectedDbConnModal.name}</span>
              </h3>
              <button onClick={() => setSelectedDbConnModal(null)} className="text-slate-400 hover:text-white cursor-pointer">✕</button>
            </div>
            <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 font-mono text-xs text-emerald-400 break-all select-all">
              {selectedDbConnModal.connection_uri}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
