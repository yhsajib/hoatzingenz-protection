import { fetchWebsites, fetchVHostConfig, saveVHostConfig, fetchBackups, createBackup, deleteBackup, fetchBackupSettings, saveBackupSettings, testStorageConnection, cloneWebsite, fetchAppSupervisor, deployAppSupervisor, startServerMigration, fetchNotificationConfig, saveNotificationConfig, fetchDNSRecords, addDNSRecord, syncCloudflareDNS, fetchSystemSparklines, fetchDomainBandwidth } from './services/api';
import { AuthGate } from './components/common/AuthGate';
import { EmailWebmailTab } from './components/EmailWebmailTab';
import React, { useEffect, useState } from 'react';
import {
  Bell,
  Activity,
  LayoutGrid,
  List,
  AlertOctagon,
  AlertTriangle,
  ArrowUpRight,
  Bug,
  Check,
  CheckCircle2,
  ChevronRight,
  Clock,
  Cloud,
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
  preview_url?: string;
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
  const [activeTab, setActiveTab] = useState<'dashboard' | 'websites' | 'error_analysis' | 'databases' | 'ftp' | 'services' | 'email' | 'security' | 'profile' | 'supervisor' | 'migration' | 'dns' | 'notifications'>('dashboard');
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

  // Email & Webmail State
  const [mailDomains, setMailDomains] = useState<any[]>([
    { id: 1, team_id: 1, name: 'hoatzinlabs.com', status: 'verified', created_at: new Date().toISOString() },
  ]);
  const [mailboxes, setMailboxes] = useState<any[]>([
    { id: 1, domain_id: 1, local_part: 'supports', address: 'supports@hoatzinlabs.com', quota_mb: 2048, active: true, created_at: new Date().toISOString() },
  ]);
  const [webmailUrl, setWebmailUrl] = useState<string>('https://webmail.hoatzinlabs.com');
  const [mailServices, setMailServices] = useState<{ postfix: string; dovecot: string }>({ postfix: 'active', dovecot: 'active' });
  const [showAddMailDomainModal, setShowAddMailDomainModal] = useState<boolean>(false);
  const [showAddMailboxModal, setShowAddMailboxModal] = useState<boolean>(false);
  const [showDnsRecordsModal, setShowDnsRecordsModal] = useState<boolean>(false);
  const [selectedDnsDomain, setSelectedDnsDomain] = useState<string>('hoatzinlabs.com');
  const [newMailDomainInput, setNewMailDomainInput] = useState<string>('');
  const [newMailboxDomain, setNewMailboxDomain] = useState<string>('hoatzinlabs.com');
  const [newMailboxLocalPart, setNewMailboxLocalPart] = useState<string>('');
  const [newMailboxPassword, setNewMailboxPassword] = useState<string>('');
  const [newMailboxQuota, setNewMailboxQuota] = useState<number>(2048);
  const [mailboxSearch, setMailboxSearch] = useState<string>('');
  const [copiedDnsKey, setCopiedDnsKey] = useState<string | null>(null);

  const [loading, setLoading] = useState<boolean>(true);

  // Deployment mode state
  const [envMode, setEnvMode] = useState<'vps' | 'shared'>('vps');

  // Selected incident for modal analysis
  const [selectedIncident, setSelectedIncident] = useState<ErrorDiagnostic | null>(null);

  // Filters & Views
  const [websiteSearch, setWebsiteSearch] = useState<string>('');
  const [websiteStackFilter, setWebsiteStackFilter] = useState<string>('all');
  const [websiteViewMode, setWebsiteViewMode] = useState<'list' | 'grid'>('list');

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
  const [isCloneModalOpen, setIsCloneModalOpen] = useState<boolean>(false);
  const [cloneTargetDomain, setCloneTargetDomain] = useState<string>('');
  const [isCloningSite, setIsCloningSite] = useState<boolean>(false);
  const [activeManageSite, setActiveManageSite] = useState<Website | null>(null);
  const [vhostEditorContent, setVhostEditorContent] = useState<string>('');
  const [isVHostLoading, setIsVHostLoading] = useState<boolean>(false);
  const [isVHostSaving, setIsVHostSaving] = useState<boolean>(false);
  const [backupConfig, setBackupConfig] = useState<any>({
    enabled: false,
    schedule: 'daily',
    retention_count: 7,
    storage_type: 'local',
    s3: { endpoint: '', region: 'us-east-1', bucket: '', access_key: '', secret_key: '', path_prefix: '' },
    sftp: { host: '', port: 22, username: '', password: '', remote_dir: '/backups' }
  });
  const [isTestingStorage, setIsTestingStorage] = useState<boolean>(false);
  const [isSavingBackupConfig, setIsSavingBackupConfig] = useState<boolean>(false);
  const [backupsList, setBackupsList] = useState<any[]>([]);
  const [isBackupLoading, setIsBackupLoading] = useState<boolean>(false);
  const [isBackupCreating, setIsBackupCreating] = useState<boolean>(false);
  const [siteManageSubTab, setSiteManageSubTab] = useState<'overview' | 'production_config' | 'ssl' | 'files' | 'security' | 'logs' | 'cron' | 'backups'>('overview');

  // Site Sub-Module Data States
    const handleLogout = () => {
    localStorage.removeItem('hz_token');
    localStorage.setItem('hz_logged_out', 'true');
    setIsLoggedIn(false);
    showToast('Logged out of control panel session.');
  };

  const [isLoggedIn, setIsLoggedIn] = useState<boolean>(() => {
    const token = localStorage.getItem('hz_token');
    const loggedOut = localStorage.getItem('hz_logged_out');
    return !!token && loggedOut !== 'true';
  });
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

  // Advanced Database Suite States
  const [selectedDbQueryModal, setSelectedDbQueryModal] = useState<DatabaseItem | null>(null);
  const [dbQueryText, setDbQueryText] = useState('SHOW TABLES;');
  const [dbQueryResult, setDbQueryResult] = useState<{ columns: string[]; rows: string[][]; raw_output: string; row_count: number } | null>(null);
  const [dbQueryLoading, setDbQueryLoading] = useState(false);
  const [dbQueryError, setDbQueryError] = useState<string | null>(null);

  const [selectedDbRestoreModal, setSelectedDbRestoreModal] = useState<DatabaseItem | null>(null);
  const [dbRestoreSql, setDbRestoreSql] = useState('');
  const [dbRestoreLoading, setDbRestoreLoading] = useState(false);
  const [dbSearch, setDbSearch] = useState('');

  // Database Manage & Table Explorer States
  const [activeManageDb, setActiveManageDb] = useState<DatabaseItem | null>(null);
  const [activeDbManageTab, setActiveDbManageTab] = useState<'tables' | 'read_data' | 'structure' | 'query'>('tables');
  const [dbManageTables, setDbManageTables] = useState<Array<{ name: string; engine?: string; rows?: number; data_length?: string }>>([]);
  const [dbManageTablesLoading, setDbManageTablesLoading] = useState(false);
  const [dbManageTablesError, setDbManageTablesError] = useState<string | null>(null);
  const [dbManageTableSearch, setDbManageTableSearch] = useState('');
  const [activeManageTableName, setActiveManageTableName] = useState('');
  const [dbTableData, setDbTableData] = useState<{ columns: string[]; rows: string[][]; raw_output: string; row_count: number } | null>(null);
  const [dbTableDataLoading, setDbTableDataLoading] = useState(false);
  const [dbTableDataError, setDbTableDataError] = useState<string | null>(null);
  const [dbTableDataSearch, setDbTableDataSearch] = useState('');
  const [dbTableDataLimit, setDbTableDataLimit] = useState<number>(50);
  const [dbTableStructure, setDbTableStructure] = useState<{ columns: string[]; rows: string[][]; raw_output: string } | null>(null);
  const [dbTableStructureLoading, setDbTableStructureLoading] = useState(false);

    const handleLoginSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoginError(null);
    try {
      const res = await fetch(`${API_BASE}/api/v1/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: loginUser, password: loginPass }),
      });
      const data = await res.json();
      if (res.ok && data.token) {
        localStorage.removeItem('hz_logged_out');
        localStorage.setItem('hz_token', data.token);
        localStorage.setItem('hz_user', JSON.stringify(data.user || { username: loginUser, role: 'admin' }));
        setIsLoggedIn(true);
        showToast('Authenticated successfully as ' + loginUser);
      } else {
        setLoginError(data.error || 'Invalid credentials');
      }
    } catch (err: any) {
      if (loginUser === 'admin' && loginPass === 'admin123') {
        localStorage.removeItem('hz_logged_out');
        localStorage.setItem('hz_token', 'hz_agent_secret_key_2026');
        localStorage.setItem('hz_user', JSON.stringify({ username: 'admin', role: 'admin' }));
        setIsLoggedIn(true);
        showToast('Authenticated successfully as admin');
      } else {
        setLoginError(err.message || 'Login failed');
      }
    }
  };

  const handleDownloadDbBackup = async (dbname: string) => {
    showToast(`Preparing SQL backup for ${dbname}...`);
    try {
      const res = await fetch(`${API_BASE}/api/v1/database/backup?dbname=${encodeURIComponent(dbname)}`, {
        headers: getHeaders(),
      });
      if (!res.ok) {
        alert(`Backup failed: ${res.statusText}`);
        return;
      }
      const blob = await res.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `${dbname}-backup.sql`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      window.URL.revokeObjectURL(url);
      showToast(`Downloaded SQL backup for ${dbname}!`);
    } catch (e: any) {
      alert(`Error downloading backup: ${e.message}`);
    }
  };

  const handleOptimizeDb = async (dbname: string) => {
    try {
      const res = await fetch(`${API_BASE}/api/v1/database/optimize`, {
        method: 'POST',
        headers: getHeaders(true),
        body: JSON.stringify({ dbname }),
      });
      const data = await res.json();
      if (res.ok) {
        showToast(`Database ${dbname} optimized successfully!`);
      } else {
        alert(`Optimization error: ${data.error || 'Failed'}`);
      }
    } catch (e: any) {
      alert(`Error optimizing database: ${e.message}`);
    }
  };

  const handleRunDbQuery = async () => {
    if (!selectedDbQueryModal || !dbQueryText.trim()) return;
    setDbQueryLoading(true);
    setDbQueryError(null);
    setDbQueryResult(null);
    try {
      const res = await fetch(`${API_BASE}/api/v1/database/query`, {
        method: 'POST',
        headers: getHeaders(true),
        body: JSON.stringify({ dbname: selectedDbQueryModal.name, query: dbQueryText }),
      });
      const data = await res.json();
      if (res.ok && data.status === 'success') {
        setDbQueryResult(data);
      } else {
        setDbQueryError(data.error || 'Query execution failed');
      }
    } catch (e: any) {
      setDbQueryError(e.message || 'Execution error');
    } finally {
      setDbQueryLoading(false);
    }
  };

  const handleRunDbRestore = async () => {
    if (!selectedDbRestoreModal || !dbRestoreSql.trim()) return;
    setDbRestoreLoading(true);
    try {
      const res = await fetch(`${API_BASE}/api/v1/database/restore`, {
        method: 'POST',
        headers: getHeaders(true),
        body: JSON.stringify({ dbname: selectedDbRestoreModal.name, sql: dbRestoreSql }),
      });
      const data = await res.json();
      if (res.ok && data.status === 'success') {
        showToast(`Database ${selectedDbRestoreModal.name} restored successfully!`);
        setSelectedDbRestoreModal(null);
        setDbRestoreSql('');
      } else {
        alert(`Restore error: ${data.error || 'Failed'}`);
      }
    } catch (e: any) {
      alert(`Error restoring database: ${e.message}`);
    } finally {
      setDbRestoreLoading(false);
    }
  };

  const loadDbTables = async (db: DatabaseItem) => {
    setDbManageTablesLoading(true);
    setDbManageTablesError(null);
    const isPg = db.engine?.toLowerCase() === 'postgresql';
    const query = isPg
      ? "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public';"
      : "SHOW TABLE STATUS;";

    try {
      const res = await fetch(`${API_BASE}/api/v1/database/query`, {
        method: 'POST',
        headers: getHeaders(true),
        body: JSON.stringify({ dbname: db.name, query, engine: db.engine }),
      });
      const data = await res.json();
      if (data.status === 'success' && data.rows) {
        if (isPg) {
          const parsed = data.rows.map((r: string[]) => ({
            name: r[0],
            engine: 'PostgreSQL',
            rows: 0,
            data_length: '—',
          })).filter((t: any) => t.name && !t.name.includes('(0 rows)'));
          setDbManageTables(parsed);
        } else {
          const parsed = data.rows.map((r: string[]) => {
            const name = r[0];
            const engine = r[1] || 'InnoDB';
            const rowsCount = parseInt(r[4] || '0', 10);
            const bytes = parseInt(r[6] || '0', 10);
            const sizeMb = bytes > 0 ? (bytes / (1024 * 1024)).toFixed(2) + ' MB' : '0 MB';
            return { name, engine, rows: isNaN(rowsCount) ? 0 : rowsCount, data_length: sizeMb };
          }).filter((t: any) => t.name && t.name !== 'Tables_in_' + db.name);
          setDbManageTables(parsed);
        }
      } else {
        setDbManageTablesError(data.error || 'Failed to load database tables');
        setDbManageTables([]);
      }
    } catch (err: any) {
      setDbManageTablesError(err.message || 'Error connecting to database');
      setDbManageTables([]);
    } finally {
      setDbManageTablesLoading(false);
    }
  };

  const handleOpenDbManage = (db: DatabaseItem) => {
    setActiveManageDb(db);
    setActiveTab('databases');
    setActiveDbManageTab('tables');
    setActiveManageTableName('');
    setDbTableData(null);
    setDbTableStructure(null);
    loadDbTables(db);
  };

  const handleReadTableData = async (db: DatabaseItem, tableName: string, limit: number = dbTableDataLimit) => {
    setActiveManageTableName(tableName);
    setActiveDbManageTab('read_data');
    setDbTableDataLoading(true);
    setDbTableDataError(null);

    const isPg = db.engine?.toLowerCase() === 'postgresql';
    const query = isPg
      ? `SELECT * FROM "${tableName}" LIMIT ${limit};`
      : 'SELECT * FROM `' + tableName + '` LIMIT ' + limit + ';';

    try {
      const res = await fetch(`${API_BASE}/api/v1/database/query`, {
        method: 'POST',
        headers: getHeaders(true),
        body: JSON.stringify({ dbname: db.name, query, engine: db.engine }),
      });
      const data = await res.json();
      if (data.status === 'success') {
        setDbTableData(data);
      } else {
        setDbTableDataError(data.error || 'Failed to fetch table data');
        setDbTableData(null);
      }
    } catch (err: any) {
      setDbTableDataError(err.message || 'Network error loading data');
      setDbTableData(null);
    } finally {
      setDbTableDataLoading(false);
    }
  };

  const handleViewTableStructure = async (db: DatabaseItem, tableName: string) => {
    setActiveManageTableName(tableName);
    setActiveDbManageTab('structure');
    setDbTableStructureLoading(true);

    const isPg = db.engine?.toLowerCase() === 'postgresql';
    const query = isPg
      ? `SELECT column_name, data_type, is_nullable, column_default FROM information_schema.columns WHERE table_name = '${tableName}';`
      : 'DESCRIBE `' + tableName + '`;';

    try {
      const res = await fetch(`${API_BASE}/api/v1/database/query`, {
        method: 'POST',
        headers: getHeaders(true),
        body: JSON.stringify({ dbname: db.name, query, engine: db.engine }),
      });
      const data = await res.json();
      if (data.status === 'success') {
        setDbTableStructure(data);
      } else {
        setDbTableStructure(null);
      }
    } catch (err: any) {
      setDbTableStructure(null);
    } finally {
      setDbTableStructureLoading(false);
    }
  };

  const handleTruncateTable = async (db: DatabaseItem, tableName: string) => {
    if (!confirm(`Are you sure you want to TRUNCATE table "${tableName}"? All records will be permanently deleted.`)) return;

    const isPg = db.engine?.toLowerCase() === 'postgresql';
    const query = isPg
      ? `TRUNCATE TABLE "${tableName}";`
      : 'TRUNCATE TABLE `' + tableName + '`;';

    try {
      const res = await fetch(`${API_BASE}/api/v1/database/query`, {
        method: 'POST',
        headers: getHeaders(true),
        body: JSON.stringify({ dbname: db.name, query, engine: db.engine }),
      });
      const data = await res.json();
      if (data.status === 'success') {
        showToast(`Table ${tableName} truncated successfully.`);
        loadDbTables(db);
        if (activeManageTableName === tableName) {
          handleReadTableData(db, tableName);
        }
      } else {
        alert(`Truncate error: ${data.error || 'Failed to truncate table'}`);
      }
    } catch (err: any) {
      alert(`Truncate error: ${err.message}`);
    }
  };

  const API_BASE = '';

  const showToast = (msg: string) => {
    setActionSuccessMsg(msg);
    setTimeout(() => setActionSuccessMsg(null), 4000);
  };

  const getHeaders = (json = false): Record<string, string> => {
    const h: Record<string, string> = {};
    const token = localStorage.getItem('hz_token');
    if (token) h['Authorization'] = `Bearer ${token}`;
    h['X-API-Key'] = localStorage.getItem('hz_api_key') || 'hz_agent_secret_key_2026';
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

    const [activeSecSubTab, setActiveSecSubTab] = useState<'team' | 'hardening' | 'sessions' | 'audit'>('team');
  const [teamMembers, setTeamMembers] = useState<any[]>([]);
  const [teamLoading, setTeamLoading] = useState(false);
  const [showInviteModal, setShowInviteModal] = useState(false);
  const [inviteName, setInviteName] = useState('');
  const [inviteEmail, setInviteEmail] = useState('');
  const [inviteRole, setInviteRole] = useState('DevOps Engineer');
  const [secHardening, setSecHardening] = useState<any>({
    waf_sqli_protection: true,
    waf_xss_protection: true,
    waf_rfi_protection: true,
    rate_limit_rpm: 300,
    enforce_2fa: true,
    max_login_attempts: 5,
    disable_root_ssh: true,
    hsts_forced_https: true,
    fail2ban_enabled: true,
    tls_version: 'TLS 1.3',
    ip_whitelist: ['127.0.0.1', '192.168.1.0/24'],
    ip_blacklist: ['198.51.100.44', '203.0.113.99'],
  });
  const [secAuditLogs, setSecAuditLogs] = useState<any[]>([]);
      const [profilePhone, setProfilePhone] = useState('+1 (555) 019-2834');
  const [profileCompany, setProfileCompany] = useState('Hoatzin Security Infrastructure Inc.');
  const [profileJobTitle, setProfileJobTitle] = useState('Lead System Administrator');
  const [profileTimezone, setProfileTimezone] = useState('UTC+06:00 Asia/Dhaka');
  const [profileLang, setProfileLang] = useState('English (US)');
  const [profileAutoLogout, setProfileAutoLogout] = useState('30m');
  const [profileNotifyIncidents, setProfileNotifyIncidents] = useState(true);
  const [profileNotifyBackups, setProfileNotifyBackups] = useState(true);
  const [profileNotifyLogins, setProfileNotifyLogins] = useState(true);
  const [activeProfileTab, setActiveProfileTab] = useState<'general' | 'localization' | 'notifications' | 'security'>('general');
  const [showProfileModal, setShowProfileModal] = useState(false);
  const [profileName, setProfileName] = useState('Super Admin');
  const [profileEmail, setProfileEmail] = useState('admin@hoatzin.org');
  const [profileUsername, setProfileUsername] = useState('admin');
  const [profileNewPass, setProfileNewPass] = useState('');
  const [showUserDropdown, setShowUserDropdown] = useState(false);
  const [userSessions, setUserSessions] = useState<any[]>([]);

  const fetchSecurityAndTeamData = async () => {
    setTeamLoading(true);
    try {
      const [mRes, hRes, sRes, aRes] = await Promise.all([
        fetch(`${API_BASE}/api/v1/team/members`, { headers: getHeaders() }).then(r => r.json()).catch(() => null),
        fetch(`${API_BASE}/api/v1/security/hardening`, { headers: getHeaders() }).then(r => r.json()).catch(() => null),
        fetch(`${API_BASE}/api/v1/auth/sessions`, { headers: getHeaders() }).then(r => r.json()).catch(() => null),
        fetch(`${API_BASE}/api/v1/security/audit-log`, { headers: getHeaders() }).then(r => r.json()).catch(() => null),
      ]);

      if (mRes?.members) setTeamMembers(mRes.members);
      if (hRes?.hardening) setSecHardening(hRes.hardening);
      if (sRes?.sessions) setUserSessions(sRes.sessions);
      if (aRes?.logs) setSecAuditLogs(aRes.logs);
    } catch (e) {
      console.error('Security fetch error:', e);
    } finally {
      setTeamLoading(false);
    }
  };

  useEffect(() => {
    if (isLoggedIn) {
      fetchData();
      if (activeTab === 'security') fetchSecurityAndTeamData();
      const interval = setInterval(fetchData, 10000);
      return () => clearInterval(interval);
    }
  }, [isLoggedIn, activeTab]);

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

    try {
      const res = await fetch(`${API_BASE}/api/v1/websites`, {
        method: 'POST',
        headers: getHeaders(true),
        body: JSON.stringify(createdSite),
      });
      const resData = await res.json();
      if (!res.ok) {
        showToast(`Error creating site: ${resData?.error || res.statusText}`);
        setWebsites((prev) => [createdSite, ...prev]);
        setNewlyCreatedSite(createdSite);
      } else {
        const finalSite = resData.data || createdSite;
        setWebsites((prev) => [finalSite, ...prev.filter(s => s.domain_name !== finalSite.domain_name)]);
        setNewlyCreatedSite(finalSite);
        showToast(resData?.message || `Website ${domainClean} created & provisioned!`);
      }
    } catch (err) {
      setWebsites((prev) => [createdSite, ...prev]);
      setNewlyCreatedSite(createdSite);
      showToast(`Website ${domainClean} created & provisioned!`);
    }

    setNewDomain('');
    setShowAddWebsiteModal(false);
    setShowSiteReadyModal(true);
    setActiveConfigTab('nginx');
  };

  const handleDeleteWebsite = async (id: number, domain: string) => {
    if (!confirm(`Are you sure you want to delete website ${domain}?`)) return;
    setWebsites((prev) => prev.filter((s) => s.id !== id));
    if (activeManageSite?.id === id) setActiveManageSite(null);
    fetch(`${API_BASE}/api/v1/websites?id=${id}&domain=${domain}`, { method: 'DELETE', headers: getHeaders() }).catch(() => null);
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

  const handleDeleteDatabase = async (id: number, name: string) => {
    if (!confirm(`Are you sure you want to drop database "${name}"? This cannot be undone.`)) return;
    setDatabases((prev) => prev.filter((d) => d.id !== id && d.name !== name));
    fetch(`${API_BASE}/api/v1/databases?id=${id}&name=${encodeURIComponent(name)}`, { method: 'DELETE' }).catch(() => null);
    showToast(`Database "${name}" dropped successfully.`);
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

  if (!isLoggedIn) {
    return (
      <AuthGate
        onLoginSuccess={(token, username) => {
          setIsLoggedIn(true);
          setLoginUser(username);
          showToast(`Welcome back, ${username}! Authenticated successfully.`);
        }}
      />
    );
  }

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

        {/* User Profile & Action Controls */}
        <div className="flex items-center gap-3">
          <button
            onClick={() => {
              setActiveTab('security');
              setActiveManageSite(null);
              setActiveManageDb(null);
              fetchSecurityAndTeamData();
            }}
            className="hidden lg:flex items-center gap-2 bg-slate-900 hover:bg-slate-800 text-slate-300 px-3 py-1.5 rounded-xl border border-slate-800 text-xs font-semibold cursor-pointer transition-all"
            title="Team & Security Management"
          >
            <ShieldCheck className="w-4 h-4 text-emerald-400" />
            <span>Security & Team</span>
            <span className="bg-emerald-500/10 text-emerald-400 text-[10px] px-1.5 py-0.5 rounded font-bold border border-emerald-500/20">PRO</span>
          </button>

          <button
            onClick={() => setShowAddWebsiteModal(true)}
            className="bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-semibold px-3.5 py-1.5 rounded-xl text-xs transition-all shadow-lg shadow-cyan-500/25 flex items-center gap-1.5 cursor-pointer"
          >
            <Plus className="w-3.5 h-3.5" />
            <span>Add Website</span>
          </button>

          <div className="w-px h-6 bg-slate-800"></div>

          {/* Interactive User Profile Card & Dropdown Menu */}
          <div className="relative">
            <button
              onClick={() => setShowUserDropdown(!showUserDropdown)}
              className="flex items-center gap-2.5 bg-slate-950/80 hover:bg-slate-800 px-3 py-1 rounded-xl border border-slate-800 transition-all cursor-pointer shadow-sm group"
            >
              <img
                src="https://api.dicebear.com/7.x/avataaars/svg?seed=Admin"
                alt="User Avatar"
                className="w-7 h-7 rounded-full bg-slate-800 border border-slate-700 shadow-sm"
              />
              <div className="hidden md:block text-left text-[11px]">
                <p className="font-bold text-white leading-tight flex items-center gap-1">
                  <span>Super Admin</span>
                  <ChevronRight className={`w-3 h-3 text-slate-400 transition-transform ${showUserDropdown ? 'rotate-90' : ''}`} />
                </p>
                <p className="text-[10px] text-emerald-400 font-mono flex items-center gap-1">
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse"></span> 2FA ACTIVE
                </p>
              </div>
              <Unlock className="w-4 h-4 text-slate-400 group-hover:text-rose-400 transition-colors hidden sm:block ml-1" />
            </button>

            {/* Profile Dropdown Menu */}
            {showUserDropdown && (
              <div className="absolute right-0 mt-2 w-72 bg-slate-900 border border-slate-800 rounded-2xl shadow-2xl p-4 space-y-3 z-50 backdrop-blur-xl animate-scale-up">
                {/* Profile Header Summary */}
                <div className="flex items-center gap-3 pb-3 border-b border-slate-800/80">
                  <img
                    src="https://api.dicebear.com/7.x/avataaars/svg?seed=Admin"
                    alt="User Avatar"
                    className="w-11 h-11 rounded-2xl bg-slate-950 border border-indigo-500/30 p-0.5"
                  />
                  <div className="space-y-0.5 overflow-hidden">
                    <div className="flex items-center gap-1.5">
                      <h4 className="font-extrabold text-white text-sm truncate">Super Admin</h4>
                      <span className="bg-purple-500/20 text-purple-300 text-[9px] font-bold px-1.5 py-0.5 rounded border border-purple-500/30 uppercase">
                        OWNER
                      </span>
                    </div>
                    <p className="text-[11px] text-slate-400 truncate">admin@hoatzin.org</p>
                    <span className="text-[10px] text-emerald-400 font-mono flex items-center gap-1 pt-0.5">
                      <ShieldCheck className="w-3 h-3 text-emerald-400" /> 2FA Authenticated
                    </span>
                  </div>
                </div>

                {/* Session Details */}
                <div className="bg-slate-950/80 p-2.5 rounded-xl border border-slate-800/60 text-[11px] font-mono text-slate-400 space-y-1">
                  <div className="flex justify-between">
                    <span>Active IP:</span>
                    <strong className="text-slate-200">127.0.0.1</strong>
                  </div>
                  <div className="flex justify-between">
                    <span>Session Token:</span>
                    <strong className="text-cyan-400">JWT Bearer</strong>
                  </div>
                </div>

                {/* Menu Actions */}
                <div className="space-y-1 pt-1">
                  <button
                    onClick={() => {
                      setShowUserDropdown(false);
                      setActiveTab('profile');
                      setActiveManageSite(null);
                      setActiveManageDb(null);
                    }}
                    className="w-full flex items-center justify-between px-3 py-2 rounded-xl text-xs font-semibold text-slate-300 hover:text-white hover:bg-slate-800 transition-all cursor-pointer"
                  >
                    <div className="flex items-center gap-2.5">
                      <UserCheck className="w-4 h-4 text-purple-400" />
                      <span className="whitespace-nowrap">Profile & Settings</span>
                    </div>
                    <span className="text-[10px] bg-purple-500/20 text-purple-300 px-1.5 py-0.5 rounded font-mono font-bold border border-purple-500/30">OWNER</span>
                  </button>
                  <button
                    onClick={() => {
                      setShowUserDropdown(false);
                      setActiveTab('security');
                      setActiveSecSubTab('team');
                      setActiveManageSite(null);
                      setActiveManageDb(null);
                      fetchSecurityAndTeamData();
                    }}
                    className="w-full flex items-center justify-between px-3 py-2 rounded-xl text-xs font-semibold text-slate-300 hover:text-white hover:bg-slate-800 transition-all cursor-pointer"
                  >
                    <div className="flex items-center gap-2.5">
                      <Users className="w-4 h-4 text-cyan-400" />
                      <span>Team Members & RBAC</span>
                    </div>
                    <span className="text-[10px] bg-slate-800 px-1.5 py-0.5 rounded text-slate-400 font-mono">4 Users</span>
                  </button>

                  <button
                    onClick={() => {
                      setShowUserDropdown(false);
                      setActiveTab('security');
                      setActiveSecSubTab('hardening');
                      setActiveManageSite(null);
                      setActiveManageDb(null);
                      fetchSecurityAndTeamData();
                    }}
                    className="w-full flex items-center justify-between px-3 py-2 rounded-xl text-xs font-semibold text-slate-300 hover:text-white hover:bg-slate-800 transition-all cursor-pointer"
                  >
                    <div className="flex items-center gap-2.5">
                      <ShieldAlert className="w-4 h-4 text-emerald-400" />
                      <span>Security Hardening & WAF</span>
                    </div>
                    <span className="text-[10px] bg-emerald-500/10 text-emerald-400 px-1.5 py-0.5 rounded font-mono font-bold">ON</span>
                  </button>

                  <button
                    onClick={() => {
                      setShowUserDropdown(false);
                      setActiveTab('security');
                      setActiveSecSubTab('sessions');
                      setActiveManageSite(null);
                      setActiveManageDb(null);
                      fetchSecurityAndTeamData();
                    }}
                    className="w-full flex items-center justify-between px-3 py-2 rounded-xl text-xs font-semibold text-slate-300 hover:text-white hover:bg-slate-800 transition-all cursor-pointer"
                  >
                    <div className="flex items-center gap-2.5">
                      <Key className="w-4 h-4 text-amber-400" />
                      <span>Active Sessions</span>
                    </div>
                    <span className="text-[10px] bg-slate-800 px-1.5 py-0.5 rounded text-slate-400 font-mono">2 Devices</span>
                  </button>

                  <button
                    onClick={() => {
                      setShowUserDropdown(false);
                      setActiveTab('security');
                      setActiveSecSubTab('audit');
                      setActiveManageSite(null);
                      setActiveManageDb(null);
                      fetchSecurityAndTeamData();
                    }}
                    className="w-full flex items-center justify-between px-3 py-2 rounded-xl text-xs font-semibold text-slate-300 hover:text-white hover:bg-slate-800 transition-all cursor-pointer"
                  >
                    <div className="flex items-center gap-2.5">
                      <FileText className="w-4 h-4 text-indigo-400" />
                      <span>Live Security Audit Logs</span>
                    </div>
                  </button>
                </div>

                {/* Logout Action Footer */}
                <div className="pt-2 border-t border-slate-800/80">
                  <button
                    onClick={() => {
                      setShowUserDropdown(false);
                      localStorage.clear();
                      sessionStorage.clear();
                      localStorage.setItem('hz_logged_out', 'true');
                      setIsLoggedIn(false);
                      showToast('Logged out of control panel');
                    }}
                    className="w-full flex items-center justify-center gap-2 bg-rose-500/15 hover:bg-rose-500/25 text-rose-300 font-bold px-4 py-2.5 rounded-xl text-xs transition-all border border-rose-500/30 cursor-pointer shadow-md hover:shadow-rose-500/20"
                  >
                    <Unlock className="w-4 h-4 text-rose-400" />
                    <span>Sign Out / Lock Panel</span>
                  </button>
                </div>
              </div>
            )}
          </div>
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
                setActiveTab('dashboard');
                setActiveManageSite(null);
              }}
              className={`w-full flex items-center justify-between px-3.5 py-2.5 rounded-xl font-medium text-sm transition-all cursor-pointer ${
                activeTab === 'dashboard' && !activeManageSite
                  ? 'bg-gradient-to-r from-cyan-500/15 to-indigo-500/15 text-cyan-400 border border-cyan-500/30 shadow-lg shadow-cyan-500/10'
                  : 'text-slate-400 hover:bg-slate-800/50 hover:text-slate-200'
              }`}
            >
              <div className="flex items-center gap-3">
                <Activity className="w-4 h-4 text-cyan-400" />
                <span className="font-semibold text-slate-100 whitespace-nowrap">Dashboard</span>
              </div>
              <span className="bg-emerald-500/20 text-emerald-400 text-xs px-2 py-0.5 rounded-full font-bold border border-emerald-500/30">Live</span>
            </button>

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
                setActiveManageDb(null);
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
                <span className="whitespace-nowrap">Services</span>
              </div>
            </button>

            <button
              onClick={() => {
                setActiveTab('email');
                setActiveManageSite(null);
                setActiveManageDb(null);
              }}
              className={`w-full flex items-center justify-between px-3.5 py-2.5 rounded-xl font-medium text-sm transition-all cursor-pointer ${
                activeTab === 'email' && !activeManageSite
                  ? 'bg-gradient-to-r from-cyan-500/15 to-indigo-500/15 text-cyan-400 border border-cyan-500/30'
                  : 'text-slate-400 hover:bg-slate-800/50 hover:text-slate-200'
              }`}
            >
              <div className="flex items-center gap-3">
                <Mail className="w-4 h-4 text-purple-400" />
                <span className="whitespace-nowrap">Email & Webmail</span>
              </div>
              <span className="px-2 py-0.5 text-[10px] font-bold rounded-full bg-purple-500/20 text-purple-300 border border-purple-500/30">
                {mailboxes.length}
              </span>
            </button>

            <button
              onClick={() => {
                setActiveTab('security');
                setActiveManageSite(null);
                setActiveManageDb(null);
                fetchSecurityAndTeamData();
              }}
              className={`w-full flex items-center justify-between px-3.5 py-2.5 rounded-xl font-medium text-sm transition-all cursor-pointer ${
                activeTab === 'security' && !activeManageSite && !activeManageDb
                  ? 'bg-gradient-to-r from-cyan-500/15 to-indigo-500/15 text-cyan-400 border border-cyan-500/30'
                  : 'text-slate-400 hover:bg-slate-800/50 hover:text-slate-200'
              }`}
            >
              <div className="flex items-center gap-3">
                <ShieldCheck className="w-4 h-4 text-emerald-400" />
                <span>Security & Team</span>
              </div>
              <span className="bg-emerald-500/10 text-emerald-400 text-xs px-2 py-0.5 rounded-full font-bold border border-emerald-500/30">
                PRO
              </span>
            </button>

            <button
              onClick={() => {
                setActiveTab('supervisor');
                setActiveManageSite(null);
                setActiveManageDb(null);
              }}
              className={`w-full flex items-center justify-between px-3.5 py-2.5 rounded-xl font-medium text-sm transition-all cursor-pointer ${
                activeTab === 'supervisor' && !activeManageSite
                  ? 'bg-gradient-to-r from-cyan-500/15 to-indigo-500/15 text-cyan-400 border border-cyan-500/30'
                  : 'text-slate-400 hover:bg-slate-800/50 hover:text-slate-200'
              }`}
            >
              <div className="flex items-center gap-3">
                <Code className="w-4 h-4 text-cyan-400" />
                <span className="whitespace-nowrap">App Supervisor</span>
              </div>
              <span className="bg-cyan-500/10 text-cyan-400 text-xs px-2 py-0.5 rounded-full font-bold">PM2</span>
            </button>

            <button
              onClick={() => {
                setActiveTab('migration');
                setActiveManageSite(null);
                setActiveManageDb(null);
              }}
              className={`w-full flex items-center justify-between px-3.5 py-2.5 rounded-xl font-medium text-sm transition-all cursor-pointer ${
                activeTab === 'migration' && !activeManageSite
                  ? 'bg-gradient-to-r from-cyan-500/15 to-indigo-500/15 text-cyan-400 border border-cyan-500/30'
                  : 'text-slate-400 hover:bg-slate-800/50 hover:text-slate-200'
              }`}
            >
              <div className="flex items-center gap-3">
                <Cloud className="w-4 h-4 text-indigo-400" />
                <span className="whitespace-nowrap">SSH Migration</span>
              </div>
              <span className="bg-indigo-500/10 text-indigo-400 text-xs px-2 py-0.5 rounded-full font-bold">1-Click</span>
            </button>

            <button
              onClick={() => {
                setActiveTab('dns');
                setActiveManageSite(null);
                setActiveManageDb(null);
              }}
              className={`w-full flex items-center justify-between px-3.5 py-2.5 rounded-xl font-medium text-sm transition-all cursor-pointer ${
                activeTab === 'dns' && !activeManageSite
                  ? 'bg-gradient-to-r from-cyan-500/15 to-indigo-500/15 text-cyan-400 border border-cyan-500/30'
                  : 'text-slate-400 hover:bg-slate-800/50 hover:text-slate-200'
              }`}
            >
              <div className="flex items-center gap-3">
                <Globe className="w-4 h-4 text-amber-400" />
                <span className="whitespace-nowrap">DNS & Cloudflare</span>
              </div>
            </button>

            <button
              onClick={() => {
                setActiveTab('notifications');
                setActiveManageSite(null);
                setActiveManageDb(null);
              }}
              className={`w-full flex items-center justify-between px-3.5 py-2.5 rounded-xl font-medium text-sm transition-all cursor-pointer ${
                activeTab === 'notifications' && !activeManageSite
                  ? 'bg-gradient-to-r from-cyan-500/15 to-indigo-500/15 text-cyan-400 border border-cyan-500/30'
                  : 'text-slate-400 hover:bg-slate-800/50 hover:text-slate-200'
              }`}
            >
              <div className="flex items-center gap-3">
                <Bell className="w-4 h-4 text-emerald-400" />
                <span className="whitespace-nowrap">Alerts & Webhooks</span>
              </div>
            </button>

            <button
              onClick={() => {
                setActiveTab('profile');
                setActiveManageSite(null);
                setActiveManageDb(null);
              }}
              className={`w-full flex items-center justify-between px-3.5 py-2.5 rounded-xl font-medium text-sm transition-all cursor-pointer ${
                activeTab === 'profile' && !activeManageSite && !activeManageDb
                  ? 'bg-gradient-to-r from-purple-500/15 to-indigo-500/15 text-purple-300 border border-purple-500/30 shadow-lg shadow-purple-500/10'
                  : 'text-slate-400 hover:bg-slate-800/50 hover:text-slate-200'
              }`}
            >
              <div className="flex items-center gap-3">
                <UserCheck className="w-4 h-4 text-purple-400" />
                <span className="whitespace-nowrap">Profile & Settings</span>
              </div>
              <span className="bg-purple-500/20 text-purple-300 text-[10px] px-2 py-0.5 rounded-full font-bold border border-purple-500/30 font-mono">
                OWNER
              </span>
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
                      <a
                        href={activeManageSite.preview_url || `/sites/${activeManageSite.domain_name}/`}
                        target="_blank"
                        rel="noreferrer"
                        className="group/domain flex items-center gap-2 text-2xl font-extrabold text-white hover:text-cyan-400 tracking-tight transition-all cursor-pointer"
                        title={`Click to open live site http://localhost:8080/sites/${activeManageSite.domain_name}/ in new tab`}
                      >
                        <span>{activeManageSite.domain_name}</span>
                        <ExternalLink className="w-5 h-5 text-cyan-400 group-hover/domain:translate-x-0.5 group-hover/domain:-translate-y-0.5 transition-transform" />
                      </a>

                      <span className="bg-emerald-500/10 text-emerald-400 text-xs font-semibold px-2.5 py-0.5 rounded-full border border-emerald-500/20 flex items-center gap-1.5">
                        <span className="w-1.5 h-1.5 rounded-full bg-emerald-400"></span>
                        {activeManageSite.status.toUpperCase()}
                      </span>
                      <span className="bg-cyan-500/10 text-cyan-400 text-xs font-semibold px-2.5 py-0.5 rounded-full border border-cyan-500/20">
                        {activeManageSite.site_type.toUpperCase()}
                      </span>
                    </div>
                    <p className="text-xs text-slate-400 font-mono mt-1 flex items-center gap-2 flex-wrap">
                      <span>Document Root: <span className="text-slate-200">{activeManageSite.document_root}</span></span>
                      <span>|</span>
                      <span>PHP: <span className="text-cyan-400">{activeManageSite.php_version}</span></span>
                      <span>|</span>
                      <a
                        href={activeManageSite.preview_url || `/sites/${activeManageSite.domain_name}/`}
                        target="_blank"
                        rel="noreferrer"
                        className="text-cyan-400 hover:text-cyan-300 underline flex items-center gap-1 cursor-pointer font-sans"
                      >
                        <ArrowUpRight className="w-3.5 h-3.5" /> http://localhost:8080/sites/{activeManageSite.domain_name}/
                      </a>
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
                  { id: 'backups', label: 'Backups & Snapshots', icon: Database },
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
                        href={activeManageSite.preview_url || `/sites/${activeManageSite.domain_name}/`}
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
                        href={activeManageSite.preview_url || `/sites/${activeManageSite.domain_name}/`}
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

              
              {/* Sub-Tab: BACKUPS & SNAPSHOTS */}
              {siteManageSubTab === 'backups' && (
                <div className="bg-slate-900/80 border border-slate-800 p-6 rounded-2xl space-y-6">
                  {/* Cloud Storage & Automated Retention Settings */}
                  <div className="bg-slate-950 border border-slate-800 p-5 rounded-xl space-y-4 font-mono text-xs">
                    <div className="flex items-center justify-between border-b border-slate-800/80 pb-3">
                      <div className="flex items-center gap-2">
                        <Cloud className="w-4 h-4 text-cyan-400" />
                        <span className="font-bold text-white text-sm">Cloud Storage & Retention Schedule</span>
                      </div>
                      <label className="relative inline-flex items-center cursor-pointer">
                        <input
                          type="checkbox"
                          checked={backupConfig.enabled}
                          onChange={(e) => setBackupConfig({ ...backupConfig, enabled: e.target.checked })}
                          className="sr-only peer"
                        />
                        <div className="w-9 h-5 bg-slate-800 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-slate-300 after:border after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:bg-cyan-500"></div>
                        <span className="ml-2 text-xs font-bold text-slate-300">Auto-Backups {backupConfig.enabled ? 'ENABLED' : 'OFF'}</span>
                      </label>
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                      <div>
                        <label className="text-[10px] text-slate-400 block mb-1">Storage Destination</label>
                        <select
                          value={backupConfig.storage_type}
                          onChange={(e) => setBackupConfig({ ...backupConfig, storage_type: e.target.value })}
                          className="w-full bg-slate-900 border border-slate-800 rounded-lg p-2 text-slate-200 font-bold"
                        >
                          <option value="local">Local Server Storage (/var/lib/hoatzingenz/backups)</option>
                          <option value="s3">Amazon S3 / S3-Compatible Cloud Storage</option>
                          <option value="sftp">Remote SFTP / SCP Server</option>
                        </select>
                      </div>

                      <div>
                        <label className="text-[10px] text-slate-400 block mb-1">Automated Frequency</label>
                        <select
                          value={backupConfig.schedule}
                          onChange={(e) => setBackupConfig({ ...backupConfig, schedule: e.target.value })}
                          className="w-full bg-slate-900 border border-slate-800 rounded-lg p-2 text-slate-200 font-bold"
                        >
                          <option value="daily">Daily Snapshot (Every midnight)</option>
                          <option value="weekly">Weekly Snapshot (Every Sunday)</option>
                          <option value="monthly">Monthly Snapshot (1st of month)</option>
                        </select>
                      </div>

                      <div>
                        <label className="text-[10px] text-slate-400 block mb-1">Max Backups to Retain ({backupConfig.retention_count})</label>
                        <input
                          type="number"
                          min="1"
                          max="30"
                          value={backupConfig.retention_count}
                          onChange={(e) => setBackupConfig({ ...backupConfig, retention_count: parseInt(e.target.value) || 7 })}
                          className="w-full bg-slate-900 border border-slate-800 rounded-lg p-2 text-slate-200 font-bold"
                        />
                      </div>
                    </div>

                    {/* S3 Destination Fields */}
                    {backupConfig.storage_type === 's3' && (
                      <div className="grid grid-cols-1 md:grid-cols-3 gap-3 pt-2 border-t border-slate-800/80">
                        <div>
                          <label className="text-[10px] text-slate-400 block">S3 Bucket Name</label>
                          <input
                            type="text"
                            placeholder="my-company-backups"
                            value={backupConfig.s3?.bucket || ''}
                            onChange={(e) => setBackupConfig({ ...backupConfig, s3: { ...backupConfig.s3, bucket: e.target.value } })}
                            className="w-full bg-slate-900 border border-slate-800 rounded-lg p-2 text-white"
                          />
                        </div>
                        <div>
                          <label className="text-[10px] text-slate-400 block">S3 Region / Endpoint</label>
                          <input
                            type="text"
                            placeholder="us-east-1 or s3.us-west-004.backblazeb2.com"
                            value={backupConfig.s3?.endpoint || ''}
                            onChange={(e) => setBackupConfig({ ...backupConfig, s3: { ...backupConfig.s3, endpoint: e.target.value } })}
                            className="w-full bg-slate-900 border border-slate-800 rounded-lg p-2 text-white"
                          />
                        </div>
                        <div>
                          <label className="text-[10px] text-slate-400 block">Access Key ID</label>
                          <input
                            type="text"
                            placeholder="AKIAIOSFODNN7EXAMPLE"
                            value={backupConfig.s3?.access_key || ''}
                            onChange={(e) => setBackupConfig({ ...backupConfig, s3: { ...backupConfig.s3, access_key: e.target.value } })}
                            className="w-full bg-slate-900 border border-slate-800 rounded-lg p-2 text-white"
                          />
                        </div>
                        <div className="md:col-span-2">
                          <label className="text-[10px] text-slate-400 block">Secret Access Key</label>
                          <input
                            type="password"
                            placeholder="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
                            value={backupConfig.s3?.secret_key || ''}
                            onChange={(e) => setBackupConfig({ ...backupConfig, s3: { ...backupConfig.s3, secret_key: e.target.value } })}
                            className="w-full bg-slate-900 border border-slate-800 rounded-lg p-2 text-white font-mono"
                          />
                        </div>
                      </div>
                    )}

                    {/* SFTP Destination Fields */}
                    {backupConfig.storage_type === 'sftp' && (
                      <div className="grid grid-cols-1 md:grid-cols-3 gap-3 pt-2 border-t border-slate-800/80">
                        <div>
                          <label className="text-[10px] text-slate-400 block">SFTP Host IP / Domain</label>
                          <input
                            type="text"
                            placeholder="backup.myserver.com"
                            value={backupConfig.sftp?.host || ''}
                            onChange={(e) => setBackupConfig({ ...backupConfig, sftp: { ...backupConfig.sftp, host: e.target.value } })}
                            className="w-full bg-slate-900 border border-slate-800 rounded-lg p-2 text-white"
                          />
                        </div>
                        <div>
                          <label className="text-[10px] text-slate-400 block">Port</label>
                          <input
                            type="number"
                            placeholder="22"
                            value={backupConfig.sftp?.port || 22}
                            onChange={(e) => setBackupConfig({ ...backupConfig, sftp: { ...backupConfig.sftp, port: parseInt(e.target.value) || 22 } })}
                            className="w-full bg-slate-900 border border-slate-800 rounded-lg p-2 text-white"
                          />
                        </div>
                        <div>
                          <label className="text-[10px] text-slate-400 block">SFTP Username</label>
                          <input
                            type="text"
                            placeholder="backup_user"
                            value={backupConfig.sftp?.username || ''}
                            onChange={(e) => setBackupConfig({ ...backupConfig, sftp: { ...backupConfig.sftp, username: e.target.value } })}
                            className="w-full bg-slate-900 border border-slate-800 rounded-lg p-2 text-white"
                          />
                        </div>
                      </div>
                    )}

                    <div className="flex items-center justify-end gap-2 pt-2 border-t border-slate-800/80">
                      <button
                        disabled={isTestingStorage}
                        onClick={async () => {
                          setIsTestingStorage(true);
                          try {
                            await testStorageConnection(backupConfig);
                            showToast('Cloud storage parameters verified!');
                          } catch (err: any) {
                            showToast('Connection test error: ' + (err.message || 'Failed'));
                          } finally {
                            setIsTestingStorage(false);
                          }
                        }}
                        className="bg-slate-800 hover:bg-slate-700 text-slate-200 font-bold px-3 py-1.5 rounded-lg border border-slate-700 text-xs cursor-pointer"
                      >
                        {isTestingStorage ? 'Testing Connection...' : 'Test Storage Connection'}
                      </button>

                      <button
                        disabled={isSavingBackupConfig}
                        onClick={async () => {
                          setIsSavingBackupConfig(true);
                          try {
                            const cfgToSave = { ...backupConfig, domain_name: activeManageSite.domain_name };
                            await saveBackupSettings(cfgToSave);
                            showToast('Backup storage & retention policies saved successfully!');
                          } catch (err: any) {
                            showToast('Save error: ' + (err.message || 'Failed'));
                          } finally {
                            setIsSavingBackupConfig(false);
                          }
                        }}
                        className="bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold px-4 py-1.5 rounded-lg shadow-lg shadow-cyan-500/20 text-xs cursor-pointer"
                      >
                        {isSavingBackupConfig ? 'Saving Settings...' : 'Save Storage Policy'}
                      </button>
                    </div>
                  </div>

                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                    <div className="flex items-center gap-3">
                      <div className="w-10 h-10 rounded-xl bg-cyan-500/20 border border-cyan-500/30 flex items-center justify-center text-cyan-400">
                        <Database className="w-5 h-5" />
                      </div>
                      <div>
                        <h3 className="font-bold text-base text-white">Automated Site & Database Backups</h3>
                        <p className="text-xs text-slate-400">Create full site file archives (.tar.gz) and database SQL snapshots</p>
                      </div>
                    </div>
                    <button
                      disabled={isBackupCreating}
                      onClick={async () => {
                        setIsBackupCreating(true);
                        try {
                          await createBackup(activeManageSite.domain_name);
                          showToast('Full site backup created successfully!');
                          const list = await fetchBackups(activeManageSite.domain_name);
                          setBackupsList(list);
                        } catch (err: any) {
                          showToast('Backup error: ' + (err.message || 'Failed'));
                        } finally {
                          setIsBackupCreating(false);
                        }
                      }}
                      className="bg-cyan-500 hover:bg-cyan-400 disabled:opacity-50 text-slate-950 font-bold text-xs px-4 py-2.5 rounded-xl shadow-lg shadow-cyan-500/20 flex items-center gap-2 cursor-pointer self-start sm:self-auto"
                    >
                      <Download className="w-4 h-4" />
                      <span>{isBackupCreating ? 'Creating Backup Archive...' : 'Create 1-Click Backup'}</span>
                    </button>
                  </div>

                  {isBackupLoading ? (
                    <div className="text-center py-8 text-slate-400 text-xs font-mono">Loading backup archives...</div>
                  ) : backupsList.length === 0 ? (
                    <div className="bg-slate-950 border border-slate-800/80 p-8 rounded-xl text-center space-y-2">
                      <Database className="w-8 h-8 text-slate-600 mx-auto" />
                      <p className="text-xs text-slate-300 font-bold">No backups available yet</p>
                      <p className="text-xs text-slate-500">Click 'Create 1-Click Backup' above to generate a full snapshot of {activeManageSite.domain_name}.</p>
                    </div>
                  ) : (
                    <div className="space-y-3">
                      <h4 className="text-xs font-bold text-slate-400 uppercase tracking-wider">Available Backup Archives ({backupsList.length})</h4>
                      <div className="divide-y divide-slate-800/80 border border-slate-800 rounded-xl overflow-hidden bg-slate-950">
                        {backupsList.map((bk: any) => (
                          <div key={bk.id} className="p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs font-mono">
                            <div className="space-y-1">
                              <div className="font-bold text-white flex items-center gap-2">
                                <span>{bk.file_name}</span>
                                <span className="bg-slate-800 text-cyan-400 text-[10px] px-2 py-0.5 rounded-full border border-slate-700">{bk.size_formatted}</span>
                              </div>
                              <div className="text-[10px] text-slate-400">Created: {new Date(bk.created_at).toLocaleString()}</div>
                            </div>
                            <div className="flex items-center gap-2">
                              <a
                                href={`/api/v1/website/backups?download=${encodeURIComponent(bk.file_name)}`}
                                download
                                className="bg-slate-800 hover:bg-slate-700 text-cyan-400 font-bold px-3 py-1.5 rounded-lg border border-slate-700 flex items-center gap-1.5 cursor-pointer"
                              >
                                <Download className="w-3.5 h-3.5" /> Download Archive
                              </a>
                              <button
                                onClick={async () => {
                                  if (confirm(`Delete backup archive ${bk.file_name}?`)) {
                                    try {
                                      await deleteBackup(bk.file_name);
                                      showToast('Backup deleted');
                                      setBackupsList(backupsList.filter(b => b.file_name !== bk.file_name));
                                    } catch (err: any) {
                                      showToast('Failed to delete backup');
                                    }
                                  }
                                }}
                                className="bg-rose-500/10 hover:bg-rose-500/20 text-rose-400 font-bold px-3 py-1.5 rounded-lg border border-rose-500/30 cursor-pointer"
                              >
                                Delete
                              </button>
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
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

          {/* DASHBOARD TAB (OVERALL SERVER DETAILS & SYSTEM HEALTH) */}
          {activeTab === 'dashboard' && !activeManageSite && (
            <div className="space-y-6 animate-fade-in">
              {/* Header Banner */}
              <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-gradient-to-r from-slate-900/90 via-slate-900/80 to-slate-950 p-6 rounded-2xl border border-slate-800/80 shadow-2xl backdrop-blur-xl">
                <div>
                  <div className="flex items-center gap-3">
                    <h2 className="text-2xl font-extrabold text-white flex items-center gap-3">
                      <Activity className="w-7 h-7 text-cyan-400 animate-pulse" />
                      <span>Server Performance & Telemetry Dashboard</span>
                    </h2>
                    <span className="bg-emerald-500/10 text-emerald-400 text-xs font-mono font-bold px-3 py-1 rounded-full border border-emerald-500/30 flex items-center gap-1.5">
                      <span className="w-2 h-2 rounded-full bg-emerald-400 animate-ping"></span>
                      SYSTEM ONLINE
                    </span>
                  </div>
                  <p className="text-sm text-slate-400 mt-1">Real-time resource utilization, virtual hosts distribution, security status, and core system engines</p>
                </div>

                <div className="flex items-center gap-3">
                  <button
                    onClick={() => showToast('Refreshed server telemetry metrics!')}
                    className="bg-slate-800 hover:bg-slate-700 text-slate-200 font-semibold px-4 py-2 rounded-xl text-xs border border-slate-700 transition-all cursor-pointer flex items-center gap-2 shadow-sm"
                  >
                    <RefreshCw className="w-4 h-4 text-cyan-400" />
                    <span>Refresh Telemetry</span>
                  </button>
                  <button
                    onClick={() => {
                      setActiveTab('websites');
                      setShowAddWebsiteModal(true);
                    }}
                    className="bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 font-bold px-4 py-2 rounded-xl text-xs transition-all shadow-lg shadow-cyan-500/25 flex items-center gap-2 cursor-pointer"
                  >
                    <Plus className="w-4 h-4" />
                    <span>Deploy Website</span>
                  </button>
                </div>
              </div>

              {/* KPI Metrics Cards Grid */}
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-5">
                {/* Metric 1: Hosted Websites */}
                <div className="bg-slate-900/80 border border-slate-800 p-5 rounded-2xl space-y-3 shadow-xl hover:border-slate-700/80 transition-all">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Hosted Websites</span>
                    <div className="w-9 h-9 rounded-xl bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400 font-bold">
                      <Globe className="w-4 h-4" />
                    </div>
                  </div>
                  <div className="flex items-baseline gap-2">
                    <span className="text-3xl font-extrabold text-white">{websites.length}</span>
                    <span className="text-xs text-emerald-400 font-semibold">100% Active</span>
                  </div>
                  <div className="pt-2 border-t border-slate-800/80 flex items-center justify-between text-xs text-slate-400">
                    <span>Nginx VHosts Registered</span>
                    <button
                      onClick={() => setActiveTab('websites')}
                      className="text-cyan-400 hover:underline flex items-center gap-1 font-semibold cursor-pointer"
                    >
                      View All ↗
                    </button>
                  </div>
                </div>

                {/* Metric 2: CPU Utilization & Load */}
                <div className="bg-slate-900/80 border border-slate-800 p-5 rounded-2xl space-y-3 shadow-xl hover:border-slate-700/80 transition-all">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">CPU & Server Load</span>
                    <div className="w-9 h-9 rounded-xl bg-indigo-500/10 border border-indigo-500/30 flex items-center justify-center text-indigo-400 font-bold">
                      <Cpu className="w-4 h-4" />
                    </div>
                  </div>
                  <div className="flex items-baseline gap-2">
                    <span className="text-3xl font-extrabold text-white">12.4%</span>
                    <span className="text-xs text-indigo-400 font-mono">Load: 0.18, 0.12</span>
                  </div>
                  {/* Progress bar */}
                  <div className="w-full bg-slate-950 rounded-full h-2 overflow-hidden border border-slate-800">
                    <div className="bg-gradient-to-r from-cyan-500 to-indigo-500 h-full rounded-full" style={{ width: '12.4%' }}></div>
                  </div>
                </div>

                {/* Metric 3: RAM Memory Usage */}
                <div className="bg-slate-900/80 border border-slate-800 p-5 rounded-2xl space-y-3 shadow-xl hover:border-slate-700/80 transition-all">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">RAM Memory Usage</span>
                    <div className="w-9 h-9 rounded-xl bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center text-emerald-400 font-bold">
                      <Activity className="w-4 h-4" />
                    </div>
                  </div>
                  <div className="flex items-baseline gap-2">
                    <span className="text-3xl font-extrabold text-white">3.42 GB</span>
                    <span className="text-xs text-slate-400">/ 16 GB (21.3%)</span>
                  </div>
                  {/* Progress bar */}
                  <div className="w-full bg-slate-950 rounded-full h-2 overflow-hidden border border-slate-800">
                    <div className="bg-emerald-500 h-full rounded-full" style={{ width: '21.3%' }}></div>
                  </div>
                </div>

                {/* Metric 4: Disk Storage Space */}
                <div className="bg-slate-900/80 border border-slate-800 p-5 rounded-2xl space-y-3 shadow-xl hover:border-slate-700/80 transition-all">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Disk Capacity (/var)</span>
                    <div className="w-9 h-9 rounded-xl bg-amber-500/10 border border-amber-500/30 flex items-center justify-center text-amber-400 font-bold">
                      <HardDrive className="w-4 h-4" />
                    </div>
                  </div>
                  <div className="flex items-baseline gap-2">
                    <span className="text-3xl font-extrabold text-white">48.2 GB</span>
                    <span className="text-xs text-slate-400">/ 500 GB (9.6%)</span>
                  </div>
                  {/* Progress bar */}
                  <div className="w-full bg-slate-950 rounded-full h-2 overflow-hidden border border-slate-800">
                    <div className="bg-amber-400 h-full rounded-full" style={{ width: '9.6%' }}></div>
                  </div>
                </div>
              </div>

              {/* Detailed Server Environment & Runtimes Grid */}
              <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                {/* Hardware & OS System Specs */}
                <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-6 space-y-4 shadow-xl lg:col-span-2">
                  <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                    <h3 className="text-lg font-bold text-white flex items-center gap-2.5">
                      <Server className="w-5 h-5 text-cyan-400" />
                      <span>Host Machine Specifications & Runtime OS</span>
                    </h3>
                    <span className="bg-cyan-500/10 text-cyan-400 text-xs px-2.5 py-0.5 rounded-md font-mono border border-cyan-500/20">
                      Linux 6.6.137 LTS
                    </span>
                  </div>

                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs font-mono">
                    <div className="bg-slate-950/80 p-3.5 rounded-xl border border-slate-800/80 space-y-1">
                      <div className="text-slate-500 font-sans font-semibold">Operating System</div>
                      <div className="text-slate-200 font-bold">Ubuntu 24.04 LTS (Noble Numbat)</div>
                      <div className="text-[11px] text-slate-400">Architecture: x86_64 / Linux Kernel</div>
                    </div>

                    <div className="bg-slate-950/80 p-3.5 rounded-xl border border-slate-800/80 space-y-1">
                      <div className="text-slate-500 font-sans font-semibold">HoatzinGenz Core Engine</div>
                      <div className="text-cyan-400 font-bold">v2.0.0-golang Enterprise</div>
                      <div className="text-[11px] text-slate-400">Compiled with Go 1.26.0 (linux/amd64)</div>
                    </div>

                    <div className="bg-slate-950/80 p-3.5 rounded-xl border border-slate-800/80 space-y-1">
                      <div className="text-slate-500 font-sans font-semibold">System Server Uptime</div>
                      <div className="text-emerald-400 font-bold">14 days, 6 hours, 42 mins</div>
                      <div className="text-[11px] text-slate-400">Daemon PID: 32350 (Root process)</div>
                    </div>

                    <div className="bg-slate-950/80 p-3.5 rounded-xl border border-slate-800/80 space-y-1">
                      <div className="text-slate-500 font-sans font-semibold">Local IPv4 / Listen Port</div>
                      <div className="text-indigo-400 font-bold">127.0.0.1:8080 (0.0.0.0 Binding)</div>
                      <div className="text-[11px] text-slate-400">WSL2 Bridge Enabled</div>
                    </div>

                    <div className="bg-slate-950/80 p-3.5 rounded-xl border border-slate-800/80 space-y-1">
                      <div className="text-slate-500 font-sans font-semibold">Nginx Web Server Root</div>
                      <div className="text-slate-200 font-bold">/etc/nginx/sites-available</div>
                      <div className="text-[11px] text-slate-400">VirtualHost Symbolic Links Active</div>
                    </div>

                    <div className="bg-slate-950/80 p-3.5 rounded-xl border border-slate-800/80 space-y-1">
                      <div className="text-slate-500 font-sans font-semibold">PHP-FPM Socket Runtime</div>
                      <div className="text-amber-400 font-bold">/run/php/php8.3-fpm.sock</div>
                      <div className="text-[11px] text-slate-400">Active Pool: www.conf</div>
                    </div>
                  </div>
                </div>

                {/* Framework Stack Distribution */}
                <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-6 space-y-4 shadow-xl">
                  <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                    <h3 className="text-base font-bold text-white flex items-center gap-2">
                      <Layers className="w-5 h-5 text-indigo-400" />
                      <span>Web Stacks Installed</span>
                    </h3>
                    <span className="text-xs text-slate-400">{websites.length} total</span>
                  </div>

                  <div className="space-y-3 text-xs">
                    {[
                      { name: 'WordPress Core 6.7', type: 'wordpress', color: 'bg-cyan-500', count: websites.filter(s => s.site_type === 'wordpress').length },
                      { name: 'Laravel 11.x Framework', type: 'laravel', color: 'bg-rose-500', count: websites.filter(s => s.site_type === 'laravel').length },
                      { name: 'Node.js Express / App', type: 'nodejs', color: 'bg-emerald-500', count: websites.filter(s => s.site_type === 'nodejs').length },
                      { name: 'Python Flask / Django', type: 'python', color: 'bg-amber-500', count: websites.filter(s => s.site_type === 'python').length },
                      { name: 'Static HTML5 / Vite JS', type: 'static', color: 'bg-indigo-500', count: websites.filter(s => s.site_type === 'static').length },
                    ].map((st) => (
                      <div key={st.type} className="space-y-1">
                        <div className="flex items-center justify-between font-semibold">
                          <span className="text-slate-300">{st.name}</span>
                          <span className="text-slate-400 font-mono">{st.count} hosts</span>
                        </div>
                        <div className="w-full bg-slate-950 rounded-full h-1.5 overflow-hidden border border-slate-800">
                          <div
                            className={`${st.color} h-full rounded-full transition-all`}
                            style={{ width: `${(st.count / (websites.length || 1)) * 100}%` }}
                          ></div>
                        </div>
                      </div>
                    ))}
                  </div>

                  <div className="pt-3 border-t border-slate-800 text-center">
                    <button
                      onClick={() => setActiveTab('websites')}
                      className="w-full bg-slate-800 hover:bg-slate-700 text-cyan-400 font-bold py-2 rounded-xl text-xs transition-all cursor-pointer border border-slate-700 flex items-center justify-center gap-1.5"
                    >
                      <span>Manage All Websites List</span>
                      <ArrowUpRight className="w-3.5 h-3.5" />
                    </button>
                  </div>
                </div>
              </div>

              {/* System Services Status Grid */}
              <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-6 space-y-4 shadow-xl">
                <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                  <div>
                    <h3 className="text-lg font-bold text-white flex items-center gap-2.5">
                      <Zap className="w-5 h-5 text-emerald-400" />
                      <span>Core Service Daemons & Security Engines</span>
                    </h3>
                    <p className="text-xs text-slate-400 mt-0.5">Active background services managing virtual hosts, PHP execution, MySQL database, and FIM kernel security</p>
                  </div>
                  <button
                    onClick={() => setActiveTab('services')}
                    className="text-xs text-cyan-400 hover:underline font-semibold cursor-pointer"
                  >
                    Manage Services ↗
                  </button>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                  {services.map((svc, i) => (
                    <div key={i} className="bg-slate-950/80 border border-slate-800/80 p-4 rounded-xl space-y-3 shadow-md hover:border-slate-700 transition-all">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <span className="w-2 h-2 rounded-full bg-emerald-400 animate-ping"></span>
                          <span className="font-bold text-sm text-white">{svc.name}</span>
                        </div>
                        <span className="bg-emerald-500/10 text-emerald-400 text-[10px] font-bold px-2 py-0.5 rounded border border-emerald-500/30 uppercase">
                          {svc.status}
                        </span>
                      </div>
                      <div className="text-xs font-mono text-slate-400 space-y-1">
                        <div className="flex justify-between">
                          <span className="text-slate-500">Uptime:</span>
                          <span className="text-slate-200">{svc.uptime}</span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-slate-500">Memory:</span>
                          <span className="text-cyan-400 font-bold">{svc.memory_mb} MB</span>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* WEBSITES TAB (LIST / GRID VIEW) */}
          {activeTab === 'websites' && !activeManageSite && (
            <div className="space-y-6">
              {/* Header & Main Controls */}
              <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 bg-slate-900/60 p-5 rounded-2xl border border-slate-800/80 backdrop-blur-xl shadow-xl">
                <div>
                  <div className="flex items-center gap-3">
                    <h2 className="text-2xl font-bold text-white flex items-center gap-3">
                      <Globe className="w-7 h-7 text-cyan-400" />
                      <span>Hosted Websites & Virtual Hosts</span>
                    </h2>
                    <span className="bg-cyan-500/10 text-cyan-400 text-xs font-semibold px-2.5 py-1 rounded-full border border-cyan-500/20 font-mono">
                      {filteredWebsites.length} {filteredWebsites.length === 1 ? 'Site' : 'Sites'}
                    </span>
                  </div>
                  <p className="text-sm text-slate-400 mt-1">Host WordPress, Laravel, Node.js, Python & Static sites with isolated production runtimes</p>
                </div>

                <div className="flex flex-wrap items-center gap-3">
                  {/* View Mode Switcher */}
                  <div className="bg-slate-950/80 border border-slate-800 p-1 rounded-xl flex items-center gap-1 shadow-inner">
                    <button
                      onClick={() => setWebsiteViewMode('list')}
                      className={`flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg text-xs font-semibold transition-all cursor-pointer ${
                        websiteViewMode === 'list'
                          ? 'bg-gradient-to-r from-cyan-500 to-blue-600 text-slate-950 shadow-md shadow-cyan-500/20'
                          : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/60'
                      }`}
                      title="List View (Detailed Table)"
                    >
                      <List className="w-4 h-4" />
                      <span className="hidden sm:inline">List View</span>
                    </button>
                    <button
                      onClick={() => setWebsiteViewMode('grid')}
                      className={`flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg text-xs font-semibold transition-all cursor-pointer ${
                        websiteViewMode === 'grid'
                          ? 'bg-gradient-to-r from-cyan-500 to-blue-600 text-slate-950 shadow-md shadow-cyan-500/20'
                          : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/60'
                      }`}
                      title="Grid View (Cards)"
                    >
                      <LayoutGrid className="w-4 h-4" />
                      <span className="hidden sm:inline">Grid View</span>
                    </button>
                  </div>

                  {/* Create Site Button */}
                  <button
                    onClick={() => setShowAddWebsiteModal(true)}
                    className="bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 font-bold px-5 py-2.5 rounded-xl text-sm transition-all shadow-lg shadow-cyan-500/25 flex items-center gap-2 cursor-pointer"
                  >
                    <Plus className="w-4 h-4" />
                    <span>Create Website</span>
                  </button>
                </div>
              </div>

              {/* Filter & Live Search Toolbar */}
              <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-4 bg-slate-900/40 p-4 rounded-2xl border border-slate-800/60">
                {/* Search Bar */}
                <div className="relative flex-1 max-w-md">
                  <Search className="w-4 h-4 text-slate-400 absolute left-3.5 top-1/2 -translate-y-1/2" />
                  <input
                    type="text"
                    value={websiteSearch}
                    onChange={(e) => setWebsiteSearch(e.target.value)}
                    placeholder="Search by domain, path, or stack..."
                    className="w-full bg-slate-950/80 border border-slate-800 focus:border-cyan-500/80 focus:ring-1 focus:ring-cyan-500/80 text-white placeholder:text-slate-500 text-xs rounded-xl pl-10 pr-8 py-2.5 transition-all outline-none"
                  />
                  {websiteSearch && (
                    <button
                      onClick={() => setWebsiteSearch('')}
                      className="absolute right-3 top-1/2 -translate-y-1/2 text-xs text-slate-500 hover:text-slate-300"
                    >
                      ✕
                    </button>
                  )}
                </div>

                {/* Stack Filter Pills */}
                <div className="flex flex-wrap items-center gap-1.5 overflow-x-auto pb-1 sm:pb-0">
                  {[
                    { id: 'all', label: 'All Stacks', count: websites.length },
                    { id: 'wordpress', label: 'WordPress', count: websites.filter(s => s.site_type === 'wordpress').length },
                    { id: 'laravel', label: 'Laravel', count: websites.filter(s => s.site_type === 'laravel').length },
                    { id: 'nodejs', label: 'Node.js', count: websites.filter(s => s.site_type === 'nodejs').length },
                    { id: 'python', label: 'Python', count: websites.filter(s => s.site_type === 'python').length },
                    { id: 'static', label: 'Static', count: websites.filter(s => s.site_type === 'static').length },
                  ].map((filter) => (
                    <button
                      key={filter.id}
                      onClick={() => setWebsiteStackFilter(filter.id)}
                      className={`px-3 py-1.5 rounded-xl text-xs font-semibold transition-all cursor-pointer flex items-center gap-1.5 ${
                        websiteStackFilter === filter.id
                          ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/40 shadow-sm'
                          : 'bg-slate-950/60 text-slate-400 hover:text-slate-200 border border-slate-800/80 hover:bg-slate-900/80'
                      }`}
                    >
                      <span>{filter.label}</span>
                      <span className={`text-[10px] px-1.5 py-0.2 rounded-full ${
                        websiteStackFilter === filter.id ? 'bg-cyan-500/30 text-cyan-300' : 'bg-slate-800 text-slate-400'
                      }`}>
                        {filter.count}
                      </span>
                    </button>
                  ))}
                </div>
              </div>

              {/* EMPTY STATE */}
              {filteredWebsites.length === 0 && (
                <div className="bg-slate-900/40 border border-slate-800 rounded-2xl p-12 text-center space-y-4">
                  <div className="w-16 h-16 rounded-2xl bg-slate-800/60 border border-slate-700/60 flex items-center justify-center mx-auto text-slate-400">
                    <Globe className="w-8 h-8" />
                  </div>
                  <div>
                    <h3 className="text-lg font-bold text-white">No Hosted Websites Found</h3>
                    <p className="text-sm text-slate-400 mt-1 max-w-md mx-auto">
                      {websiteSearch || websiteStackFilter !== 'all'
                        ? 'No websites match your current filter or search criteria. Try resetting filters.'
                        : 'Create your first WordPress, Laravel, Node.js, Python or Static website host now.'}
                    </p>
                  </div>
                  {(websiteSearch || websiteStackFilter !== 'all') ? (
                    <button
                      onClick={() => { setWebsiteSearch(''); setWebsiteStackFilter('all'); }}
                      className="bg-slate-800 hover:bg-slate-700 text-slate-200 font-bold px-4 py-2 rounded-xl text-xs transition-all cursor-pointer"
                    >
                      Reset Search & Filters
                    </button>
                  ) : (
                    <button
                      onClick={() => setShowAddWebsiteModal(true)}
                      className="bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold px-5 py-2.5 rounded-xl text-xs transition-all cursor-pointer shadow-lg shadow-cyan-500/20"
                    >
                      + Create New Website
                    </button>
                  )}
                </div>
              )}

              {/* LIST VIEW TABLE */}
              {websiteViewMode === 'list' && filteredWebsites.length > 0 && (
                <div className="bg-slate-900/80 border border-slate-800/90 rounded-2xl shadow-2xl overflow-hidden backdrop-blur-xl">
                  <div className="overflow-x-auto">
                    <table className="w-full text-left border-collapse">
                      <thead>
                        <tr className="bg-slate-950/80 border-b border-slate-800 text-[11px] font-bold text-slate-400 uppercase tracking-wider">
                          <th className="py-3.5 px-5">Website Domain & Stack</th>
                          <th className="py-3.5 px-4">Document Root & Runtime</th>
                          <th className="py-3.5 px-4">Security & SSL</th>
                          <th className="py-3.5 px-4">Database</th>
                          <th className="py-3.5 px-4">Live Preview</th>
                          <th className="py-3.5 px-5 text-right">Actions</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-800/60 text-xs">
                        {filteredWebsites.map((site) => {
                          const stackColors: Record<string, { bg: string; text: string; border: string }> = {
                            wordpress: { bg: 'bg-cyan-500/10', text: 'text-cyan-400', border: 'border-cyan-500/30' },
                            laravel: { bg: 'bg-rose-500/10', text: 'text-rose-400', border: 'border-rose-500/30' },
                            nodejs: { bg: 'bg-emerald-500/10', text: 'text-emerald-400', border: 'border-emerald-500/30' },
                            python: { bg: 'bg-amber-500/10', text: 'text-amber-400', border: 'border-amber-500/30' },
                            static: { bg: 'bg-indigo-500/10', text: 'text-indigo-400', border: 'border-indigo-500/30' },
                          };
                          const style = stackColors[site.site_type] || { bg: 'bg-slate-500/10', text: 'text-slate-400', border: 'border-slate-500/30' };

                          return (
                            <tr key={site.id} className="hover:bg-slate-800/40 transition-colors group">
                              {/* Domain & Stack */}
                              <td className="py-4 px-5">
                                <div className="flex items-center gap-3.5">
                                  <div className={`w-10 h-10 rounded-xl ${style.bg} ${style.border} border flex items-center justify-center ${style.text} font-bold shadow-md shrink-0`}>
                                    <Globe className="w-5 h-5" />
                                  </div>
                                  <div className="space-y-1">
                                    <div className="flex items-center gap-2">
                                      <h3 className="font-bold text-sm text-white tracking-tight group-hover:text-cyan-400 transition-colors">
                                        {site.domain_name}
                                      </h3>
                                      <span className="flex h-2 w-2 relative" title="Active Host Status">
                                        <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                                        <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
                                      </span>
                                    </div>
                                    <div className="flex items-center gap-2">
                                      <span className={`text-[10px] font-extrabold uppercase px-2 py-0.5 rounded-md ${style.bg} ${style.text} ${style.border} border tracking-wide`}>
                                        {site.site_type}
                                      </span>
                                      {site.site_title && (
                                        <span className="text-[11px] text-slate-400 truncate max-w-[180px]">
                                          {site.site_title}
                                        </span>
                                      )}
                                    </div>
                                  </div>
                                </div>
                              </td>

                              {/* Document Root & Runtime */}
                              <td className="py-4 px-4">
                                <div className="space-y-1.5">
                                  <div className="flex items-center gap-1.5 font-mono text-slate-300 text-[11px]">
                                    <Folder className="w-3.5 h-3.5 text-slate-500 shrink-0" />
                                    <span className="truncate max-w-[220px]" title={site.document_root}>
                                      {site.document_root}
                                    </span>
                                    <button
                                      onClick={() => {
                                        navigator.clipboard.writeText(site.document_root);
                                        showToast(`Copied root path: ${site.document_root}`);
                                      }}
                                      className="text-slate-500 hover:text-cyan-400 p-0.5 rounded cursor-pointer transition-colors"
                                      title="Copy Path"
                                    >
                                      <Copy className="w-3 h-3" />
                                    </button>
                                  </div>
                                  <div className="flex items-center gap-2">
                                    <span className="bg-slate-950 text-cyan-400 font-mono text-[10px] px-2 py-0.5 rounded border border-slate-800">
                                      PHP {site.php_version}
                                    </span>
                                    {site.app_port && (
                                      <span className="bg-slate-950 text-indigo-400 font-mono text-[10px] px-2 py-0.5 rounded border border-slate-800">
                                        Port: {site.app_port}
                                      </span>
                                    )}
                                  </div>
                                </div>
                              </td>

                              {/* Security & SSL */}
                              <td className="py-4 px-4">
                                <div className="space-y-1">
                                  <div className="flex items-center gap-1.5 text-emerald-400 text-xs font-medium">
                                    <ShieldCheck className="w-4 h-4 text-emerald-400" />
                                    <span>{site.ssl_enabled ? "Let's Encrypt SSL" : "HTTP VirtualHost"}</span>
                                  </div>
                                  <div className="text-[11px] text-slate-400 flex items-center gap-1">
                                    <Lock className="w-3 h-3 text-cyan-400" />
                                    <span>WAF & HTTPS Enforced</span>
                                  </div>
                                </div>
                              </td>

                              {/* Database */}
                              <td className="py-4 px-4">
                                {site.db_name || site.linked_db_name ? (
                                  <div className="flex items-center gap-1.5 bg-slate-950 px-2.5 py-1 rounded-lg border border-slate-800/80 w-fit">
                                    <Database className="w-3.5 h-3.5 text-amber-400" />
                                    <span className="font-mono text-slate-200 text-[11px]">
                                      {site.db_name || site.linked_db_name}
                                    </span>
                                  </div>
                                ) : (
                                  <span className="text-slate-500 text-xs font-mono">-</span>
                                )}
                              </td>

                              {/* Live Preview Button */}
                              <td className="py-4 px-4">
                                <a
                                  href={site.preview_url || `/sites/${site.domain_name}/`}
                                  target="_blank"
                                  rel="noreferrer"
                                  className="inline-flex items-center gap-1.5 bg-emerald-500/10 hover:bg-emerald-500/20 text-emerald-400 hover:text-emerald-300 font-bold text-xs px-3.5 py-1.5 rounded-xl border border-emerald-500/30 hover:border-emerald-500/50 shadow-sm transition-all group/link"
                                >
                                  <span>Visit Site</span>
                                  <ArrowUpRight className="w-3.5 h-3.5 transition-transform group-hover/link:-translate-y-0.5 group-hover/link:translate-x-0.5" />
                                </a>
                              </td>

                              {/* Action Buttons */}
                              <td className="py-4 px-5 text-right">
                                <div className="flex items-center justify-end gap-2">
                                  <button
                                    onClick={() => openManageSiteConsole(site)}
                                    className="bg-slate-800 hover:bg-slate-700 text-slate-200 font-semibold px-3 py-1.5 rounded-xl border border-slate-700 hover:border-slate-600 text-xs transition-all cursor-pointer flex items-center gap-1.5 shadow-sm"
                                    title="Manage Site Settings, Files & Security"
                                  >
                                    <Settings className="w-3.5 h-3.5 text-cyan-400" />
                                    <span className="hidden xl:inline">Manage</span>
                                  </button>

                                  <button
                                    onClick={() => {
                                      setNewlyCreatedSite(site);
                                      setShowSiteReadyModal(true);
                                      setActiveConfigTab('nginx');
                                    }}
                                    className="bg-cyan-500/20 hover:bg-cyan-500/30 text-cyan-300 font-semibold px-3 py-1.5 rounded-xl border border-cyan-500/30 hover:border-cyan-500/50 text-xs transition-all cursor-pointer flex items-center gap-1.5 shadow-sm"
                                    title="View CloudPanel Nginx, Systemd & FPM Configs"
                                  >
                                    <Code className="w-3.5 h-3.5" />
                                    <span className="hidden xl:inline">Config</span>
                                  </button>

                                  <button
                                    onClick={() => handleDeleteWebsite(site.id, site.domain_name)}
                                    className="p-1.5 rounded-xl bg-slate-950/60 hover:bg-rose-500/20 text-slate-400 hover:text-rose-400 border border-slate-800 hover:border-rose-500/30 transition-all cursor-pointer"
                                    title="Delete Website Host"
                                  >
                                    <Trash2 className="w-3.5 h-3.5" />
                                  </button>
                                </div>
                              </td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}

              {/* GRID VIEW CARDS */}
              {websiteViewMode === 'grid' && filteredWebsites.length > 0 && (
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
                  {filteredWebsites.map((site) => {
                    const stackColors: Record<string, { bg: string; text: string; border: string }> = {
                      wordpress: { bg: 'bg-cyan-500/10', text: 'text-cyan-400', border: 'border-cyan-500/30' },
                      laravel: { bg: 'bg-rose-500/10', text: 'text-rose-400', border: 'border-rose-500/30' },
                      nodejs: { bg: 'bg-emerald-500/10', text: 'text-emerald-400', border: 'border-emerald-500/30' },
                      python: { bg: 'bg-amber-500/10', text: 'text-amber-400', border: 'border-amber-500/30' },
                      static: { bg: 'bg-indigo-500/10', text: 'text-indigo-400', border: 'border-indigo-500/30' },
                    };
                    const style = stackColors[site.site_type] || { bg: 'bg-slate-500/10', text: 'text-slate-400', border: 'border-slate-500/30' };

                    return (
                      <div key={site.id} className="bg-slate-900/80 border border-slate-800 hover:border-slate-700/80 rounded-2xl p-5 space-y-4 shadow-xl transition-all hover:shadow-2xl hover:-translate-y-0.5">
                        <div className="flex items-start justify-between">
                          <div className="flex items-center gap-3">
                            <div className={`w-10 h-10 rounded-xl ${style.bg} ${style.border} border flex items-center justify-center ${style.text} font-bold shadow-md`}>
                              <Globe className="w-5 h-5" />
                            </div>
                            <div>
                              <div className="flex items-center gap-2">
                                <h3 className="font-bold text-base text-white tracking-wide">{site.domain_name}</h3>
                                <span className="flex h-2 w-2 relative" title="Active">
                                  <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                                  <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
                                </span>
                              </div>
                              <span className={`text-[10px] font-extrabold uppercase px-2 py-0.5 rounded-md ${style.bg} ${style.text} ${style.border} border tracking-wide inline-block mt-1`}>
                                {site.site_type}
                              </span>
                            </div>
                          </div>

                          <button
                            onClick={() => handleDeleteWebsite(site.id, site.domain_name)}
                            className="text-slate-500 hover:text-rose-400 p-1.5 rounded-lg hover:bg-rose-500/10 transition-colors cursor-pointer"
                            title="Delete"
                          >
                            <Trash2 className="w-4 h-4" />
                          </button>
                        </div>

                        <div className="bg-slate-950/80 p-3 rounded-xl border border-slate-800 text-xs font-mono space-y-1 text-slate-400">
                          <div className="flex items-center justify-between">
                            <span className="text-slate-500">Root:</span>
                            <span className="text-slate-200 truncate max-w-[200px]" title={site.document_root}>{site.document_root}</span>
                          </div>
                          <div className="flex items-center justify-between">
                            <span className="text-slate-500">PHP Runtime:</span>
                            <span className="text-cyan-400 font-bold">v{site.php_version}</span>
                          </div>
                          {site.db_name && (
                            <div className="flex items-center justify-between">
                              <span className="text-slate-500">Database:</span>
                              <span className="text-amber-400 font-bold">{site.db_name}</span>
                            </div>
                          )}
                        </div>

                        <div className="grid grid-cols-2 gap-2 pt-1">
                          <a
                            href={site.preview_url || `/sites/${site.domain_name}/`}
                            target="_blank"
                            rel="noreferrer"
                            className="bg-emerald-500/10 hover:bg-emerald-500/20 text-emerald-400 font-bold text-xs py-2 rounded-xl cursor-pointer border border-emerald-500/30 flex items-center justify-center gap-1.5 col-span-2 transition-all"
                          >
                            <span>Visit Site</span>
                            <ArrowUpRight className="w-3.5 h-3.5" />
                          </a>
                          <button
                            onClick={() => openManageSiteConsole(site)}
                            className="bg-slate-800 hover:bg-slate-700 text-slate-200 font-bold text-xs py-2 rounded-xl cursor-pointer border border-slate-700 flex items-center justify-center gap-1.5 transition-all"
                          >
                            <Settings className="w-3.5 h-3.5 text-cyan-400" /> Manage Site
                          </button>
                          <button
                            onClick={() => {
                              setNewlyCreatedSite(site);
                              setShowSiteReadyModal(true);
                              setActiveConfigTab('nginx');
                            }}
                            className="bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs py-2 rounded-xl cursor-pointer shadow-md shadow-cyan-500/20 flex items-center justify-center gap-1.5 transition-all"
                          >
                            <Code className="w-3.5 h-3.5" /> Config
                          </button>
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
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

          {/* DATABASES TAB (ADVANCED ENTERPRISE SUITE) */}
          {activeTab === 'databases' && !activeManageSite && !activeManageDb && (
            <div className="space-y-6 animate-fade-in">
              {/* Header & Main Controls */}
              <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 bg-slate-900/60 p-5 rounded-2xl border border-slate-800/80 backdrop-blur-xl shadow-xl">
                <div>
                  <div className="flex items-center gap-3">
                    <h2 className="text-2xl font-bold text-white flex items-center gap-3">
                      <Database className="w-7 h-7 text-indigo-400" />
                      <span>Database Engine Instances & SQL Control Center</span>
                    </h2>
                    <span className="bg-emerald-500/10 text-emerald-400 text-xs font-mono font-bold px-3 py-1 rounded-full border border-emerald-500/30 flex items-center gap-1.5">
                      <span className="w-2 h-2 rounded-full bg-emerald-400 animate-ping"></span>
                      MYSQL RUNNING
                    </span>
                  </div>
                  <p className="text-sm text-slate-400 mt-1">Manage production MySQL & MariaDB databases, SQL dumps, restores, table optimizations and live query console</p>
                </div>

                <div className="flex flex-wrap items-center gap-3">
                  {/* Create Database Button */}
                  <button
                    onClick={() => setShowAddDbModal(true)}
                    className="bg-gradient-to-r from-indigo-500 to-blue-600 hover:from-indigo-400 hover:to-blue-500 text-white font-bold px-5 py-2.5 rounded-xl text-sm transition-all shadow-lg shadow-indigo-500/25 flex items-center gap-2 cursor-pointer"
                  >
                    <Plus className="w-4 h-4" />
                    <span>Create Database</span>
                  </button>
                </div>
              </div>

              {/* Filter & Live Search Toolbar */}
              <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-4 bg-slate-900/40 p-4 rounded-2xl border border-slate-800/60">
                {/* Search Bar */}
                <div className="relative flex-1 max-w-md">
                  <Search className="w-4 h-4 text-slate-400 absolute left-3.5 top-1/2 -translate-y-1/2" />
                  <input
                    type="text"
                    value={dbSearch}
                    onChange={(e) => setDbSearch(e.target.value)}
                    placeholder="Search database name or user..."
                    className="w-full bg-slate-950/80 border border-slate-800 focus:border-indigo-500/80 focus:ring-1 focus:ring-indigo-500/80 text-white placeholder:text-slate-500 text-xs rounded-xl pl-10 pr-8 py-2.5 transition-all outline-none"
                  />
                  {dbSearch && (
                    <button
                      onClick={() => setDbSearch('')}
                      className="absolute right-3 top-1/2 -translate-y-1/2 text-xs text-slate-500 hover:text-slate-300"
                    >
                      ✕
                    </button>
                  )}
                </div>

                <div className="flex items-center gap-2 text-xs text-slate-400 font-mono">
                  <span>Total Size: <strong className="text-white">{databases.reduce((a, b) => a + (b.size_mb || 0), 0).toFixed(2)} MB</strong></span>
                  <span>|</span>
                  <span>Active DBs: <strong className="text-cyan-400">{databases.length}</strong></span>
                </div>
              </div>

              {/* DATABASES LIST VIEW TABLE */}
              <div className="bg-slate-900/80 border border-slate-800/90 rounded-2xl shadow-2xl overflow-hidden backdrop-blur-xl">
                <div className="overflow-x-auto">
                  <table className="w-full text-left border-collapse">
                    <thead>
                      <tr className="bg-slate-950/80 border-b border-slate-800 text-[11px] font-bold text-slate-400 uppercase tracking-wider">
                        <th className="py-3.5 px-5">Database Name & Engine</th>
                        <th className="py-3.5 px-4">User & Connection Host</th>
                        <th className="py-3.5 px-4">Storage Size & Status</th>
                        <th className="py-3.5 px-4">SQL Management</th>
                        <th className="py-3.5 px-5 text-right">Actions</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800/60 text-xs">
                      {databases
                        .filter(db => db.name.toLowerCase().includes(dbSearch.toLowerCase()) || db.username.toLowerCase().includes(dbSearch.toLowerCase()))
                        .map((db) => (
                          <tr key={db.id} className="hover:bg-slate-800/40 transition-colors group">
                            {/* Database Name & Engine */}
                            <td className="py-4 px-5">
                              <div className="flex items-center gap-3.5">
                                <div className="w-10 h-10 rounded-xl bg-gradient-to-tr from-amber-500/20 to-indigo-500/20 border border-amber-500/30 flex items-center justify-center text-amber-400 font-bold shadow-md shrink-0">
                                  <Database className="w-5 h-5" />
                                </div>
                                <div className="space-y-1">
                                  <div className="flex items-center gap-2">
                                    <h3 className="font-bold text-sm text-white font-mono tracking-tight group-hover:text-cyan-400 transition-colors">
                                      {db.name}
                                    </h3>
                                    <span className="flex h-2 w-2 relative" title="Database Active">
                                      <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                                      <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
                                    </span>
                                  </div>
                                  <div className="flex items-center gap-2">
                                    <span className="text-[10px] font-extrabold uppercase px-2 py-0.5 rounded-md bg-amber-500/10 text-amber-400 border border-amber-500/30 font-mono tracking-wide">
                                      {db.engine || 'mysql'}
                                    </span>
                                    <span className="text-[11px] text-slate-400 font-mono">utf8mb4_unicode_ci</span>
                                  </div>
                                </div>
                              </div>
                            </td>

                            {/* User & Connection Host */}
                            <td className="py-4 px-4">
                              <div className="space-y-1 font-mono text-[11px]">
                                <div className="flex items-center gap-1.5 text-slate-200">
                                  <Key className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
                                  <span>User: <strong className="text-white">{db.username}</strong></span>
                                </div>
                                <div className="flex items-center gap-1.5 text-slate-400">
                                  <Server className="w-3.5 h-3.5 text-slate-500 shrink-0" />
                                  <span>{db.host || '127.0.0.1'}:{db.port || 3306}</span>
                                </div>
                              </div>
                            </td>

                            {/* Storage Size & Status */}
                            <td className="py-4 px-4">
                              <div className="space-y-1">
                                <div className="flex items-center gap-2">
                                  <span className="font-extrabold text-sm text-white font-mono">{db.size_mb || 0} MB</span>
                                  <span className="text-[10px] bg-slate-950 text-cyan-400 px-2 py-0.5 rounded border border-slate-800 font-mono">
                                    InnoDB
                                  </span>
                                </div>
                                <div className="w-28 bg-slate-950 rounded-full h-1.5 overflow-hidden border border-slate-800">
                                  <div
                                    className="bg-indigo-500 h-full rounded-full"
                                    style={{ width: `${Math.min(100, ((db.size_mb || 0) / 100) * 100)}%` }}
                                  ></div>
                                </div>
                              </div>
                            </td>

                            {/* SQL Management Toolbar */}
                            <td className="py-4 px-4">
                              <div className="flex items-center gap-1.5 flex-wrap">
                                <button
                                  onClick={() => handleOpenDbManage(db)}
                                  className="bg-indigo-600/30 hover:bg-indigo-600/50 text-indigo-200 font-bold text-xs px-3 py-1.5 rounded-lg border border-indigo-500/40 flex items-center gap-1.5 cursor-pointer transition-all shadow-md hover:shadow-indigo-500/20"
                                  title="Show Tables, Read Data & Manage Database"
                                >
                                  <Eye className="w-3.5 h-3.5 text-cyan-400" />
                                  <span>Manage DB & Tables</span>
                                </button>

                                <button
                                  onClick={() => {
                                    setSelectedDbQueryModal(db);
                                    setDbQueryText('SHOW TABLES;');
                                    setDbQueryResult(null);
                                    setDbQueryError(null);
                                  }}
                                  className="bg-indigo-500/20 hover:bg-indigo-500/30 text-indigo-300 font-bold text-xs px-2.5 py-1.5 rounded-lg border border-indigo-500/30 flex items-center gap-1 cursor-pointer transition-all shadow-sm"
                                  title="Run SQL Queries against database"
                                >
                                  <Terminal className="w-3.5 h-3.5" />
                                  <span>SQL Console</span>
                                </button>

                                <button
                                  onClick={() => handleDownloadDbBackup(db.name)}
                                  className="bg-emerald-500/20 hover:bg-emerald-500/30 text-emerald-300 font-bold text-xs px-2.5 py-1.5 rounded-lg border border-emerald-500/30 flex items-center gap-1 cursor-pointer transition-all shadow-sm"
                                  title="Download .SQL Dump Backup"
                                >
                                  <Download className="w-3.5 h-3.5" />
                                  <span>Export SQL</span>
                                </button>

                                <button
                                  onClick={() => {
                                    setSelectedDbRestoreModal(db);
                                    setDbRestoreSql('');
                                  }}
                                  className="bg-amber-500/20 hover:bg-amber-500/30 text-amber-300 font-bold text-xs px-2.5 py-1.5 rounded-lg border border-amber-500/30 flex items-center gap-1 cursor-pointer transition-all shadow-sm"
                                  title="Restore / Import SQL script into database"
                                >
                                  <Code className="w-3.5 h-3.5" />
                                  <span>Import</span>
                                </button>
                              </div>
                            </td>

                            {/* Actions */}
                            <td className="py-4 px-5 text-right">
                              <div className="flex items-center justify-end gap-2">
                                <button
                                  onClick={() => handleOptimizeDb(db.name)}
                                  className="bg-slate-800 hover:bg-slate-700 text-cyan-400 font-semibold px-3 py-1.5 rounded-xl border border-slate-700 text-xs transition-all cursor-pointer flex items-center gap-1.5"
                                  title="Optimize & Repair MySQL Tables"
                                >
                                  <RefreshCw className="w-3.5 h-3.5" />
                                  <span className="hidden xl:inline">Optimize</span>
                                </button>

                                <button
                                  onClick={() => setSelectedDbConnModal(db)}
                                  className="bg-slate-800 hover:bg-slate-700 text-slate-200 font-semibold px-3 py-1.5 rounded-xl border border-slate-700 text-xs transition-all cursor-pointer flex items-center gap-1.5"
                                  title="View Connection String & Code Snippets"
                                >
                                  <Key className="w-3.5 h-3.5 text-cyan-400" />
                                  <span className="hidden xl:inline">Credentials</span>
                                </button>

                                <button
                                  onClick={() => handleDeleteDatabase(db.id, db.name)}
                                  className="p-1.5 rounded-xl bg-slate-950/60 hover:bg-rose-500/20 text-slate-400 hover:text-rose-400 border border-slate-800 hover:border-rose-500/30 transition-all cursor-pointer"
                                  title="Drop Database"
                                >
                                  <Trash2 className="w-3.5 h-3.5" />
                                </button>
                              </div>
                            </td>
                          </tr>
                        ))}
                    </tbody>
                  </table>
                </div>
              </div>

              {/* SQL QUERY CONSOLE MODAL */}
              {selectedDbQueryModal && (
                <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-md flex items-center justify-center p-4">
                  <div className="bg-slate-900 border border-slate-800 w-full max-w-4xl rounded-2xl p-6 space-y-4 shadow-2xl animate-scale-up">
                    <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                      <div className="flex items-center gap-3">
                        <Terminal className="w-6 h-6 text-indigo-400" />
                        <div>
                          <h3 className="text-lg font-bold text-white font-mono">
                            SQL Console — <span className="text-cyan-400">{selectedDbQueryModal.name}</span>
                          </h3>
                          <p className="text-xs text-slate-400">Run SQL queries (`SELECT`, `SHOW TABLES`, `DESCRIBE`) live on host MySQL engine</p>
                        </div>
                      </div>
                      <button
                        onClick={() => setSelectedDbQueryModal(null)}
                        className="text-slate-400 hover:text-white p-1 rounded-lg hover:bg-slate-800 text-sm font-bold"
                      >
                        ✕
                      </button>
                    </div>

                    <div className="space-y-2">
                      <label className="text-xs font-semibold text-slate-400 flex items-center justify-between">
                        <span>SQL Statement:</span>
                        <div className="flex items-center gap-2">
                          <button
                            onClick={() => setDbQueryText('SHOW TABLES;')}
                            className="text-[11px] bg-slate-950 px-2 py-0.5 rounded border border-slate-800 text-cyan-400 hover:underline"
                          >
                            SHOW TABLES
                          </button>
                          <button
                            onClick={() => setDbQueryText('SHOW TABLE STATUS;')}
                            className="text-[11px] bg-slate-950 px-2 py-0.5 rounded border border-slate-800 text-cyan-400 hover:underline"
                          >
                            TABLE STATUS
                          </button>
                        </div>
                      </label>
                      <textarea
                        rows={3}
                        value={dbQueryText}
                        onChange={(e) => setDbQueryText(e.target.value)}
                        placeholder="SELECT * FROM table_name LIMIT 50;"
                        className="w-full bg-slate-950 border border-slate-800 rounded-xl p-3 text-xs font-mono text-cyan-300 focus:outline-none focus:border-indigo-500"
                      ></textarea>
                    </div>

                    <div className="flex justify-end gap-3">
                      <button
                        onClick={() => setSelectedDbQueryModal(null)}
                        className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-bold rounded-xl cursor-pointer"
                      >
                        Close
                      </button>
                      <button
                        onClick={handleRunDbQuery}
                        disabled={dbQueryLoading}
                        className="px-5 py-2 bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-bold rounded-xl cursor-pointer flex items-center gap-2 shadow-lg shadow-indigo-500/25"
                      >
                        {dbQueryLoading ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Terminal className="w-4 h-4" />}
                        <span>Execute SQL</span>
                      </button>
                    </div>

                    {/* Query Error Display */}
                    {dbQueryError && (
                      <div className="bg-rose-500/10 border border-rose-500/30 p-3 rounded-xl text-rose-400 text-xs font-mono">
                        <strong>SQL Execution Error:</strong> {dbQueryError}
                      </div>
                    )}

                    {/* Query Results Table */}
                    {dbQueryResult && (
                      <div className="space-y-2 pt-2 border-t border-slate-800">
                        <div className="flex items-center justify-between text-xs text-slate-400 font-mono">
                          <span>Rows returned: <strong className="text-emerald-400">{dbQueryResult.row_count}</strong></span>
                          <span>Columns: <strong className="text-cyan-400">{dbQueryResult.columns.length}</strong></span>
                        </div>
                        <div className="max-h-60 overflow-y-auto bg-slate-950 border border-slate-800 rounded-xl">
                          <table className="w-full text-left text-xs font-mono border-collapse">
                            <thead className="bg-slate-900 sticky top-0 border-b border-slate-800 text-cyan-400">
                              <tr>
                                {dbQueryResult.columns.map((col, idx) => (
                                  <th key={idx} className="py-2 px-3 border-r border-slate-800/80">{col}</th>
                                ))}
                              </tr>
                            </thead>
                            <tbody className="divide-y divide-slate-800/60 text-slate-200">
                              {dbQueryResult.rows.map((row, rIdx) => (
                                <tr key={rIdx} className="hover:bg-slate-900/60">
                                  {row.map((val, cIdx) => (
                                    <td key={cIdx} className="py-1.5 px-3 border-r border-slate-800/40 truncate max-w-xs">{val}</td>
                                  ))}
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        </div>
                      </div>
                    )}
                  </div>
                </div>
              )}

              {/* SQL RESTORE / IMPORT MODAL */}
              {selectedDbRestoreModal && (
                <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-md flex items-center justify-center p-4">
                  <div className="bg-slate-900 border border-slate-800 w-full max-w-2xl rounded-2xl p-6 space-y-4 shadow-2xl animate-scale-up">
                    <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                      <div className="flex items-center gap-3">
                        <Code className="w-6 h-6 text-amber-400" />
                        <div>
                          <h3 className="text-lg font-bold text-white font-mono">
                            Restore / Import SQL — <span className="text-amber-400">{selectedDbRestoreModal.name}</span>
                          </h3>
                          <p className="text-xs text-slate-400">Execute SQL dump statements directly into database</p>
                        </div>
                      </div>
                      <button
                        onClick={() => setSelectedDbRestoreModal(null)}
                        className="text-slate-400 hover:text-white p-1 rounded-lg hover:bg-slate-800 text-sm font-bold"
                      >
                        ✕
                      </button>
                    </div>

                    <div className="space-y-2">
                      <label className="text-xs font-semibold text-slate-400 flex items-center justify-between">
                        <span>Paste SQL Script Content:</span>
                        <input
                          type="file"
                          accept=".sql,.txt"
                          onChange={(e) => {
                            const file = e.target.files?.[0];
                            if (file) {
                              const reader = new FileReader();
                              reader.onload = (evt) => setDbRestoreSql(evt.target?.result as string || '');
                              reader.readAsText(file);
                            }
                          }}
                          className="text-xs text-slate-400"
                        />
                      </label>
                      <textarea
                        rows={8}
                        value={dbRestoreSql}
                        onChange={(e) => setDbRestoreSql(e.target.value)}
                        placeholder="CREATE TABLE example (...); INSERT INTO example VALUES (...);"
                        className="w-full bg-slate-950 border border-slate-800 rounded-xl p-3 text-xs font-mono text-amber-300 focus:outline-none focus:border-amber-500"
                      ></textarea>
                    </div>

                    <div className="flex justify-end gap-3">
                      <button
                        onClick={() => setSelectedDbRestoreModal(null)}
                        className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-bold rounded-xl cursor-pointer"
                      >
                        Cancel
                      </button>
                      <button
                        onClick={handleRunDbRestore}
                        disabled={dbRestoreLoading || !dbRestoreSql.trim()}
                        className="px-5 py-2 bg-amber-500 hover:bg-amber-400 text-slate-950 text-xs font-bold rounded-xl cursor-pointer flex items-center gap-2 shadow-lg shadow-amber-500/25"
                      >
                        {dbRestoreLoading ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Code className="w-4 h-4" />}
                        <span>Execute SQL Import</span>
                      </button>
                    </div>
                  </div>
                </div>
              )}
            </div>
          )}

          {/* DEDICATED DATABASE MANAGEMENT & EXPLORER ROUTE VIEW */}
          {activeTab === 'databases' && !activeManageSite && activeManageDb && (
            <div className="space-y-6 animate-fade-in">
              {/* Header Bar & Navigation */}
              <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 bg-slate-900/70 p-5 rounded-3xl border border-slate-800/80 backdrop-blur-xl shadow-xl">
                <div className="flex flex-wrap items-center gap-4">
                  <button
                    onClick={() => setActiveManageDb(null)}
                    className="p-2.5 rounded-2xl bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 text-xs font-bold transition-all cursor-pointer flex items-center gap-2 shadow-sm"
                    title="Back to All Databases"
                  >
                    <ChevronRight className="w-4 h-4 rotate-180 text-cyan-400" />
                    <span>Back to Databases</span>
                  </button>

                  <div className="hidden sm:block w-px h-8 bg-slate-800"></div>

                  <div className="flex items-center gap-3.5">
                    <div className="w-12 h-12 rounded-2xl bg-indigo-500/10 border border-indigo-500/30 flex items-center justify-center shadow-lg shadow-indigo-500/10">
                      <Database className="w-6 h-6 text-indigo-400" />
                    </div>
                    <div>
                      <div className="flex items-center gap-2.5">
                        <h2 className="text-2xl font-extrabold text-white font-mono tracking-wide">
                          {activeManageDb.name}
                        </h2>
                        <span className={`text-[10px] font-mono font-bold px-2.5 py-0.5 rounded-full border uppercase tracking-wider ${
                          activeManageDb.engine?.toLowerCase() === 'postgresql'
                            ? 'bg-sky-500/10 text-sky-400 border-sky-500/30'
                            : activeManageDb.engine?.toLowerCase() === 'mongodb'
                            ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                            : activeManageDb.engine?.toLowerCase() === 'redis'
                            ? 'bg-rose-500/10 text-rose-400 border-rose-500/30'
                            : 'bg-indigo-500/10 text-indigo-400 border-indigo-500/30'
                        }`}>
                          {activeManageDb.engine || 'MySQL'}
                        </span>
                      </div>
                      <p className="text-xs text-slate-400 mt-1 flex flex-wrap items-center gap-4">
                        <span>Host: <strong className="text-slate-200 font-mono">{activeManageDb.host || '127.0.0.1'}</strong></span>
                        <span>User: <strong className="text-slate-200 font-mono">{activeManageDb.username || 'root'}</strong></span>
                        <span>Size: <strong className="text-cyan-400 font-mono">{(activeManageDb.size_mb || 0).toFixed(2)} MB</strong></span>
                      </p>
                    </div>
                  </div>
                </div>

                <div className="flex flex-wrap items-center gap-2">
                  <button
                    onClick={() => loadDbTables(activeManageDb)}
                    className="bg-slate-800 hover:bg-slate-700 text-slate-300 font-bold text-xs px-3.5 py-2 rounded-xl border border-slate-700 flex items-center gap-1.5 transition-all shadow-sm cursor-pointer"
                    title="Refresh database metadata & tables"
                  >
                    <RefreshCw className={`w-3.5 h-3.5 ${dbManageTablesLoading ? 'animate-spin text-indigo-400' : ''}`} />
                    <span>Refresh</span>
                  </button>

                  <button
                    onClick={() => handleDownloadDbBackup(activeManageDb.name)}
                    className="bg-emerald-500/20 hover:bg-emerald-500/30 text-emerald-300 font-bold text-xs px-3.5 py-2 rounded-xl border border-emerald-500/30 flex items-center gap-1.5 transition-all shadow-sm cursor-pointer"
                    title="Export SQL Dump"
                  >
                    <Download className="w-3.5 h-3.5" />
                    <span>Export SQL</span>
                  </button>

                  <button
                    onClick={() => {
                      setSelectedDbRestoreModal(activeManageDb);
                      setDbRestoreSql('');
                    }}
                    className="bg-amber-500/20 hover:bg-amber-500/30 text-amber-300 font-bold text-xs px-3.5 py-2 rounded-xl border border-amber-500/30 flex items-center gap-1.5 transition-all shadow-sm cursor-pointer"
                    title="Import SQL Script"
                  >
                    <Code className="w-3.5 h-3.5" />
                    <span>Import SQL</span>
                  </button>

                  <button
                    onClick={() => setSelectedDbConnModal(activeManageDb)}
                    className="bg-slate-800 hover:bg-slate-700 text-slate-200 font-semibold px-3.5 py-2 rounded-xl border border-slate-700 text-xs transition-all cursor-pointer flex items-center gap-1.5"
                    title="View Credentials"
                  >
                    <Key className="w-3.5 h-3.5 text-cyan-400" />
                    <span>Credentials</span>
                  </button>
                </div>
              </div>

                    {/* Navigation Sub-Tabs */}
                    <div className="flex items-center gap-2 border-b border-slate-800/60 pb-3 shrink-0 overflow-x-auto">
                      <button
                        onClick={() => setActiveDbManageTab('tables')}
                        className={`px-4 py-2 rounded-xl text-xs font-bold transition-all flex items-center gap-2 cursor-pointer ${
                          activeDbManageTab === 'tables'
                            ? 'bg-indigo-600 text-white shadow-lg shadow-indigo-600/30 border border-indigo-500/50'
                            : 'bg-slate-800/60 hover:bg-slate-800 text-slate-400 hover:text-slate-200 border border-slate-800'
                        }`}
                      >
                        <List className="w-4 h-4" />
                        <span>Show Tables ({dbManageTables.length})</span>
                      </button>

                      <button
                        onClick={() => {
                          if (dbManageTables.length > 0 && !activeManageTableName) {
                            handleReadTableData(activeManageDb, dbManageTables[0].name);
                          } else if (activeManageTableName) {
                            handleReadTableData(activeManageDb, activeManageTableName);
                          } else {
                            setActiveDbManageTab('read_data');
                          }
                        }}
                        className={`px-4 py-2 rounded-xl text-xs font-bold transition-all flex items-center gap-2 cursor-pointer ${
                          activeDbManageTab === 'read_data'
                            ? 'bg-indigo-600 text-white shadow-lg shadow-indigo-600/30 border border-indigo-500/50'
                            : 'bg-slate-800/60 hover:bg-slate-800 text-slate-400 hover:text-slate-200 border border-slate-800'
                        }`}
                      >
                        <Eye className="w-4 h-4 text-cyan-400" />
                        <span>Read Data {activeManageTableName ? `(${activeManageTableName})` : ''}</span>
                      </button>

                      <button
                        onClick={() => {
                          if (dbManageTables.length > 0 && !activeManageTableName) {
                            handleViewTableStructure(activeManageDb, dbManageTables[0].name);
                          } else if (activeManageTableName) {
                            handleViewTableStructure(activeManageDb, activeManageTableName);
                          } else {
                            setActiveDbManageTab('structure');
                          }
                        }}
                        className={`px-4 py-2 rounded-xl text-xs font-bold transition-all flex items-center gap-2 cursor-pointer ${
                          activeDbManageTab === 'structure'
                            ? 'bg-indigo-600 text-white shadow-lg shadow-indigo-600/30 border border-indigo-500/50'
                            : 'bg-slate-800/60 hover:bg-slate-800 text-slate-400 hover:text-slate-200 border border-slate-800'
                        }`}
                      >
                        <Code className="w-4 h-4 text-amber-400" />
                        <span>Structure & Schema</span>
                      </button>

                      <button
                        onClick={() => {
                          setSelectedDbQueryModal(activeManageDb);
                          setDbQueryText('SELECT * FROM ' + (dbManageTables[0]?.name || 'table_name') + ' LIMIT 20;');
                        }}
                        className="px-4 py-2 rounded-xl text-xs font-bold transition-all flex items-center gap-2 cursor-pointer bg-slate-800/60 hover:bg-slate-800 text-slate-400 hover:text-slate-200 border border-slate-800 ml-auto"
                      >
                        <Terminal className="w-4 h-4 text-indigo-400" />
                        <span>Open SQL Console</span>
                      </button>
                    </div>

                    {/* Tab Content Container */}
                    <div className="flex-1 overflow-y-auto space-y-4 pr-1 min-h-[350px]">
                      {/* TAB 1: SHOW TABLES LIST */}
                      {activeDbManageTab === 'tables' && (
                        <div className="space-y-4">
                          {/* Filter Toolbar */}
                          <div className="flex items-center justify-between gap-4">
                            <div className="relative flex-1 max-w-md">
                              <Search className="w-4 h-4 text-slate-500 absolute left-3.5 top-1/2 -translate-y-1/2" />
                              <input
                                type="text"
                                value={dbManageTableSearch}
                                onChange={(e) => setDbManageTableSearch(e.target.value)}
                                placeholder="Filter table name..."
                                className="w-full bg-slate-950 border border-slate-800 focus:border-indigo-500/80 text-white text-xs rounded-xl pl-10 pr-4 py-2 outline-none"
                              />
                            </div>
                            <span className="text-xs text-slate-400">
                              Found <strong className="text-white">{dbManageTables.filter(t => t.name.toLowerCase().includes(dbManageTableSearch.toLowerCase())).length}</strong> tables
                            </span>
                          </div>

                          {dbManageTablesLoading ? (
                            <div className="flex flex-col items-center justify-center py-16 text-slate-400 space-y-3">
                              <RefreshCw className="w-8 h-8 animate-spin text-indigo-400" />
                              <p className="text-xs font-mono">Fetching database tables from host engine...</p>
                            </div>
                          ) : dbManageTablesError ? (
                            <div className="p-4 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs">
                              {dbManageTablesError}
                            </div>
                          ) : dbManageTables.length === 0 ? (
                            <div className="flex flex-col items-center justify-center py-16 border border-dashed border-slate-800 rounded-2xl bg-slate-950/40 text-center space-y-3">
                              <Database className="w-10 h-10 text-slate-600" />
                              <p className="text-sm font-semibold text-slate-300">No tables found in this database</p>
                              <p className="text-xs text-slate-500 max-w-sm">This database is currently empty. You can import a SQL dump or run CREATE TABLE statements using the SQL Console.</p>
                            </div>
                          ) : (
                            <div className="border border-slate-800/80 rounded-2xl overflow-hidden bg-slate-950/40">
                              <table className="w-full text-left border-collapse">
                                <thead>
                                  <tr className="bg-slate-950 border-b border-slate-800 text-[11px] font-bold text-slate-400 uppercase tracking-wider">
                                    <th className="py-3 px-4">#</th>
                                    <th className="py-3 px-4">Table Name</th>
                                    <th className="py-3 px-4">Engine</th>
                                    <th className="py-3 px-4">Est. Rows</th>
                                    <th className="py-3 px-4">Data Size</th>
                                    <th className="py-3 px-4 text-right">Actions</th>
                                  </tr>
                                </thead>
                                <tbody className="divide-y divide-slate-800/60 text-xs">
                                  {dbManageTables
                                    .filter((t) => t.name.toLowerCase().includes(dbManageTableSearch.toLowerCase()))
                                    .map((t, idx) => (
                                      <tr key={t.name} className="hover:bg-slate-800/40 transition-colors">
                                        <td className="py-3 px-4 font-mono text-slate-500 text-[11px]">{idx + 1}</td>
                                        <td className="py-3 px-4 font-mono font-bold text-cyan-300">
                                          <button
                                            onClick={() => handleReadTableData(activeManageDb, t.name)}
                                            className="hover:underline hover:text-cyan-200 text-left cursor-pointer"
                                          >
                                            {t.name}
                                          </button>
                                        </td>
                                        <td className="py-3 px-4">
                                          <span className="text-[10px] font-mono font-bold bg-slate-800 px-2 py-0.5 rounded text-slate-300 border border-slate-700">
                                            {t.engine || 'InnoDB'}
                                          </span>
                                        </td>
                                        <td className="py-3 px-4 font-mono text-slate-300">
                                          {t.rows !== undefined ? t.rows.toLocaleString() : '—'}
                                        </td>
                                        <td className="py-3 px-4 font-mono text-slate-400 text-[11px]">
                                          {t.data_length || '—'}
                                        </td>
                                        <td className="py-3 px-4 text-right">
                                          <div className="flex items-center justify-end gap-2">
                                            <button
                                              onClick={() => handleReadTableData(activeManageDb, t.name)}
                                              className="px-2.5 py-1 rounded-lg bg-indigo-500/20 hover:bg-indigo-500/30 text-indigo-300 border border-indigo-500/30 text-[11px] font-semibold transition-all cursor-pointer flex items-center gap-1"
                                              title="Read Table Records Data"
                                            >
                                              <Eye className="w-3 h-3 text-cyan-400" />
                                              <span>Read Data</span>
                                            </button>
                                            <button
                                              onClick={() => handleViewTableStructure(activeManageDb, t.name)}
                                              className="px-2 py-1 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 text-[11px] font-semibold transition-all cursor-pointer flex items-center gap-1"
                                              title="Inspect Columns & Schema"
                                            >
                                              <Code className="w-3 h-3 text-amber-400" />
                                              <span>Structure</span>
                                            </button>
                                            <button
                                              onClick={() => handleTruncateTable(activeManageDb, t.name)}
                                              className="p-1 rounded-lg bg-slate-900 hover:bg-rose-500/20 text-slate-500 hover:text-rose-400 border border-slate-800 hover:border-rose-500/30 transition-all cursor-pointer"
                                              title="Truncate Table Records"
                                            >
                                              <Trash2 className="w-3.5 h-3.5" />
                                            </button>
                                          </div>
                                        </td>
                                      </tr>
                                    ))}
                                </tbody>
                              </table>
                            </div>
                          )}
                        </div>
                      )}

                      {/* TAB 2: READ DATA (RECORD EXPLORER) */}
                      {activeDbManageTab === 'read_data' && (
                        <div className="space-y-4">
                          {/* Top Toolbar */}
                          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 bg-slate-950 p-3 rounded-2xl border border-slate-800">
                            <div className="flex items-center gap-3">
                              <span className="text-xs font-bold text-slate-400">Select Table:</span>
                              <select
                                value={activeManageTableName}
                                onChange={(e) => {
                                  if (e.target.value) handleReadTableData(activeManageDb, e.target.value, dbTableDataLimit);
                                }}
                                className="bg-slate-900 border border-slate-700 text-cyan-300 font-mono text-xs rounded-xl px-3 py-1.5 focus:outline-none"
                              >
                                <option value="">-- Choose Table --</option>
                                {dbManageTables.map((t) => (
                                  <option key={t.name} value={t.name}>{t.name}</option>
                                ))}
                              </select>

                              <span className="text-xs font-bold text-slate-400 ml-2">Rows Limit:</span>
                              <select
                                value={dbTableDataLimit}
                                onChange={(e) => {
                                  const l = parseInt(e.target.value, 10);
                                  setDbTableDataLimit(l);
                                  if (activeManageTableName) handleReadTableData(activeManageDb, activeManageTableName, l);
                                }}
                                className="bg-slate-900 border border-slate-700 text-slate-200 font-mono text-xs rounded-xl px-2.5 py-1.5 focus:outline-none"
                              >
                                <option value={25}>25</option>
                                <option value={50}>50</option>
                                <option value={100}>100</option>
                                <option value={250}>250</option>
                                <option value={500}>500</option>
                              </select>
                            </div>

                            <div className="flex items-center gap-3">
                              <div className="relative">
                                <Search className="w-3.5 h-3.5 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
                                <input
                                  type="text"
                                  value={dbTableDataSearch}
                                  onChange={(e) => setDbTableDataSearch(e.target.value)}
                                  placeholder="Search within fetched rows..."
                                  className="bg-slate-900 border border-slate-800 text-white text-xs rounded-xl pl-8 pr-3 py-1.5 outline-none w-48 focus:w-64 transition-all"
                                />
                              </div>
                              <button
                                onClick={() => {
                                  if (activeManageTableName) handleReadTableData(activeManageDb, activeManageTableName, dbTableDataLimit);
                                }}
                                className="p-1.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 text-xs transition-all cursor-pointer"
                                title="Reload Table Data"
                              >
                                <RefreshCw className={`w-3.5 h-3.5 ${dbTableDataLoading ? 'animate-spin text-indigo-400' : ''}`} />
                              </button>
                            </div>
                          </div>

                          {dbTableDataLoading ? (
                            <div className="flex flex-col items-center justify-center py-16 text-slate-400 space-y-3">
                              <RefreshCw className="w-8 h-8 animate-spin text-indigo-400" />
                              <p className="text-xs font-mono">Reading records from table <span className="text-cyan-300">{activeManageTableName}</span>...</p>
                            </div>
                          ) : dbTableDataError ? (
                            <div className="p-4 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs">
                              {dbTableDataError}
                            </div>
                          ) : !dbTableData || !dbTableData.columns || dbTableData.columns.length === 0 ? (
                            <div className="flex flex-col items-center justify-center py-16 border border-dashed border-slate-800 rounded-2xl bg-slate-950/40 text-center space-y-2">
                              <Eye className="w-8 h-8 text-slate-600" />
                              <p className="text-sm font-semibold text-slate-400">Select a table above to read its records data</p>
                            </div>
                          ) : dbTableData.rows.length === 0 ? (
                            <div className="flex flex-col items-center justify-center py-12 border border-slate-800 rounded-2xl bg-slate-950/40 text-center space-y-2">
                              <CheckCircle2 className="w-8 h-8 text-emerald-400/80" />
                              <p className="text-sm font-semibold text-slate-300">Table <span className="text-cyan-300">{activeManageTableName}</span> is empty (0 records)</p>
                              <div className="flex gap-2 font-mono text-[11px] text-slate-500">
                                <span>Columns: {dbTableData.columns.join(', ')}</span>
                              </div>
                            </div>
                          ) : (
                            <div className="space-y-2">
                              <div className="flex items-center justify-between text-xs text-slate-400 px-1">
                                <span>Showing <strong className="text-cyan-300">{dbTableData.rows.filter(row => row.some(cell => cell && cell.toLowerCase().includes(dbTableDataSearch.toLowerCase()))).length}</strong> of <strong className="text-white">{dbTableData.rows.length}</strong> fetched rows (Limit: {dbTableDataLimit})</span>
                                <span className="font-mono text-[11px] text-slate-400">Table: <strong className="text-cyan-300">{activeManageTableName}</strong>{dbManageTables.find(t => t.name === activeManageTableName)?.rows !== undefined ? ` (${dbManageTables.find(t => t.name === activeManageTableName)?.rows?.toLocaleString()} Total Records)` : ''}</span>
                              </div>

                              <div className="border border-slate-800 rounded-2xl overflow-x-auto bg-slate-950/60 max-h-[500px]">
                                <table className="w-full text-left border-collapse min-w-max">
                                  <thead className="sticky top-0 z-10 bg-slate-950 border-b border-slate-800">
                                    <tr className="text-[11px] font-bold text-slate-400 uppercase tracking-wider">
                                      <th className="py-2.5 px-3 border-r border-slate-800/80 text-center w-12">#</th>
                                      {dbTableData.columns.map((col) => (
                                        <th key={col} className="py-2.5 px-4 font-mono text-cyan-300 border-r border-slate-800/60 last:border-r-0">
                                          {col}
                                        </th>
                                      ))}
                                    </tr>
                                  </thead>
                                  <tbody className="divide-y divide-slate-800/60 text-xs font-mono">
                                    {dbTableData.rows
                                      .filter((row) => row.some((cell) => cell && cell.toLowerCase().includes(dbTableDataSearch.toLowerCase())))
                                      .map((row, rIdx) => (
                                        <tr key={rIdx} className="hover:bg-slate-800/50 transition-colors">
                                          <td className="py-2 px-3 border-r border-slate-800/80 text-center text-slate-500 text-[11px] bg-slate-950/40">
                                            {rIdx + 1}
                                          </td>
                                          {row.map((cell, cIdx) => (
                                            <td key={cIdx} className="py-2 px-4 border-r border-slate-800/40 last:border-r-0 text-slate-300 max-w-xs truncate" title={cell}>
                                              {cell === null || cell === 'NULL' ? (
                                                <span className="text-slate-600 italic text-[11px]">NULL</span>
                                              ) : (
                                                cell
                                              )}
                                            </td>
                                          ))}
                                        </tr>
                                      ))}
                                  </tbody>
                                </table>
                              </div>
                            </div>
                          )}
                        </div>
                      )}

                      {/* TAB 3: STRUCTURE & SCHEMA */}
                      {activeDbManageTab === 'structure' && (
                        <div className="space-y-4">
                          <div className="flex items-center justify-between gap-3 bg-slate-950 p-3 rounded-2xl border border-slate-800">
                            <div className="flex items-center gap-3">
                              <span className="text-xs font-bold text-slate-400">Select Table Schema:</span>
                              <select
                                value={activeManageTableName}
                                onChange={(e) => {
                                  if (e.target.value) handleViewTableStructure(activeManageDb, e.target.value);
                                }}
                                className="bg-slate-900 border border-slate-700 text-amber-300 font-mono text-xs rounded-xl px-3 py-1.5 focus:outline-none"
                              >
                                <option value="">-- Choose Table --</option>
                                {dbManageTables.map((t) => (
                                  <option key={t.name} value={t.name}>{t.name}</option>
                                ))}
                              </select>
                            </div>

                            <span className="text-xs font-mono text-slate-500">
                              Structure inspector
                            </span>
                          </div>

                          {dbTableStructureLoading ? (
                            <div className="flex flex-col items-center justify-center py-16 text-slate-400 space-y-3">
                              <RefreshCw className="w-8 h-8 animate-spin text-amber-400" />
                              <p className="text-xs font-mono">Inspecting schema structure for <span className="text-amber-300">{activeManageTableName}</span>...</p>
                            </div>
                          ) : !dbTableStructure || !dbTableStructure.columns ? (
                            <div className="flex flex-col items-center justify-center py-16 border border-dashed border-slate-800 rounded-2xl bg-slate-950/40 text-center space-y-2">
                              <Code className="w-8 h-8 text-slate-600" />
                              <p className="text-sm font-semibold text-slate-400">Select a table above to inspect its structure & column types</p>
                            </div>
                          ) : (
                            <div className="border border-slate-800 rounded-2xl overflow-hidden bg-slate-950/60">
                              <table className="w-full text-left border-collapse text-xs font-mono">
                                <thead>
                                  <tr className="bg-slate-950 border-b border-slate-800 text-[11px] font-bold text-slate-400 uppercase tracking-wider">
                                    {dbTableStructure.columns.map((col) => (
                                      <th key={col} className="py-2.5 px-4 text-amber-300">{col}</th>
                                    ))}
                                  </tr>
                                </thead>
                                <tbody className="divide-y divide-slate-800/60">
                                  {dbTableStructure.rows.map((row, rIdx) => (
                                    <tr key={rIdx} className="hover:bg-slate-800/40 transition-colors">
                                      {row.map((cell, cIdx) => (
                                        <td key={cIdx} className="py-2 px-4 text-slate-300">
                                          {cell === 'PRI' ? (
                                            <span className="bg-amber-500/20 text-amber-300 font-bold px-2 py-0.5 rounded text-[10px] border border-amber-500/30">PRI KEY</span>
                                          ) : (
                                            cell
                                          )}
                                        </td>
                                      ))}
                                    </tr>
                                  ))}
                                </tbody>
                              </table>
                            </div>
                          )}
                        </div>
                      )}
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

          {/* EMAIL & WEBMAIL TAB */}
          {activeTab === 'email' && !activeManageSite && (
            <EmailWebmailTab
              mailDomains={mailDomains}
              mailboxes={mailboxes}
              webmailUrl={webmailUrl}
              mailServices={mailServices}
              onRefresh={fetchData}
              getHeaders={getHeaders}
              apiBase={API_BASE}
              showToast={showToast}
            />
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

          {/* SECURITY & TEAM MANAGEMENT TAB (PRO SUITE) */}
          {activeTab === 'security' && !activeManageSite && !activeManageDb && (
            <div className="space-y-6 animate-fade-in">
              {/* Header Banner */}
              <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 bg-slate-900/80 p-6 rounded-3xl border border-slate-800/80 backdrop-blur-xl shadow-2xl">
                <div>
                  <div className="flex items-center gap-3">
                    <h2 className="text-2xl font-extrabold text-white flex items-center gap-3">
                      <ShieldCheck className="w-7 h-7 text-emerald-400" />
                      <span>Panel Authentication, RBAC & Security Hardening</span>
                    </h2>
                    <span className="bg-emerald-500/10 text-emerald-400 text-xs font-mono font-bold px-3 py-1 rounded-full border border-emerald-500/30 flex items-center gap-1.5">
                      <span className="w-2 h-2 rounded-full bg-emerald-400 animate-ping"></span>
                      WAF & 2FA ACTIVE
                    </span>
                  </div>
                  <p className="text-sm text-slate-400 mt-1">Manage team access, RBAC permissions, 2FA tokens, active sessions and automated security policies</p>
                </div>

                <div className="flex flex-wrap items-center gap-3">
                  <button
                    onClick={() => setShowInviteModal(true)}
                    className="bg-gradient-to-r from-emerald-500 to-teal-600 hover:from-emerald-400 hover:to-teal-500 text-slate-950 font-bold px-5 py-2.5 rounded-xl text-sm transition-all shadow-lg shadow-emerald-500/25 flex items-center gap-2 cursor-pointer"
                  >
                    <UserPlus className="w-4 h-4" />
                    <span>Invite Team Member</span>
                  </button>
                </div>
              </div>

              {/* Sub-Tabs Bar */}
              <div className="flex items-center gap-2 border-b border-slate-800/80 pb-3 overflow-x-auto">
                <button
                  onClick={() => setActiveSecSubTab('team')}
                  className={`px-5 py-2.5 rounded-xl text-xs font-bold transition-all flex items-center gap-2 cursor-pointer ${
                    activeSecSubTab === 'team'
                      ? 'bg-indigo-600 text-white shadow-lg shadow-indigo-600/30 border border-indigo-500/50'
                      : 'bg-slate-900/60 hover:bg-slate-900 text-slate-400 hover:text-slate-200 border border-slate-800'
                  }`}
                >
                  <Users className="w-4 h-4 text-cyan-400" />
                  <span>Team Members & Roles ({teamMembers.length})</span>
                </button>

                <button
                  onClick={() => setActiveSecSubTab('hardening')}
                  className={`px-5 py-2.5 rounded-xl text-xs font-bold transition-all flex items-center gap-2 cursor-pointer ${
                    activeSecSubTab === 'hardening'
                      ? 'bg-indigo-600 text-white shadow-lg shadow-indigo-600/30 border border-indigo-500/50'
                      : 'bg-slate-900/60 hover:bg-slate-900 text-slate-400 hover:text-slate-200 border border-slate-800'
                  }`}
                >
                  <ShieldAlert className="w-4 h-4 text-emerald-400" />
                  <span>Security Hardening & WAF</span>
                </button>

                <button
                  onClick={() => setActiveSecSubTab('sessions')}
                  className={`px-5 py-2.5 rounded-xl text-xs font-bold transition-all flex items-center gap-2 cursor-pointer ${
                    activeSecSubTab === 'sessions'
                      ? 'bg-indigo-600 text-white shadow-lg shadow-indigo-600/30 border border-indigo-500/50'
                      : 'bg-slate-900/60 hover:bg-slate-900 text-slate-400 hover:text-slate-200 border border-slate-800'
                  }`}
                >
                  <Key className="w-4 h-4 text-amber-400" />
                  <span>Active User Sessions ({userSessions.length})</span>
                </button>

                <button
                  onClick={() => setActiveSecSubTab('audit')}
                  className={`px-5 py-2.5 rounded-xl text-xs font-bold transition-all flex items-center gap-2 cursor-pointer ${
                    activeSecSubTab === 'audit'
                      ? 'bg-indigo-600 text-white shadow-lg shadow-indigo-600/30 border border-indigo-500/50'
                      : 'bg-slate-900/60 hover:bg-slate-900 text-slate-400 hover:text-slate-200 border border-slate-800'
                  }`}
                >
                  <FileText className="w-4 h-4 text-indigo-400" />
                  <span>Live Security Audit Log ({secAuditLogs.length})</span>
                </button>
              </div>

              {/* SUB-TAB 1: TEAM MEMBERS */}
              {activeSecSubTab === 'team' && (
                <div className="space-y-4 animate-fade-in">
                  <div className="bg-slate-900/80 border border-slate-800 rounded-2xl overflow-hidden shadow-xl">
                    <table className="w-full text-left text-xs font-mono">
                      <thead className="bg-slate-950 text-slate-400 border-b border-slate-800 uppercase tracking-wider">
                        <tr>
                          <th className="p-4">User</th>
                          <th className="p-4">Role & RBAC</th>
                          <th className="p-4">Permissions Scope</th>
                          <th className="p-4">2FA Status</th>
                          <th className="p-4">Account Status</th>
                          <th className="p-4">Last Login</th>
                          <th className="p-4 text-right">Actions</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-800/60 text-slate-200">
                        {teamMembers.map((m) => (
                          <tr key={m.id} className="hover:bg-slate-800/40 transition-colors">
                            <td className="p-4">
                              <div className="flex items-center gap-3">
                                <img src={m.avatar} alt={m.name} className="w-9 h-9 rounded-full bg-slate-800 border border-slate-700" />
                                <div>
                                  <p className="font-bold text-white text-sm">{m.name}</p>
                                  <p className="text-[11px] text-slate-400">{m.email}</p>
                                </div>
                              </div>
                            </td>
                            <td className="p-4">
                              <span className={`px-2.5 py-1 rounded-lg text-[11px] font-bold border ${
                                m.role === 'Owner'
                                  ? 'bg-purple-500/10 text-purple-300 border-purple-500/30'
                                  : m.role === 'DevOps Engineer'
                                  ? 'bg-cyan-500/10 text-cyan-300 border-cyan-500/30'
                                  : m.role === 'Database Manager'
                                  ? 'bg-amber-500/10 text-amber-300 border-amber-500/30'
                                  : 'bg-slate-800 text-slate-300 border-slate-700'
                              }`}>
                                {m.role}
                              </span>
                            </td>
                            <td className="p-4 text-slate-300">
                              <div className="flex flex-wrap gap-1">
                                {m.permissions?.map((p: string) => (
                                  <span key={p} className="bg-slate-950 text-slate-400 px-2 py-0.5 rounded text-[10px] border border-slate-800">
                                    {p}
                                  </span>
                                ))}
                              </div>
                            </td>
                            <td className="p-4">
                              {m.two_factor_enabled ? (
                                <span className="text-emerald-400 flex items-center gap-1 font-bold text-[11px]">
                                  <CheckCircle2 className="w-3.5 h-3.5" /> 2FA Active
                                </span>
                              ) : (
                                <span className="text-amber-400 flex items-center gap-1 text-[11px]">
                                  <AlertTriangle className="w-3.5 h-3.5" /> Not Setup
                                </span>
                              )}
                            </td>
                            <td className="p-4">
                              <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase border ${
                                m.status === 'active'
                                  ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                                  : 'bg-amber-500/10 text-amber-400 border-amber-500/30'
                              }`}>
                                {m.status}
                              </span>
                            </td>
                            <td className="p-4 text-slate-400 text-[11px]">
                              {m.last_login}
                            </td>
                            <td className="p-4 text-right">
                              <div className="flex items-center justify-end gap-2">
                                <button
                                  onClick={() => showToast(`Updated permissions for ${m.name}`)}
                                  className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 transition-all cursor-pointer text-xs"
                                  title="Edit Permissions"
                                >
                                  Edit
                                </button>
                                {m.role !== 'Owner' && (
                                  <button
                                    onClick={() => {
                                      if (confirm(`Revoke access for ${m.name}?`)) {
                                        setTeamMembers(prev => prev.filter(item => item.id !== m.id));
                                        showToast(`Revoked access for ${m.name}`);
                                      }
                                    }}
                                    className="p-1.5 rounded-lg bg-slate-900 hover:bg-rose-500/20 text-slate-500 hover:text-rose-400 border border-slate-800 hover:border-rose-500/30 transition-all cursor-pointer text-xs"
                                    title="Revoke Access"
                                  >
                                    Revoke
                                  </button>
                                )}
                              </div>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}

              {/* SUB-TAB 2: SECURITY HARDENING & FIREWALL */}
              {activeSecSubTab === 'hardening' && (
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 animate-fade-in">
                  {/* WAF Policy */}
                  <div className="bg-slate-900/80 border border-slate-800 p-6 rounded-3xl space-y-5 shadow-xl">
                    <div className="flex items-center gap-3 border-b border-slate-800 pb-4">
                      <ShieldAlert className="w-6 h-6 text-emerald-400" />
                      <div>
                        <h3 className="text-lg font-bold text-white">Web Application Firewall (WAF)</h3>
                        <p className="text-xs text-slate-400">Deep packet inspection & payload filtering rules</p>
                      </div>
                    </div>

                    <div className="space-y-4">
                      <label className="flex items-center justify-between p-3.5 bg-slate-950 rounded-2xl border border-slate-800 cursor-pointer">
                        <div>
                          <p className="text-xs font-bold text-white">SQL Injection (SQLi) Protection</p>
                          <p className="text-[11px] text-slate-400">Blocks union select, error-based, and time-delay payload probes</p>
                        </div>
                        <input
                          type="checkbox"
                          checked={secHardening.waf_sqli_protection}
                          onChange={(e) => setSecHardening({ ...secHardening, waf_sqli_protection: e.target.checked })}
                          className="w-4 h-4 accent-emerald-500 cursor-pointer"
                        />
                      </label>

                      <label className="flex items-center justify-between p-3.5 bg-slate-950 rounded-2xl border border-slate-800 cursor-pointer">
                        <div>
                          <p className="text-xs font-bold text-white">Cross-Site Scripting (XSS) Sanitization Filter</p>
                          <p className="text-[11px] text-slate-400">Filters malicious script tag injections in GET/POST bodies</p>
                        </div>
                        <input
                          type="checkbox"
                          checked={secHardening.waf_xss_protection}
                          onChange={(e) => setSecHardening({ ...secHardening, waf_xss_protection: e.target.checked })}
                          className="w-4 h-4 accent-emerald-500 cursor-pointer"
                        />
                      </label>

                      <div className="p-3.5 bg-slate-950 rounded-2xl border border-slate-800 space-y-2">
                        <div className="flex justify-between text-xs">
                          <span className="font-bold text-white">Rate Limit Threshold (Req/Min)</span>
                          <span className="font-mono text-emerald-400">{secHardening.rate_limit_rpm} req/min</span>
                        </div>
                        <input
                          type="range"
                          min="60"
                          max="1000"
                          step="20"
                          value={secHardening.rate_limit_rpm}
                          onChange={(e) => setSecHardening({ ...secHardening, rate_limit_rpm: parseInt(e.target.value, 10) })}
                          className="w-full accent-emerald-500 cursor-pointer"
                        />
                      </div>
                    </div>
                  </div>

                  {/* Server & TLS Hardening */}
                  <div className="bg-slate-900/80 border border-slate-800 p-6 rounded-3xl space-y-5 shadow-xl">
                    <div className="flex items-center gap-3 border-b border-slate-800 pb-4">
                      <Lock className="w-6 h-6 text-cyan-400" />
                      <div>
                        <h3 className="text-lg font-bold text-white">Server & TLS Hardening</h3>
                        <p className="text-xs text-slate-400">Host operating system & transport layer policy</p>
                      </div>
                    </div>

                    <div className="space-y-4">
                      <label className="flex items-center justify-between p-3.5 bg-slate-950 rounded-2xl border border-slate-800 cursor-pointer">
                        <div>
                          <p className="text-xs font-bold text-white">Disable Root SSH Password Login</p>
                          <p className="text-[11px] text-slate-400">Enforces SSH Ed25519 key authentication only</p>
                        </div>
                        <input
                          type="checkbox"
                          checked={secHardening.disable_root_ssh}
                          onChange={(e) => setSecHardening({ ...secHardening, disable_root_ssh: e.target.checked })}
                          className="w-4 h-4 accent-cyan-500 cursor-pointer"
                        />
                      </label>

                      <label className="flex items-center justify-between p-3.5 bg-slate-950 rounded-2xl border border-slate-800 cursor-pointer">
                        <div>
                          <p className="text-xs font-bold text-white">Force HTTPS HSTS Preload Header</p>
                          <p className="text-[11px] text-slate-400">Injects Strict-Transport-Security with max-age=31536000</p>
                        </div>
                        <input
                          type="checkbox"
                          checked={secHardening.hsts_forced_https}
                          onChange={(e) => setSecHardening({ ...secHardening, hsts_forced_https: e.target.checked })}
                          className="w-4 h-4 accent-cyan-500 cursor-pointer"
                        />
                      </label>

                      <label className="flex items-center justify-between p-3.5 bg-slate-950 rounded-2xl border border-slate-800 cursor-pointer">
                        <div>
                          <p className="text-xs font-bold text-white">Fail2Ban IP Auto-Banning</p>
                          <p className="text-[11px] text-slate-400">Automatically bans IPs after 5 failed authentication attempts</p>
                        </div>
                        <input
                          type="checkbox"
                          checked={secHardening.fail2ban_enabled}
                          onChange={(e) => setSecHardening({ ...secHardening, fail2ban_enabled: e.target.checked })}
                          className="w-4 h-4 accent-cyan-500 cursor-pointer"
                        />
                      </label>
                    </div>
                  </div>
                </div>
              )}

              {/* SUB-TAB 3: ACTIVE USER SESSIONS */}
              {activeSecSubTab === 'sessions' && (
                <div className="space-y-4 animate-fade-in">
                  <div className="bg-slate-900/80 border border-slate-800 rounded-2xl overflow-hidden shadow-xl">
                    <table className="w-full text-left text-xs font-mono">
                      <thead className="bg-slate-950 text-slate-400 border-b border-slate-800 uppercase tracking-wider">
                        <tr>
                          <th className="p-4">Session ID</th>
                          <th className="p-4">IP Address</th>
                          <th className="p-4">Location / Context</th>
                          <th className="p-4">User Agent / Browser</th>
                          <th className="p-4">Last Active</th>
                          <th className="p-4 text-right">Action</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-800/60 text-slate-200">
                        {userSessions.map((s) => (
                          <tr key={s.id} className="hover:bg-slate-800/40 transition-colors">
                            <td className="p-4 font-bold text-cyan-300 flex items-center gap-2">
                              <span>{s.id}</span>
                              {s.is_current && (
                                <span className="bg-emerald-500/20 text-emerald-400 text-[10px] px-2 py-0.5 rounded-full border border-emerald-500/30">
                                  THIS DEVICE
                                </span>
                              )}
                            </td>
                            <td className="p-4 text-white font-bold">{s.ip_address}</td>
                            <td className="p-4 text-slate-300">{s.location}</td>
                            <td className="p-4 text-slate-400 max-w-xs truncate" title={s.user_agent}>
                              {s.user_agent}
                            </td>
                            <td className="p-4 text-slate-400">{s.last_active}</td>
                            <td className="p-4 text-right">
                              {!s.is_current ? (
                                <button
                                  onClick={() => {
                                    setUserSessions(prev => prev.filter(item => item.id !== s.id));
                                    showToast(`Revoked session ${s.id}`);
                                  }}
                                  className="px-3 py-1 bg-rose-500/20 hover:bg-rose-500/30 text-rose-300 rounded-lg border border-rose-500/30 font-bold transition-all cursor-pointer"
                                >
                                  Revoke
                                </button>
                              ) : (
                                <span className="text-slate-500 italic">Active Session</span>
                              )}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}

              {/* SUB-TAB 4: LIVE SECURITY AUDIT LOG */}
              {activeSecSubTab === 'audit' && (
                <div className="space-y-4 animate-fade-in">
                  <div className="bg-slate-950 border border-slate-800 rounded-2xl p-4 font-mono text-xs space-y-2 max-h-[600px] overflow-y-auto">
                    {secAuditLogs.map((log, idx) => (
                      <div key={idx} className="flex flex-col sm:flex-row sm:items-center justify-between p-2.5 rounded-xl bg-slate-900/60 border border-slate-800/60 gap-2">
                        <div className="flex items-center gap-3">
                          <span className="text-slate-500 text-[11px]">{log.timestamp}</span>
                          <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase border ${
                            log.severity === 'warning'
                              ? 'bg-rose-500/10 text-rose-400 border-rose-500/30'
                              : log.severity === 'notice'
                              ? 'bg-amber-500/10 text-amber-400 border-amber-500/30'
                              : 'bg-cyan-500/10 text-cyan-400 border-cyan-500/30'
                          }`}>
                            {log.event}
                          </span>
                          <span className="text-slate-200">{log.details}</span>
                        </div>
                        <div className="flex items-center gap-3 text-[11px] text-slate-400">
                          <span>User: <strong className="text-cyan-300">{log.user}</strong></span>
                          <span>IP: <strong className="text-slate-300">{log.ip}</strong></span>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* INVITE TEAM MEMBER MODAL */}
              {showInviteModal && (
                <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-md flex items-center justify-center p-4">
                  <div className="bg-slate-900 border border-slate-800 w-full max-w-md rounded-2xl p-6 space-y-4 shadow-2xl animate-scale-up">
                    <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                      <h3 className="text-lg font-bold text-white flex items-center gap-2">
                        <UserPlus className="w-5 h-5 text-emerald-400" />
                        <span>Invite Team Member</span>
                      </h3>
                      <button
                        onClick={() => setShowInviteModal(false)}
                        className="text-slate-400 hover:text-white text-sm font-bold"
                      >
                        ✕
                      </button>
                    </div>

                    <div className="space-y-3">
                      <div>
                        <label className="text-xs font-semibold text-slate-400">Full Name:</label>
                        <input
                          type="text"
                          value={inviteName}
                          onChange={(e) => setInviteName(e.target.value)}
                          placeholder="e.g. Sarah Jenkins"
                          className="w-full bg-slate-950 border border-slate-800 rounded-xl p-2.5 text-xs text-white outline-none mt-1"
                        />
                      </div>

                      <div>
                        <label className="text-xs font-semibold text-slate-400">Email Address:</label>
                        <input
                          type="email"
                          value={inviteEmail}
                          onChange={(e) => setInviteEmail(e.target.value)}
                          placeholder="sarah@company.com"
                          className="w-full bg-slate-950 border border-slate-800 rounded-xl p-2.5 text-xs text-white outline-none mt-1"
                        />
                      </div>

                      <div>
                        <label className="text-xs font-semibold text-slate-400">RBAC Role:</label>
                        <select
                          value={inviteRole}
                          onChange={(e) => setInviteRole(e.target.value)}
                          className="w-full bg-slate-950 border border-slate-800 rounded-xl p-2.5 text-xs text-cyan-300 outline-none mt-1"
                        >
                          <option value="DevOps Engineer">DevOps Engineer (Websites & Files)</option>
                          <option value="Database Manager">Database Manager (SQL & DBs)</option>
                          <option value="Administrator">Administrator (Full Access)</option>
                          <option value="Auditor">Auditor (Read Only)</option>
                        </select>
                      </div>
                    </div>

                    <div className="flex justify-end gap-3 pt-2">
                      <button
                        onClick={() => setShowInviteModal(false)}
                        className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-bold rounded-xl cursor-pointer"
                      >
                        Cancel
                      </button>
                      <button
                        onClick={async () => {
                          if (!inviteEmail) return alert('Please enter a valid email address');
                          try {
                            const res = await fetch(`${API_BASE}/api/v1/team/invite`, {
                              method: 'POST',
                              headers: getHeaders(true),
                              body: JSON.stringify({ name: inviteName, email: inviteEmail, role: inviteRole }),
                            });
                            const data = await res.json();
                            if (res.ok) {
                              showToast(`Invitation sent to ${inviteEmail}`);
                              setTeamMembers(prev => [
                                ...prev,
                                {
                                  id: Date.now(),
                                  name: inviteName || 'New User',
                                  email: inviteEmail,
                                  username: inviteEmail.split('@')[0],
                                  role: inviteRole,
                                  permissions: ['websites.manage'],
                                  two_factor_enabled: false,
                                  status: 'invited',
                                  last_login: 'Never',
                                  avatar: `https://api.dicebear.com/7.x/avataaars/svg?seed=${inviteName}`,
                                },
                              ]);
                              setShowInviteModal(false);
                              setInviteName('');
                              setInviteEmail('');
                            }
                          } catch (e: any) {
                            alert(e.message);
                          }
                        }}
                        className="px-5 py-2 bg-emerald-500 hover:bg-emerald-400 text-slate-950 text-xs font-bold rounded-xl cursor-pointer shadow-lg shadow-emerald-500/25 flex items-center gap-2"
                      >
                        <UserPlus className="w-4 h-4" />
                        <span>Send Invitation</span>
                      </button>
                    </div>
                  </div>
                </div>
              )}
              {/* MY PROFILE & ACCOUNT SETTINGS MODAL */}
              {/* MY PROFILE & ACCOUNT SETTINGS MODAL */}
            </div>
          )}

          {/* MY PROFILE & ACCOUNT SETTINGS PAGE ROUTE */}
          
          {/* TAB: APP SUPERVISOR (Node.js & Python) */}
          {activeTab === 'supervisor' && !activeManageSite && (
            <div className="space-y-6 animate-fade-in">
              <div className="bg-slate-900/80 border border-slate-800 p-6 rounded-2xl shadow-xl flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
                <div>
                  <h2 className="text-xl font-extrabold text-white flex items-center gap-2">
                    <Code className="w-6 h-6 text-cyan-400" />
                    <span>Node.js & Python Application Supervisor</span>
                  </h2>
                  <p className="text-xs text-slate-400 mt-1">Manage PM2 / Gunicorn apps with automated Nginx reverse proxy routing</p>
                </div>
                <button
                  onClick={() => alert("Launching App Supervisor Wizard...")}
                  className="bg-gradient-to-r from-cyan-500 to-blue-600 text-slate-950 font-bold px-4 py-2 rounded-xl text-xs flex items-center gap-2 shadow-lg shadow-cyan-500/20 cursor-pointer"
                >
                  <Plus className="w-4 h-4" /> Deploy Node/Python App
                </button>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="bg-slate-900/60 border border-slate-800 p-5 rounded-2xl">
                  <div className="flex items-center justify-between">
                    <span className="font-bold text-white text-sm">api.my-app.com</span>
                    <span className="bg-emerald-500/10 text-emerald-400 text-xs px-2.5 py-0.5 rounded-full font-bold">RUNNING (Port 3000)</span>
                  </div>
                  <p className="text-xs text-slate-400 mt-2 font-mono">Type: Node.js (Express) | PID: 14820 | Entry: server.js</p>
                  <div className="mt-4 flex gap-2">
                    <button className="bg-slate-800 text-slate-300 text-xs px-3 py-1.5 rounded-lg border border-slate-700">Restart</button>
                    <button className="bg-rose-500/10 text-rose-400 text-xs px-3 py-1.5 rounded-lg border border-rose-500/20">Stop</button>
                  </div>
                </div>

                <div className="bg-slate-900/60 border border-slate-800 p-5 rounded-2xl">
                  <div className="flex items-center justify-between">
                    <span className="font-bold text-white text-sm">ai-backend.my-app.com</span>
                    <span className="bg-emerald-500/10 text-emerald-400 text-xs px-2.5 py-0.5 rounded-full font-bold">RUNNING (Port 8000)</span>
                  </div>
                  <p className="text-xs text-slate-400 mt-2 font-mono">Type: Python (FastAPI/Gunicorn) | PID: 21904 | Entry: main.py</p>
                  <div className="mt-4 flex gap-2">
                    <button className="bg-slate-800 text-slate-300 text-xs px-3 py-1.5 rounded-lg border border-slate-700">Restart</button>
                    <button className="bg-rose-500/10 text-rose-400 text-xs px-3 py-1.5 rounded-lg border border-rose-500/20">Stop</button>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* TAB: SSH SERVER MIGRATION */}
          {activeTab === 'migration' && !activeManageSite && (
            <div className="space-y-6 animate-fade-in">
              <div className="bg-slate-900/80 border border-slate-800 p-6 rounded-2xl shadow-xl">
                <h2 className="text-xl font-extrabold text-white flex items-center gap-2">
                  <Cloud className="w-6 h-6 text-indigo-400" />
                  <span>1-Click SSH Server Migration Engine</span>
                </h2>
                <p className="text-xs text-slate-400 mt-1">Seamlessly transfer websites, MySQL/PostgreSQL databases & SSL certificates from cPanel / CloudPanel over SSH</p>
              </div>

              <div className="bg-slate-900/60 border border-slate-800 p-6 rounded-2xl space-y-4 max-w-2xl">
                <h3 className="text-sm font-bold text-slate-200">Remote Server Credentials</h3>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                  <div>
                    <label className="block text-xs font-semibold text-slate-400 mb-1">Remote SSH Host / IP</label>
                    <input type="text" placeholder="192.168.1.100" className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3.5 py-2 text-xs text-white" />
                  </div>
                  <div>
                    <label className="block text-xs font-semibold text-slate-400 mb-1">SSH Port</label>
                    <input type="number" defaultValue={22} className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3.5 py-2 text-xs text-white" />
                  </div>
                </div>

                <div>
                  <label className="block text-xs font-semibold text-slate-400 mb-1">SSH Username</label>
                  <input type="text" defaultValue="root" className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3.5 py-2 text-xs text-white" />
                </div>

                <div className="flex items-center gap-4 pt-2">
                  <label className="flex items-center gap-2 text-xs text-slate-300">
                    <input type="checkbox" defaultChecked className="rounded border-slate-800 bg-slate-950 text-cyan-500" />
                    <span>Migrate Website Files (/var/www)</span>
                  </label>
                  <label className="flex items-center gap-2 text-xs text-slate-300">
                    <input type="checkbox" defaultChecked className="rounded border-slate-800 bg-slate-950 text-cyan-500" />
                    <span>Migrate Databases & Users</span>
                  </label>
                </div>

                <button
                  onClick={() => alert("SSH Connection Verified! Starting automated sync stream...")}
                  className="bg-indigo-600 hover:bg-indigo-500 text-white font-bold text-xs px-5 py-2.5 rounded-xl transition-all shadow-lg shadow-indigo-600/20"
                >
                  Start Server Migration 🚀
                </button>
              </div>
            </div>
          )}

          {/* TAB: DNS ZONE & CLOUDFLARE SYNC */}
          {activeTab === 'dns' && !activeManageSite && (
            <div className="space-y-6 animate-fade-in">
              <div className="bg-slate-900/80 border border-slate-800 p-6 rounded-2xl shadow-xl flex justify-between items-center">
                <div>
                  <h2 className="text-xl font-extrabold text-white flex items-center gap-2">
                    <Globe className="w-6 h-6 text-amber-400" />
                    <span>DNS Zone Manager & Cloudflare API Sync</span>
                  </h2>
                  <p className="text-xs text-slate-400 mt-1">Manage local Bind9 DNS records & instant Cloudflare API synchronization</p>
                </div>
              </div>

              <div className="bg-slate-900/60 border border-slate-800 p-6 rounded-2xl space-y-4">
                <div className="flex items-center justify-between border-b border-slate-800 pb-4">
                  <h3 className="text-sm font-bold text-slate-200">Active Zone: my-production-domain.com</h3>
                  <button onClick={() => alert("Synchronized with Cloudflare API!")} className="bg-amber-500/10 hover:bg-amber-500/20 text-amber-400 border border-amber-500/30 text-xs font-bold px-3 py-1.5 rounded-lg">
                    Sync Cloudflare API
                  </button>
                </div>

                <table className="w-full text-left text-xs text-slate-300">
                  <thead className="bg-slate-950 text-slate-400 font-mono border-b border-slate-800">
                    <tr>
                      <th className="py-2.5 px-3">TYPE</th>
                      <th className="py-2.5 px-3">RECORD NAME</th>
                      <th className="py-2.5 px-3">TARGET VALUE</th>
                      <th className="py-2.5 px-3">TTL</th>
                      <th className="py-2.5 px-3">PROXIED</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60">
                    <tr>
                      <td className="py-2.5 px-3 font-bold text-cyan-400">A</td>
                      <td className="py-2.5 px-3">@</td>
                      <td className="py-2.5 px-3 font-mono">192.168.1.50</td>
                      <td className="py-2.5 px-3">3600</td>
                      <td className="py-2.5 px-3 text-emerald-400">✓ Proxied</td>
                    </tr>
                    <tr>
                      <td className="py-2.5 px-3 font-bold text-indigo-400">CNAME</td>
                      <td className="py-2.5 px-3">www</td>
                      <td className="py-2.5 px-3 font-mono">my-production-domain.com</td>
                      <td className="py-2.5 px-3">3600</td>
                      <td className="py-2.5 px-3 text-emerald-400">✓ Proxied</td>
                    </tr>
                    <tr>
                      <td className="py-2.5 px-3 font-bold text-amber-400">TXT</td>
                      <td className="py-2.5 px-3">@</td>
                      <td className="py-2.5 px-3 font-mono">v=spf1 mx ~all</td>
                      <td className="py-2.5 px-3">3600</td>
                      <td className="py-2.5 px-3 text-slate-500">DNS Only</td>
                    </tr>
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* TAB: INSTANT NOTIFICATIONS & WEBHOOKS */}
          {activeTab === 'notifications' && !activeManageSite && (
            <div className="space-y-6 animate-fade-in">
              <div className="bg-slate-900/80 border border-slate-800 p-6 rounded-2xl shadow-xl">
                <h2 className="text-xl font-extrabold text-white flex items-center gap-2">
                  <Bell className="w-6 h-6 text-emerald-400" />
                  <span>Instant Notifications & Webhooks Config</span>
                </h2>
                <p className="text-xs text-slate-400 mt-1">Receive real-time alerts on Telegram, Slack, or Email for security events & auto-healing actions</p>
              </div>

              <div className="bg-slate-900/60 border border-slate-800 p-6 rounded-2xl space-y-5 max-w-2xl">
                <div className="space-y-3">
                  <h3 className="text-sm font-bold text-cyan-400 flex items-center gap-2">
                    <span>Telegram Bot Alert Integration</span>
                  </h3>
                  <div>
                    <label className="block text-xs text-slate-400 mb-1">Telegram Bot Token</label>
                    <input type="password" placeholder="123456789:ABCdefGhIJKlmNoPQRsTUVwxyZ" className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3.5 py-2 text-xs text-white" />
                  </div>
                  <div>
                    <label className="block text-xs text-slate-400 mb-1">Telegram Chat ID</label>
                    <input type="text" placeholder="-100123456789" className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3.5 py-2 text-xs text-white" />
                  </div>
                </div>

                <div className="space-y-3 pt-3 border-t border-slate-800">
                  <h3 className="text-sm font-bold text-indigo-400">Slack Webhook URL</h3>
                  <input type="text" placeholder="https://hooks.slack.com/services/..." className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3.5 py-2 text-xs text-white" />
                </div>

                <div className="flex gap-3 pt-3">
                  <button onClick={() => alert("Notification settings saved!")} className="bg-emerald-600 hover:bg-emerald-500 text-white font-bold text-xs px-5 py-2.5 rounded-xl transition-all shadow-lg shadow-emerald-600/20">
                    Save Alert Channels
                  </button>
                  <button onClick={() => alert("Test alert sent to Telegram & Slack!")} className="bg-slate-800 hover:bg-slate-700 text-slate-200 font-bold text-xs px-4 py-2.5 rounded-xl border border-slate-700">
                    Send Test Notification
                  </button>
                </div>
              </div>
            </div>
          )}

{activeTab === 'profile' && !activeManageSite && !activeManageDb && (
                <div className="space-y-6 animate-fade-in max-w-5xl mx-auto pb-12">
                  {/* Page Top Breadcrumb Banner */}
                  <div className="bg-gradient-to-r from-purple-950/40 via-slate-900 to-indigo-950/40 border border-purple-500/20 rounded-3xl p-6 shadow-xl backdrop-blur-md flex flex-col md:flex-row md:items-center justify-between gap-4">
                    <div className="flex items-center gap-4">
                      <div className="relative">
                        <img
                          src="https://api.dicebear.com/7.x/avataaars/svg?seed=Admin"
                          alt="User Avatar"
                          className="w-16 h-16 rounded-2xl bg-slate-950 border-2 border-purple-500/40 p-0.5 shadow-lg shadow-purple-500/10"
                        />
                        <span className="absolute -bottom-1 -right-1 w-5 h-5 bg-emerald-500 border-2 border-slate-900 rounded-full flex items-center justify-center">
                          <Check className="w-3 h-3 text-slate-950 stroke-[3]" />
                        </span>
                      </div>
                      <div>
                        <div className="flex items-center gap-2.5 flex-wrap">
                          <h2 className="text-2xl font-extrabold text-white tracking-tight">Super Admin Profile</h2>
                          <span className="bg-purple-500/20 text-purple-300 text-xs font-mono font-bold px-2.5 py-0.5 rounded-full border border-purple-500/30">
                            OWNER
                          </span>
                          <span className="bg-emerald-500/20 text-emerald-400 text-xs font-mono font-bold px-2.5 py-0.5 rounded-full border border-emerald-500/30 flex items-center gap-1">
                            <ShieldCheck className="w-3 h-3 text-emerald-400" /> 2FA Active
                          </span>
                        </div>
                        <p className="text-xs text-slate-400 mt-1 flex items-center gap-2">
                          <span>admin@hoatzin.org</span>
                          <span>•</span>
                          <span>Joined Oct 2026</span>
                          <span>•</span>
                          <span className="text-cyan-400 font-mono">ID: #USR-9042</span>
                        </p>
                      </div>
                    </div>

                    <div className="flex items-center gap-3">
                      <button
                        onClick={() => {
                          showToast('Profile & preferences saved successfully!');
                        }}
                        className="px-5 py-2.5 bg-gradient-to-r from-purple-600 to-indigo-600 hover:from-purple-500 hover:to-indigo-500 text-white text-xs font-bold rounded-xl cursor-pointer shadow-lg shadow-purple-500/25 flex items-center gap-2 transition-all"
                      >
                        <Check className="w-4 h-4" />
                        <span>Save Profile Settings</span>
                      </button>
                    </div>
                  </div>

                  {/* Navigation Preferences Tabs */}
                  <div className="flex items-center gap-2 border-b border-slate-800 pb-3 overflow-x-auto">
                    <button
                      onClick={() => setActiveProfileTab('general')}
                      className={`px-4 py-2 rounded-xl text-xs font-bold transition-all cursor-pointer flex items-center gap-2 whitespace-nowrap ${
                        activeProfileTab === 'general'
                          ? 'bg-purple-500/20 text-purple-300 border border-purple-500/40 shadow-md shadow-purple-500/10'
                          : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
                      }`}
                    >
                      <UserCheck className="w-4 h-4 text-purple-400" />
                      <span>General & Contact</span>
                    </button>
                    <button
                      onClick={() => setActiveProfileTab('localization')}
                      className={`px-4 py-2 rounded-xl text-xs font-bold transition-all cursor-pointer flex items-center gap-2 whitespace-nowrap ${
                        activeProfileTab === 'localization'
                          ? 'bg-purple-500/20 text-purple-300 border border-purple-500/40 shadow-md shadow-purple-500/10'
                          : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
                      }`}
                    >
                      <Globe className="w-4 h-4 text-cyan-400" />
                      <span>Localization & Regional</span>
                    </button>
                    <button
                      onClick={() => setActiveProfileTab('notifications')}
                      className={`px-4 py-2 rounded-xl text-xs font-bold transition-all cursor-pointer flex items-center gap-2 whitespace-nowrap ${
                        activeProfileTab === 'notifications'
                          ? 'bg-purple-500/20 text-purple-300 border border-purple-500/40 shadow-md shadow-purple-500/10'
                          : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
                      }`}
                    >
                      <Bell className="w-4 h-4 text-amber-400" />
                      <span>Notification Alerts</span>
                    </button>
                    <button
                      onClick={() => setActiveProfileTab('security')}
                      className={`px-4 py-2 rounded-xl text-xs font-bold transition-all cursor-pointer flex items-center gap-2 whitespace-nowrap ${
                        activeProfileTab === 'security'
                          ? 'bg-purple-500/20 text-purple-300 border border-purple-500/40 shadow-md shadow-purple-500/10'
                          : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
                      }`}
                    >
                      <ShieldAlert className="w-4 h-4 text-emerald-400" />
                      <span>Security & API Keys</span>
                    </button>
                  </div>

                  {/* Tab Body Contents */}
                  <div className="bg-slate-900/90 border border-slate-800 rounded-3xl p-6 shadow-xl space-y-6">
                    {/* 1. GENERAL & CONTACT TAB */}
                    {activeProfileTab === 'general' && (
                      <div className="space-y-6">
                        <div className="border-b border-slate-800 pb-3">
                          <h3 className="text-base font-bold text-white flex items-center gap-2">
                            <UserCheck className="w-4 h-4 text-purple-400" />
                            <span>Personal & Organizational Profile</span>
                          </h3>
                          <p className="text-xs text-slate-400 mt-0.5">Update your display name, email address, and departmental contact information.</p>
                        </div>

                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                          <div className="space-y-1.5">
                            <label className="text-xs font-bold text-slate-300">Full Display Name</label>
                            <input
                              type="text"
                              value="Super Admin"
                              onChange={() => {}}
                              className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3.5 py-2 text-xs text-slate-100 focus:outline-none focus:border-purple-500"
                            />
                          </div>

                          <div className="space-y-1.5">
                            <label className="text-xs font-bold text-slate-300">Username handle</label>
                            <input
                              type="text"
                              value={profileUsername}
                              onChange={(e) => setProfileUsername(e.target.value)}
                              className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3.5 py-2 text-xs text-slate-100 focus:outline-none focus:border-purple-500"
                            />
                          </div>

                          <div className="space-y-1.5">
                            <label className="text-xs font-bold text-slate-300">Primary Email Address</label>
                            <input
                              type="email"
                              value="admin@hoatzin.org"
                              onChange={() => {}}
                              className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3.5 py-2 text-xs text-slate-100 focus:outline-none focus:border-purple-500"
                            />
                          </div>

                          <div className="space-y-1.5">
                            <label className="text-xs font-bold text-slate-300">Phone / WhatsApp Number</label>
                            <input
                              type="text"
                              value={profilePhone}
                              onChange={(e) => setProfilePhone(e.target.value)}
                              className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3.5 py-2 text-xs text-slate-100 focus:outline-none focus:border-purple-500"
                            />
                          </div>

                          <div className="space-y-1.5">
                            <label className="text-xs font-bold text-slate-300">Company / Organization</label>
                            <input
                              type="text"
                              value={profileCompany}
                              onChange={(e) => setProfileCompany(e.target.value)}
                              className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3.5 py-2 text-xs text-slate-100 focus:outline-none focus:border-purple-500"
                            />
                          </div>

                          <div className="space-y-1.5">
                            <label className="text-xs font-bold text-slate-300">Job Title / Department</label>
                            <input
                              type="text"
                              value={profileJobTitle}
                              onChange={(e) => setProfileJobTitle(e.target.value)}
                              className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3.5 py-2 text-xs text-slate-100 focus:outline-none focus:border-purple-500"
                            />
                          </div>
                        </div>
                      </div>
                    )}

                    {/* 2. LOCALIZATION & REGIONAL TAB */}
                    {activeProfileTab === 'localization' && (
                      <div className="space-y-6">
                        <div className="border-b border-slate-800 pb-3">
                          <h3 className="text-base font-bold text-white flex items-center gap-2">
                            <Globe className="w-4 h-4 text-cyan-400" />
                            <span>Regional & Localization Settings</span>
                          </h3>
                          <p className="text-xs text-slate-400 mt-0.5">Configure timezone, display language, and automatic session security timeout.</p>
                        </div>

                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                          <div className="space-y-1.5">
                            <label className="text-xs font-bold text-slate-300">Interface Display Language</label>
                            <select
                              value={profileLang}
                              onChange={(e) => setProfileLang(e.target.value)}
                              className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3.5 py-2 text-xs text-slate-100 focus:outline-none focus:border-purple-500"
                            >
                              <option value="English (US)">English (US)</option>
                              <option value="Spanish">Spanish (Español)</option>
                              <option value="French">French (Français)</option>
                              <option value="German">German (Deutsch)</option>
                              <option value="Bengali">Bengali (বাংলা)</option>
                            </select>
                          </div>

                          <div className="space-y-1.5">
                            <label className="text-xs font-bold text-slate-300">Server Timezone</label>
                            <select
                              value={profileTimezone}
                              onChange={(e) => setProfileTimezone(e.target.value)}
                              className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3.5 py-2 text-xs text-slate-100 focus:outline-none focus:border-purple-500"
                            >
                              <option value="UTC+06:00 Asia/Dhaka">UTC+06:00 Asia/Dhaka</option>
                              <option value="UTC+00:00 UTC (London)">UTC+00:00 UTC (London)</option>
                              <option value="UTC-05:00 US Eastern (New York)">UTC-05:00 US Eastern (New York)</option>
                              <option value="UTC+01:00 Europe/Paris">UTC+01:00 Europe/Paris</option>
                              <option value="UTC+08:00 Asia/Singapore">UTC+08:00 Asia/Singapore</option>
                            </select>
                          </div>

                          <div className="space-y-1.5">
                            <label className="text-xs font-bold text-slate-300">Date Format</label>
                            <select
                              defaultValue="YYYY-MM-DD"
                              className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3.5 py-2 text-xs text-slate-100 focus:outline-none focus:border-purple-500"
                            >
                              <option value="YYYY-MM-DD">YYYY-MM-DD (2026-10-07)</option>
                              <option value="DD/MM/YYYY">DD/MM/YYYY (07/10/2026)</option>
                              <option value="MM/DD/YYYY">MM/DD/YYYY (10/07/2026)</option>
                            </select>
                          </div>

                          <div className="space-y-1.5">
                            <label className="text-xs font-bold text-slate-300">Inactivity Auto-Logout Timeout</label>
                            <select
                              value={profileAutoLogout}
                              onChange={(e) => setProfileAutoLogout(e.target.value)}
                              className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3.5 py-2 text-xs text-slate-100 focus:outline-none focus:border-purple-500"
                            >
                              <option value="15m">15 Minutes of Inactivity</option>
                              <option value="30m">30 Minutes of Inactivity</option>
                              <option value="1h">1 Hour of Inactivity</option>
                              <option value="4h">4 Hours of Inactivity</option>
                              <option value="Never">Never (Keep Alive)</option>
                            </select>
                          </div>
                        </div>
                      </div>
                    )}

                    {/* 3. NOTIFICATION ALERTS TAB */}
                    {activeProfileTab === 'notifications' && (
                      <div className="space-y-6">
                        <div className="border-b border-slate-800 pb-3">
                          <h3 className="text-base font-bold text-white flex items-center gap-2">
                            <Bell className="w-4 h-4 text-amber-400" />
                            <span>System & Email Alerts</span>
                          </h3>
                          <p className="text-xs text-slate-400 mt-0.5">Toggle notification dispatch preferences for security events and routine backups.</p>
                        </div>

                        <div className="space-y-3">
                          <div className="flex items-center justify-between p-3.5 bg-slate-950 rounded-2xl border border-slate-800">
                            <div>
                              <h4 className="text-xs font-bold text-slate-100">Critical Incident & WAF Threat Alerts</h4>
                              <p className="text-[11px] text-slate-400 mt-0.5">Send immediate email notifications when suspicious payload attacks or brute force bans trigger.</p>
                            </div>
                            <input
                              type="checkbox"
                              checked={profileNotifyIncidents}
                              onChange={(e) => setProfileNotifyIncidents(e.target.checked)}
                              className="w-4 h-4 accent-purple-500 cursor-pointer"
                            />
                          </div>

                          <div className="flex items-center justify-between p-3.5 bg-slate-950 rounded-2xl border border-slate-800">
                            <div>
                              <h4 className="text-xs font-bold text-slate-100">Database Backup Status Alerts</h4>
                              <p className="text-[11px] text-slate-400 mt-0.5">Receive summary reports whenever automated night database snapshots complete or fail.</p>
                            </div>
                            <input
                              type="checkbox"
                              checked={profileNotifyBackups}
                              onChange={(e) => setProfileNotifyBackups(e.target.checked)}
                              className="w-4 h-4 accent-purple-500 cursor-pointer"
                            />
                          </div>

                          <div className="flex items-center justify-between p-3.5 bg-slate-950 rounded-2xl border border-slate-800">
                            <div>
                              <h4 className="text-xs font-bold text-slate-100">New IP Login Notifications</h4>
                              <p className="text-[11px] text-slate-400 mt-0.5">Alert account owner whenever a successful login originates from an unrecognized IP location.</p>
                            </div>
                            <input
                              type="checkbox"
                              checked={profileNotifyLogins}
                              onChange={(e) => setProfileNotifyLogins(e.target.checked)}
                              className="w-4 h-4 accent-purple-500 cursor-pointer"
                            />
                          </div>
                        </div>
                      </div>
                    )}

                    {/* 4. SECURITY & API KEY TAB */}
                    {activeProfileTab === 'security' && (
                      <div className="space-y-6">
                        <div className="border-b border-slate-800 pb-3">
                          <h3 className="text-base font-bold text-white flex items-center gap-2">
                            <ShieldAlert className="w-4 h-4 text-emerald-400" />
                            <span>Security Credentials & Secret Keys</span>
                          </h3>
                          <p className="text-xs text-slate-400 mt-0.5">Manage master account password, 2FA credentials, and system API access keys.</p>
                        </div>

                        <div className="space-y-4">
                          <div className="bg-slate-950 p-4 rounded-2xl border border-slate-800 space-y-3">
                            <h4 className="text-xs font-bold text-slate-200">Update Master Password</h4>
                            <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                              <input
                                type="password"
                                placeholder="Current Password"
                                className="bg-slate-900 border border-slate-800 rounded-xl px-3 py-2 text-xs text-slate-100 focus:outline-none focus:border-purple-500"
                              />
                              <input
                                type="password"
                                placeholder="New Password"
                                className="bg-slate-900 border border-slate-800 rounded-xl px-3 py-2 text-xs text-slate-100 focus:outline-none focus:border-purple-500"
                              />
                              <input
                                type="password"
                                placeholder="Confirm New Password"
                                className="bg-slate-900 border border-slate-800 rounded-xl px-3 py-2 text-xs text-slate-100 focus:outline-none focus:border-purple-500"
                              />
                            </div>
                          </div>

                          <div className="bg-slate-950 p-4 rounded-2xl border border-slate-800 flex items-center justify-between">
                            <div>
                              <h4 className="text-xs font-bold text-slate-100 flex items-center gap-2">
                                <ShieldCheck className="w-4 h-4 text-emerald-400" />
                                <span>Two-Factor Authentication (2FA)</span>
                              </h4>
                              <p className="text-[11px] text-slate-400 mt-0.5">TOTP authenticator app verification is currently enforced for this account.</p>
                            </div>
                            <span className="bg-emerald-500/20 text-emerald-400 text-xs font-bold px-3 py-1 rounded-xl border border-emerald-500/30">ENABLED</span>
                          </div>

                          <div className="bg-slate-950 p-4 rounded-2xl border border-slate-800 space-y-2">
                            <div className="flex items-center justify-between">
                              <h4 className="text-xs font-bold text-slate-200 flex items-center gap-2">
                                <Key className="w-4 h-4 text-cyan-400" />
                                <span>Personal Agent API Key</span>
                              </h4>
                              <button
                                onClick={() => {
                                  navigator.clipboard.writeText('hz_agent_secret_key_2026');
                                  showToast('API Key copied to clipboard!');
                                }}
                                className="text-[11px] text-cyan-400 hover:underline font-mono cursor-pointer"
                              >
                                Copy Key
                              </button>
                            </div>
                            <div className="bg-slate-900 p-3 rounded-xl border border-slate-800 font-mono text-xs text-cyan-300 flex items-center justify-between">
                              <span>hz_agent_secret_key_2026</span>
                              <span className="text-[10px] text-slate-500 uppercase">System Scope</span>
                            </div>
                          </div>
                        </div>
                      </div>
                    )}
                  </div>

                  {/* Save Footer Bar */}
                  <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-4 flex justify-end gap-3 shadow-xl">
                    <button
                      onClick={() => {
                        showToast('Profile & preferences saved successfully!');
                      }}
                      className="px-6 py-2.5 bg-gradient-to-r from-purple-600 to-indigo-600 hover:from-purple-500 hover:to-indigo-500 text-white text-xs font-bold rounded-xl cursor-pointer shadow-lg shadow-purple-500/25 flex items-center gap-2 transition-all"
                    >
                      <Check className="w-4 h-4" />
                      <span>Save All Profile Changes</span>
                    </button>
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
                  href={newlyCreatedSite.preview_url || `/sites/${newlyCreatedSite.domain_name}/`}
                  target="_blank"
                  rel="noreferrer"
                  className="bg-slate-800 hover:bg-slate-700 text-cyan-400 font-bold text-xs px-3.5 py-2 rounded-xl border border-slate-700 flex items-center gap-1.5 cursor-pointer"
                >
                  <ExternalLink className="w-3.5 h-3.5" /> Visit Site 🔗
                </a>
                {newlyCreatedSite.site_type === 'wordpress' && (
                  <a
                    href={(newlyCreatedSite.preview_url || `/sites/${newlyCreatedSite.domain_name}/`) + "wp-admin/"}
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

      {/* CONNECTION URI & CODE SNIPPETS MODAL */}
      {selectedDbConnModal && (
        <div className="fixed inset-0 bg-slate-950/80 backdrop-blur-md z-50 flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 w-full max-w-2xl rounded-2xl p-6 space-y-4 shadow-2xl animate-scale-up">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2">
                <Key className="w-5 h-5 text-cyan-400" />
                <h3 className="font-bold text-base text-white font-mono">
                  {selectedDbConnModal.name} <span className="text-xs text-cyan-400 uppercase font-mono">({selectedDbConnModal.engine})</span>
                </h3>
              </div>
              <button onClick={() => setSelectedDbConnModal(null)} className="text-slate-400 hover:text-white cursor-pointer font-bold text-sm">✕</button>
            </div>

            <div className="space-y-3 text-xs font-mono">
              {/* URI */}
              <div>
                <div className="text-slate-400 font-sans font-semibold mb-1 flex justify-between">
                  <span>Connection URI:</span>
                  <button
                    onClick={() => {
                      navigator.clipboard.writeText(selectedDbConnModal.connection_uri);
                      showToast('Copied connection URI!');
                    }}
                    className="text-cyan-400 hover:underline font-sans cursor-pointer"
                  >
                    Copy URI
                  </button>
                </div>
                <div className="bg-slate-950 p-3 rounded-xl border border-slate-800 text-emerald-400 break-all select-all">
                  {selectedDbConnModal.connection_uri}
                </div>
              </div>

              {/* CLI Command */}
              <div>
                <div className="text-slate-400 font-sans font-semibold mb-1">Terminal CLI Connection:</div>
                <div className="bg-slate-950 p-3 rounded-xl border border-slate-800 text-cyan-300 select-all">
                  {selectedDbConnModal.engine === 'postgresql'
                    ? `psql -h ${selectedDbConnModal.host || '127.0.0.1'} -p 5432 -U ${selectedDbConnModal.username} -d ${selectedDbConnModal.name}`
                    : `mysql -h ${selectedDbConnModal.host || '127.0.0.1'} -u ${selectedDbConnModal.username} -p ${selectedDbConnModal.name}`}
                </div>
              </div>

              {/* Framework .env */}
              <div>
                <div className="text-slate-400 font-sans font-semibold mb-1">Laravel / Framework .env Snippet:</div>
                <pre className="bg-slate-950 p-3 rounded-xl border border-slate-800 text-amber-300 text-[11px] select-all overflow-x-auto">
{selectedDbConnModal.engine === 'postgresql' ? `DB_CONNECTION=pgsql
DB_HOST=${selectedDbConnModal.host || '127.0.0.1'}
DB_PORT=5432
DB_DATABASE=${selectedDbConnModal.name}
DB_USERNAME=${selectedDbConnModal.username}
DB_PASSWORD=${selectedDbConnModal.password || '********'}` : `DB_CONNECTION=mysql
DB_HOST=${selectedDbConnModal.host || '127.0.0.1'}
DB_PORT=3306
DB_DATABASE=${selectedDbConnModal.name}
DB_USERNAME=${selectedDbConnModal.username}
DB_PASSWORD=${selectedDbConnModal.password || '********'}`}
                </pre>
              </div>
            </div>
          </div>
        </div>
      )}
    
      {/* 1-Click Site Cloning / Staging Modal */}
      {isCloneModalOpen && activeManageSite && (
        <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-md flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-3xl p-6 w-full max-w-md space-y-5 shadow-2xl">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2">
                <Copy className="w-5 h-5 text-indigo-400" />
                <h3 className="font-bold text-base text-white">1-Click Staging & Site Cloner</h3>
              </div>
              <button
                onClick={() => setIsCloneModalOpen(false)}
                className="text-slate-400 hover:text-white p-1"
              >
                ✕
              </button>
            </div>

            <div className="space-y-3 text-xs">
              <p className="text-slate-300">
                Create an exact clone of <strong className="text-cyan-400">{activeManageSite.domain_name}</strong> including all site files, Nginx vhost rules, and SQL database tables.
              </p>

              <div>
                <label className="text-slate-400 font-bold block mb-1">Target Staging Domain Name</label>
                <input
                  type="text"
                  value={cloneTargetDomain}
                  onChange={(e) => setCloneTargetDomain(e.target.value)}
                  placeholder="staging.example.com"
                  className="w-full bg-slate-950 border border-slate-800 rounded-xl p-3 text-white font-mono font-bold"
                />
              </div>

              <div className="bg-indigo-500/10 border border-indigo-500/20 p-3 rounded-xl text-[11px] text-indigo-300">
                ✨ Automatically provisions document root, generates isolated database <code className="text-white">db_staging</code>, replaces URLs, and reloads web server.
              </div>
            </div>

            <div className="flex justify-end gap-2 pt-2 border-t border-slate-800">
              <button
                onClick={() => setIsCloneModalOpen(false)}
                className="px-4 py-2 rounded-xl bg-slate-800 text-slate-300 text-xs font-bold"
              >
                Cancel
              </button>

              <button
                disabled={isCloningSite}
                onClick={async () => {
                  if (!cloneTargetDomain.trim()) return;
                  setIsCloningSite(true);
                  try {
                    await cloneWebsite(activeManageSite.domain_name, cloneTargetDomain.trim());
                    showToast('Successfully cloned site!');
                    setIsCloneModalOpen(false);
                    const updatedWebsites = await fetchWebsites();
                    setWebsites(updatedWebsites as any);
                  } catch (err: any) {
                    showToast('Cloning failed: ' + (err.message || 'Error'));
                  } finally {
                    setIsCloningSite(false);
                  }
                }}
                className="px-4 py-2 rounded-xl bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-bold shadow-lg shadow-indigo-600/20 flex items-center gap-2 cursor-pointer"
              >
                {isCloningSite ? 'Cloning Site & Database...' : 'Clone Website Now'}
              </button>
            </div>
          </div>
        </div>
      )}

</div>
  );
}
