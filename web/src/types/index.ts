export interface Website {
  id: string;
  domain: string;
  document_root: string;
  stack_type: 'wordpress' | 'nodejs' | 'reverse_proxy' | 'static' | 'python';
  php_version: string;
  node_version?: string;
  reverse_proxy_target?: string;
  ssl_enabled: boolean;
  ssl_issuer?: string;
  ssl_auto_renew?: boolean;
  status: 'active' | 'deploying' | 'error' | 'suspended';
  created_at: string;
  db_name?: string;
  db_user?: string;
}

export interface DatabaseTable {
  name: string;
  rows: number;
  size_kb: number;
  engine?: string;
  collation?: string;
}

export interface TableColumn {
  name: string;
  type: string;
  nullable: boolean;
  key: string;
  default: string | null;
  extra: string;
}

export interface DatabaseItem {
  id: string;
  name: string;
  engine: 'MySQL' | 'PostgreSQL' | 'MongoDB' | 'Redis';
  size_mb: number;
  tables_count: number;
  host?: string;
  port?: number;
  username?: string;
  password?: string;
  created_at: string;
}

export interface ErrorDiagnostic {
  id: string;
  timestamp: string;
  service: string;
  severity: 'critical' | 'warning' | 'info';
  message: string;
  raw_log: string;
  suggested_fix?: string;
}

export interface ServiceStatus {
  name: string;
  engine: string;
  status: 'running' | 'stopped' | 'degraded';
  memory_mb: number;
  cpu_percent: number;
  uptime: string;
}

export interface TeamMember {
  id: string;
  name: string;
  email: string;
  username: string;
  role: 'Owner' | 'Admin' | 'Developer' | 'Viewer';
  permissions: string[];
  two_factor_enabled: boolean;
  status: 'active' | 'invited' | 'disabled';
  last_login: string;
  avatar: string;
}

export interface ActiveSession {
  id: string;
  ip: string;
  location: string;
  user_agent: string;
  device: string;
  auth_type: string;
  is_current: boolean;
  created_at: string;
  last_active: string;
}

export interface HardeningConfig {
  waf_enabled: boolean;
  sql_injection_shield: boolean;
  xss_filter: boolean;
  ip_rate_limiting: boolean;
  two_factor_enforced: boolean;
  ssh_root_disabled: boolean;
  failed_login_ban_threshold: number;
  banned_ips: string[];
}

export interface SecurityAuditLog {
  id: string;
  timestamp: string;
  action: string;
  user: string;
  ip: string;
  severity: 'critical' | 'warning' | 'info';
  details: string;
}

export interface FTPAccount {
  id: string;
  username: string;
  path: string;
  status: string;
}

export interface MailDomain {
  id: number;
  team_id?: number;
  name: string;
  status: string;
  created_at: string;
}

export interface Mailbox {
  id: number;
  domain_id: number;
  local_part: string;
  address: string;
  quota_mb: number;
  active: boolean;
  created_at: string;
}
