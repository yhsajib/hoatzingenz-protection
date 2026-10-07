import { Website, DatabaseItem, TeamMember, ActiveSession, HardeningConfig, SecurityAuditLog, ServiceStatus } from '../types';

export const API_BASE = '';

export async function fetchWebsites(): Promise<Website[]> {
  const res = await fetch(`${API_BASE}/api/v1/websites`);
  if (!res.ok) throw new Error('Failed to fetch websites');
  return res.json();
}

export async function fetchDatabases(): Promise<DatabaseItem[]> {
  const res = await fetch(`${API_BASE}/api/v1/databases`);
  if (!res.ok) throw new Error('Failed to fetch databases');
  return res.json();
}

export async function fetchServices(): Promise<ServiceStatus[]> {
  const res = await fetch(`${API_BASE}/api/v1/services`);
  if (!res.ok) throw new Error('Failed to fetch services');
  return res.json();
}

export async function fetchTeamMembers(): Promise<TeamMember[]> {
  const res = await fetch(`${API_BASE}/api/v1/team/members`);
  if (!res.ok) return [];
  return res.json();
}

export async function fetchActiveSessions(): Promise<ActiveSession[]> {
  const res = await fetch(`${API_BASE}/api/v1/auth/sessions`);
  if (!res.ok) return [];
  return res.json();
}

export async function fetchHardeningConfig(): Promise<HardeningConfig | null> {
  const res = await fetch(`${API_BASE}/api/v1/security/hardening`);
  if (!res.ok) return null;
  return res.json();
}

export async function fetchAuditLogs(): Promise<SecurityAuditLog[]> {
  const res = await fetch(`${API_BASE}/api/v1/security/audit-log`);
  if (!res.ok) return [];
  return res.json();
}

export async function fetchVHostConfig(domain: string): Promise<string> {
  const res = await fetch(`${API_BASE}/api/v1/website/vhost?domain=${encodeURIComponent(domain)}`);
  if (!res.ok) throw new Error('Failed to fetch vhost config');
  const data = await res.json();
  return data.content || '';
}

export async function saveVHostConfig(domain: string, content: string): Promise<void> {
  const res = await fetch(`${API_BASE}/api/v1/website/vhost`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ domain, content }),
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || 'Failed to save vhost config');
}

export async function fetchBackups(domain: string): Promise<any[]> {
  const res = await fetch(`${API_BASE}/api/v1/website/backups?domain=${encodeURIComponent(domain)}`);
  if (!res.ok) return [];
  const data = await res.json();
  return data.backups || [];
}

export async function createBackup(domain: string): Promise<any> {
  const res = await fetch(`${API_BASE}/api/v1/website/backup`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ domain }),
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || 'Failed to create backup');
  return data.backup;
}

export async function deleteBackup(id: string): Promise<void> {
  const res = await fetch(`${API_BASE}/api/v1/website/backup?id=${encodeURIComponent(id)}`, {
    method: 'DELETE',
  });
  if (!res.ok) throw new Error('Failed to delete backup archive');
}

export async function fetchBackupSettings(domain: string): Promise<any> {
  const res = await fetch(`${API_BASE}/api/v1/website/backup/settings?domain=${encodeURIComponent(domain)}`);
  if (!res.ok) throw new Error('Failed to fetch backup settings');
  const data = await res.json();
  return data.config;
}

export async function saveBackupSettings(config: any): Promise<void> {
  const res = await fetch(`${API_BASE}/api/v1/website/backup/settings`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(config),
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || 'Failed to save backup settings');
}

export async function testStorageConnection(config: any): Promise<void> {
  const res = await fetch(`${API_BASE}/api/v1/website/backup/test-storage`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(config),
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.message || 'Storage connection test failed');
}

export async function setup2FA(): Promise<any> {
  const res = await fetch(`${API_BASE}/api/v1/auth/2fa/setup`, { method: 'POST' });
  if (!res.ok) throw new Error('Failed to setup 2FA');
  return res.json();
}

export async function verify2FA(secret: string, code: string): Promise<any> {
  const res = await fetch(`${API_BASE}/api/v1/auth/2fa/verify`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ secret, code }),
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || 'Verification failed');
  return data;
}

export async function banIPAddress(ip: string, action: 'ban' | 'unban' = 'ban'): Promise<any> {
  const res = await fetch(`${API_BASE}/api/v1/security/ban-ip`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ip, action }),
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || 'Failed to update IP firewall status');
  return data;
}

export async function executeWebCLI(domain: string, tool: 'wp' | 'artisan', command: string): Promise<any> {
  const res = await fetch(`${API_BASE}/api/v1/website/cli`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ domain, tool, command }),
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || 'CLI execution failed');
  return data;
}

export async function cloneWebsite(sourceDomain: string, targetDomain: string): Promise<any> {
  const res = await fetch(`${API_BASE}/api/v1/website/clone`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ source_domain: sourceDomain, target_domain: targetDomain }),
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || 'Site cloning failed');
  return data;
}

export async function fetchAutoHealIncidents(): Promise<any[]> {
  const res = await fetch(`${API_BASE}/api/v1/diagnostics/auto-heal`);
  if (!res.ok) return [];
  const data = await res.json();
  return data.incidents || [];
}

export async function triggerAutoHealScan(domain_name: string): Promise<any> {
  const res = await fetch(`${API_BASE}/api/v1/diagnostics/auto-heal`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ domain_name }),
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || 'Diagnostic scan failed');
  return data.incident;
}

export async function executeTerminalCommand(domain: string, command: string): Promise<any> {
  const res = await fetch(`${API_BASE}/api/v1/website/terminal`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ domain, command }),
  });
  const data = await res.json();
  if (!res.ok && !data.output) throw new Error(data.error || 'Command failed');
  return data;
}

export async function fetchPHPConfig(version: string = '8.3'): Promise<any> {
  const res = await fetch(`${API_BASE}/api/v1/website/php-config?version=${encodeURIComponent(version)}`);
  if (!res.ok) throw new Error('Failed to fetch PHP config');
  const data = await res.json();
  return data.config;
}

export async function savePHPConfig(domain: string, config: any): Promise<any> {
  const res = await fetch(`${API_BASE}/api/v1/website/php-config`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ domain, config }),
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || 'Failed to save PHP config');
  return data;
}

export async function configureFastCGICache(domain: string, action: 'purge' | 'enable' | 'disable'): Promise<any> {
  const res = await fetch(`${API_BASE}/api/v1/website/cache`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ domain, action }),
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || 'Cache action failed');
  return data;
}

export async function fetchResourceLimits(domain: string): Promise<any> {
  const res = await fetch(`${API_BASE}/api/v1/website/resource-limits?domain=${encodeURIComponent(domain)}`);
  if (!res.ok) return { memory_max: '512M', cpu_quota: '100%', disk_quota: '10000M', used_disk_mb: 0 };
  const data = await res.json();
  return data.limits;
}

export async function saveResourceLimits(domain: string, limits: any): Promise<any> {
  const res = await fetch(`${API_BASE}/api/v1/website/resource-limits`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ domain, limits }),
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || 'Failed to update resource limits');
  return data;
}

// 5 Next-Level Enterprise Features API Methods
export async function fetchAppSupervisor(): Promise<any> {
  const res = await fetch(`${API_BASE}/api/v1/apps/supervisor`);
  if (!res.ok) return { apps: [] };
  return res.json();
}

export async function deployAppSupervisor(cfg: any): Promise<any> {
  const res = await fetch(`${API_BASE}/api/v1/apps/supervisor`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(cfg),
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || 'Failed to deploy app');
  return data;
}

export async function startServerMigration(job: any): Promise<any> {
  const res = await fetch(`${API_BASE}/api/v1/migration/start`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(job),
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || 'Migration failed to start');
  return data;
}

export async function fetchNotificationConfig(): Promise<any> {
  const res = await fetch(`${API_BASE}/api/v1/notifications/config`);
  if (!res.ok) return { config: {} };
  return res.json();
}

export async function saveNotificationConfig(action: string, config: any): Promise<any> {
  const res = await fetch(`${API_BASE}/api/v1/notifications/config`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ action, config }),
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || 'Failed to save notifications');
  return data;
}

export async function fetchDNSRecords(domain: string): Promise<any> {
  const res = await fetch(`${API_BASE}/api/v1/dns/records?domain=${encodeURIComponent(domain)}`);
  if (!res.ok) return { records: [] };
  return res.json();
}

export async function addDNSRecord(domain: string, record: any): Promise<any> {
  const res = await fetch(`${API_BASE}/api/v1/dns/records`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ domain, record }),
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || 'Failed to add DNS record');
  return data;
}

export async function syncCloudflareDNS(domain: string, cloudflare: any): Promise<any> {
  const res = await fetch(`${API_BASE}/api/v1/dns/cloudflare-sync`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ action: 'cloudflare_sync', domain, cloudflare }),
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || 'Cloudflare sync failed');
  return data;
}

export async function fetchSystemSparklines(): Promise<any> {
  const res = await fetch(`${API_BASE}/api/v1/monitoring/health`);
  if (!res.ok) return { sparklines: [] };
  return res.json();
}

export async function fetchDomainBandwidth(domain: string): Promise<any> {
  const res = await fetch(`${API_BASE}/api/v1/monitoring/bandwidth?domain=${encodeURIComponent(domain)}`);
  if (!res.ok) return { bandwidth: { human_size: '0 MB', request_count: 0 } };
  return res.json();
}
