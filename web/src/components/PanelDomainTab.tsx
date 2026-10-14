import React, { useState, useEffect } from 'react';
import {
  Globe,
  Shield,
  ShieldCheck,
  Check,
  Copy,
  ExternalLink,
  RefreshCw,
  AlertCircle,
  Trash2,
  Terminal,
  Lock,
  Server,
  Sparkles,
  CheckCircle2
} from 'lucide-react';

interface PanelDomainConfig {
  configured: boolean;
  domain: string;
  server_ip: string;
  port: number;
  ssl_provider: string;
  ssl_enabled: boolean;
  force_https: boolean;
  active_url: string;
  vhost_path: string;
  vhost_content: string;
  dns_status: string;
  resolved_ips: string[];
  updated_at: string;
}

interface PanelDomainTabProps {
  apiBase: string;
  getHeaders: () => Record<string, string>;
  showToast: (msg: string) => void;
}

export const PanelDomainTab: React.FC<PanelDomainTabProps> = ({
  apiBase,
  getHeaders,
  showToast,
}) => {
  const [config, setConfig] = useState<PanelDomainConfig | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [saving, setSaving] = useState<boolean>(false);
  const [verifyingDns, setVerifyingDns] = useState<boolean>(false);
  const [copiedIp, setCopiedIp] = useState<boolean>(false);
  const [copiedVhost, setCopiedVhost] = useState<boolean>(false);

  // Form states
  const [domainInput, setDomainInput] = useState<string>('');
  const [sslProvider, setSSLProvider] = useState<'letsencrypt' | 'selfsigned' | 'none'>('letsencrypt');
  const [forceHttps, setForceHttps] = useState<boolean>(true);
  const [dnsCheckResult, setDnsCheckResult] = useState<{
    matches_server: boolean;
    message: string;
    resolved_ips?: string[];
  } | null>(null);
  const [showVhostModal, setShowVhostModal] = useState<boolean>(false);

  const fetchConfig = async () => {
    try {
      setLoading(true);
      const res = await fetch(`${apiBase}/api/v1/system/panel-domain`, {
        headers: getHeaders(),
      });
      if (res.ok) {
        const data = await res.json();
        if (data.config) {
          setConfig(data.config);
          if (data.config.domain) {
            setDomainInput(data.config.domain);
            setSSLProvider(data.config.ssl_provider || 'letsencrypt');
            setForceHttps(data.config.force_https ?? true);
          }
        }
      }
    } catch {
      // Fallback
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchConfig();
  }, []);

  const handleCopy = (text: string, type: 'ip' | 'vhost') => {
    navigator.clipboard.writeText(text);
    if (type === 'ip') {
      setCopiedIp(true);
      setTimeout(() => setCopiedIp(false), 2000);
    } else {
      setCopiedVhost(true);
      setTimeout(() => setCopiedVhost(false), 2000);
    }
    showToast('Copied to clipboard!');
  };

  const handleVerifyDns = async () => {
    const domainToCheck = domainInput.trim() || config?.domain;
    if (!domainToCheck) {
      alert('Please enter a domain name to verify DNS.');
      return;
    }
    try {
      setVerifyingDns(true);
      setDnsCheckResult(null);
      const res = await fetch(`${apiBase}/api/v1/system/panel-domain`, {
        method: 'POST',
        headers: getHeaders(),
        body: JSON.stringify({
          action: 'verify_dns',
          domain: domainToCheck,
        }),
      });
      const data = await res.json();
      if (res.ok) {
        setDnsCheckResult({
          matches_server: data.matches_server,
          message: data.message,
          resolved_ips: data.resolved_ips,
        });
        showToast(data.matches_server ? 'DNS Verified!' : 'DNS check completed');
      } else {
        alert(data.error || 'Failed to check DNS');
      }
    } catch {
      alert('Error verifying DNS');
    } finally {
      setVerifyingDns(false);
    }
  };

  const handleSaveDomain = async (e: React.FormEvent) => {
    e.preventDefault();
    const cleanDomain = domainInput.trim().toLowerCase();
    if (!cleanDomain) {
      alert('Please enter a valid domain name (e.g. cp.yourcompany.com)');
      return;
    }

    try {
      setSaving(true);
      const res = await fetch(`${apiBase}/api/v1/system/panel-domain`, {
        method: 'POST',
        headers: getHeaders(),
        body: JSON.stringify({
          action: 'set_domain',
          domain: cleanDomain,
          ssl_provider: sslProvider,
          force_https: forceHttps,
        }),
      });
      const data = await res.json();
      if (res.ok) {
        showToast(data.message || `Custom domain ${cleanDomain} provisioned successfully!`);
        await fetchConfig();
      } else {
        alert(data.error || 'Failed to provision custom domain');
      }
    } catch {
      alert('Network error while configuring custom domain');
    } finally {
      setSaving(false);
    }
  };

  const handleRemoveDomain = async () => {
    if (!confirm('Are you sure you want to remove the custom domain? The control panel will revert to IP access.')) {
      return;
    }

    try {
      setSaving(true);
      const res = await fetch(`${apiBase}/api/v1/system/panel-domain`, {
        method: 'POST',
        headers: getHeaders(),
        body: JSON.stringify({ action: 'remove_domain' }),
      });
      const data = await res.json();
      if (res.ok) {
        showToast('Custom domain removed. Reverted to IP access.');
        setDomainInput('');
        setDnsCheckResult(null);
        await fetchConfig();
      } else {
        alert(data.error || 'Failed to remove custom domain');
      }
    } catch {
      alert('Error removing custom domain');
    } finally {
      setSaving(false);
    }
  };

  const serverIp = config?.server_ip || '10.255.255.254';
  const isConfigured = Boolean(config?.configured && config?.domain);

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Hero Header Banner */}
      <div className="bg-gradient-to-r from-cyan-950/40 via-slate-900 to-indigo-950/40 border border-cyan-500/20 rounded-3xl p-6 shadow-xl backdrop-blur-md flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div className="flex items-start gap-4">
          <div className="w-12 h-12 rounded-2xl bg-gradient-to-br from-cyan-500/20 to-blue-500/20 border border-cyan-500/30 flex items-center justify-center text-cyan-400 font-bold shadow-lg shadow-cyan-500/10 shrink-0 mt-0.5">
            <Globe className="w-6 h-6 text-cyan-400" />
          </div>
          <div>
            <div className="flex items-center gap-2.5 flex-wrap">
              <h2 className="text-2xl font-extrabold text-white tracking-tight">
                Panel Custom Domain
              </h2>
              <span className="bg-cyan-500/15 text-cyan-300 text-xs font-mono font-bold px-2.5 py-0.5 rounded-full border border-cyan-500/30 flex items-center gap-1.5">
                <Sparkles className="w-3 h-3 text-cyan-400" />
                CLOUDPANEL STYLE
              </span>
              <span className="bg-emerald-500/15 text-emerald-400 text-xs font-mono font-bold px-2.5 py-0.5 rounded-full border border-emerald-500/30 flex items-center gap-1">
                <ShieldCheck className="w-3 h-3 text-emerald-400" />
                REVERSE PROXY & SSL
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-1 max-w-2xl">
              Like CloudPanel, configure a branded domain or subdomain (e.g. <span className="text-cyan-300 font-mono">cp.yourcompany.com</span>) to securely access this control panel over HTTPS with automatic Let's Encrypt SSL.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-3 shrink-0">
          <button
            onClick={fetchConfig}
            disabled={loading}
            className="p-2.5 bg-slate-800 hover:bg-slate-750 text-slate-300 hover:text-white rounded-xl border border-slate-700 text-xs font-semibold cursor-pointer transition-all"
            title="Refresh Status"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
          </button>
          {isConfigured && (
            <a
              href={config?.active_url}
              target="_blank"
              rel="noreferrer"
              className="px-4 py-2 bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white text-xs font-bold rounded-xl shadow-lg shadow-cyan-500/20 flex items-center gap-2 transition-all cursor-pointer"
            >
              <span>Open Panel Domain</span>
              <ExternalLink className="w-3.5 h-3.5" />
            </a>
          )}
        </div>
      </div>

      {/* Active State / Access Mode Card */}
      {isConfigured ? (
        <div className="bg-gradient-to-br from-emerald-950/30 via-slate-900/90 to-slate-900 border border-emerald-500/30 rounded-2xl p-5 shadow-xl space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800/80 pb-4">
            <div className="flex items-center gap-3.5">
              <div className="w-10 h-10 rounded-xl bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center text-emerald-400 font-bold">
                <CheckCircle2 className="w-5 h-5 text-emerald-400" />
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <h3 className="font-extrabold text-base text-white font-mono tracking-tight">
                    {config?.domain}
                  </h3>
                  <span className="px-2 py-0.5 rounded-full text-[10px] font-bold font-mono bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">
                    ACTIVE DOMAIN
                  </span>
                </div>
                <p className="text-xs text-slate-400 mt-0.5">
                  Control panel is securely reverse-proxied to internal port 8080.
                </p>
              </div>
            </div>

            <div className="flex items-center gap-2.5">
              <button
                onClick={() => setShowVhostModal(true)}
                className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-xl text-xs font-semibold border border-slate-700 transition-all flex items-center gap-1.5 cursor-pointer"
              >
                <Terminal className="w-3.5 h-3.5 text-cyan-400" />
                <span>View Nginx VHost</span>
              </button>
              <button
                onClick={handleRemoveDomain}
                disabled={saving}
                className="px-3 py-1.5 bg-rose-500/10 hover:bg-rose-500/20 text-rose-300 hover:text-white rounded-xl text-xs font-semibold border border-rose-500/30 transition-all flex items-center gap-1.5 cursor-pointer"
              >
                <Trash2 className="w-3.5 h-3.5 text-rose-400" />
                <span>Remove Domain</span>
              </button>
            </div>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs font-mono">
            <div className="bg-slate-950/60 border border-slate-800 rounded-xl p-3 space-y-1">
              <span className="text-[10px] uppercase font-sans text-slate-400 font-bold">Access Protocol</span>
              <p className="text-emerald-400 font-bold flex items-center gap-1.5">
                <Lock className="w-3.5 h-3.5 text-emerald-400" />
                {config?.ssl_enabled ? 'HTTPS (Port 443)' : 'HTTP (Port 80)'}
              </p>
            </div>
            <div className="bg-slate-950/60 border border-slate-800 rounded-xl p-3 space-y-1">
              <span className="text-[10px] uppercase font-sans text-slate-400 font-bold">SSL Certificate</span>
              <p className="text-cyan-300 font-bold flex items-center gap-1.5">
                <ShieldCheck className="w-3.5 h-3.5 text-cyan-400" />
                {config?.ssl_provider === 'letsencrypt' ? "Let's Encrypt (Auto-Renew)" : config?.ssl_provider}
              </p>
            </div>
            <div className="bg-slate-950/60 border border-slate-800 rounded-xl p-3 space-y-1">
              <span className="text-[10px] uppercase font-sans text-slate-400 font-bold">DNS Resolution</span>
              <p className="text-slate-200 font-bold flex items-center gap-1.5">
                <span className={`w-2 h-2 rounded-full ${config?.dns_status === 'verified' ? 'bg-emerald-400 animate-pulse' : 'bg-amber-400'}`}></span>
                {config?.dns_status === 'verified' ? 'Verified to Server IP' : 'Pending Verification'}
              </p>
            </div>
          </div>
        </div>
      ) : (
        <div className="bg-slate-900/80 border border-amber-500/20 rounded-2xl p-4 shadow-xl flex items-start gap-3.5 bg-gradient-to-r from-amber-500/5 to-transparent">
          <div className="w-9 h-9 rounded-xl bg-amber-500/10 border border-amber-500/30 flex items-center justify-center text-amber-400 shrink-0 mt-0.5">
            <AlertCircle className="w-4 h-4 text-amber-400" />
          </div>
          <div>
            <h4 className="text-sm font-bold text-white">Default IP Access Active</h4>
            <p className="text-xs text-slate-400 mt-0.5">
              You are currently accessing this panel via server IP (<code className="text-amber-300 font-mono">http://{serverIp}:8080</code>). Set up a custom domain below to access without port numbers and with full SSL protection.
            </p>
          </div>
        </div>
      )}

      {/* CloudPanel-Style DNS A-Record Instructions Card */}
      <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-5 shadow-xl space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-3">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-xl bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400">
              <Server className="w-4 h-4" />
            </div>
            <div>
              <h3 className="font-bold text-sm text-white">DNS Prerequisites (A-Record)</h3>
              <p className="text-xs text-slate-400">Point your chosen panel domain/subdomain to this server before provisioning SSL</p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <span className="text-xs text-slate-400">Server IP:</span>
            <code className="bg-slate-950 border border-slate-800 px-3 py-1 rounded-lg text-cyan-300 font-bold font-mono text-xs">
              {serverIp}
            </code>
            <button
              onClick={() => handleCopy(serverIp, 'ip')}
              className="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white rounded-lg text-xs font-semibold border border-slate-700 transition-all flex items-center gap-1 cursor-pointer"
            >
              {copiedIp ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              <span>{copiedIp ? 'Copied' : 'Copy'}</span>
            </button>
          </div>
        </div>

        {/* DNS Record Table */}
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono border-collapse">
            <thead>
              <tr className="bg-slate-950/80 border-b border-slate-800 text-[11px] font-bold text-slate-400 uppercase tracking-wider">
                <th className="py-2.5 px-4">Record Type</th>
                <th className="py-2.5 px-4">Host / Name</th>
                <th className="py-2.5 px-4">Value / Destination</th>
                <th className="py-2.5 px-4">TTL</th>
                <th className="py-2.5 px-4 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              <tr>
                <td className="py-3 px-4">
                  <span className="px-2 py-0.5 rounded bg-cyan-500/15 text-cyan-300 font-bold text-[11px]">A</span>
                </td>
                <td className="py-3 px-4 text-white font-bold">
                  {domainInput ? (domainInput.split('.')[0] || 'cp') : 'cp / panel'}
                </td>
                <td className="py-3 px-4 text-cyan-400 font-bold">{serverIp}</td>
                <td className="py-3 px-4 text-slate-400">Auto / 300s</td>
                <td className="py-3 px-4 text-right">
                  <button
                    onClick={handleVerifyDns}
                    disabled={verifyingDns}
                    className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 hover:text-white font-sans text-xs font-semibold rounded-lg border border-slate-700 transition-all flex items-center gap-1.5 ml-auto cursor-pointer"
                  >
                    <RefreshCw className={`w-3.5 h-3.5 text-cyan-400 ${verifyingDns ? 'animate-spin' : ''}`} />
                    <span>{verifyingDns ? 'Checking...' : 'Check DNS'}</span>
                  </button>
                </td>
              </tr>
            </tbody>
          </table>
        </div>

        {/* DNS check result callout */}
        {dnsCheckResult && (
          <div className={`p-3.5 rounded-xl border text-xs font-mono flex items-start gap-2.5 ${
            dnsCheckResult.matches_server
              ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-300'
              : 'bg-amber-500/10 border-amber-500/30 text-amber-300'
          }`}>
            {dnsCheckResult.matches_server ? (
              <Check className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
            ) : (
              <AlertCircle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
            )}
            <div>
              <p className="font-bold">{dnsCheckResult.message}</p>
              {dnsCheckResult.resolved_ips && dnsCheckResult.resolved_ips.length > 0 && (
                <p className="text-[11px] text-slate-400 mt-0.5 font-mono">
                  Resolved IPs: {dnsCheckResult.resolved_ips.join(', ')}
                </p>
              )}
            </div>
          </div>
        )}
      </div>

      {/* Main Configuration Form Card */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-3xl p-6 shadow-2xl space-y-6">
        <div className="border-b border-slate-800 pb-3">
          <h3 className="text-base font-bold text-white flex items-center gap-2">
            <Lock className="w-4 h-4 text-purple-400" />
            <span>Configure Custom Domain & SSL Certificate</span>
          </h3>
          <p className="text-xs text-slate-400 mt-0.5">
            Set your panel domain and configure SSL mode. Nginx reverse proxy will route incoming traffic to the Go backend.
          </p>
        </div>

        <form onSubmit={handleSaveDomain} className="space-y-5">
          {/* Domain Name Input */}
          <div>
            <label className="block text-xs font-semibold text-slate-300 mb-1.5">
              Domain / Subdomain Name
            </label>
            <div className="relative">
              <Globe className="w-4 h-4 text-slate-500 absolute left-3.5 top-1/2 -translate-y-1/2 pointer-events-none" />
              <input
                type="text"
                value={domainInput}
                onChange={(e) => setDomainInput(e.target.value)}
                placeholder="e.g. cp.yourcompany.com or panel.example.org"
                className="w-full bg-slate-950 border border-slate-800 rounded-xl pl-10 pr-4 py-2.5 text-sm text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono"
                required
              />
            </div>
            <p className="text-[11px] text-slate-500 mt-1">
              Recommended: Use a dedicated subdomain like <code className="text-slate-400">cp.domain.com</code> or <code className="text-slate-400">panel.domain.com</code>.
            </p>
          </div>

          {/* SSL Provider Selection (Radio Cards) */}
          <div className="space-y-2">
            <label className="block text-xs font-semibold text-slate-300">
              SSL / TLS Security Mode
            </label>
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
              {/* Let's Encrypt */}
              <div
                onClick={() => setSSLProvider('letsencrypt')}
                className={`p-4 rounded-xl border transition-all cursor-pointer space-y-1.5 ${
                  sslProvider === 'letsencrypt'
                    ? 'bg-gradient-to-br from-cyan-950/40 to-slate-900 border-cyan-500/50 shadow-lg shadow-cyan-500/10'
                    : 'bg-slate-950/60 border-slate-800 hover:border-slate-700'
                }`}
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <ShieldCheck className="w-4 h-4 text-cyan-400" />
                    <span className="text-xs font-bold text-white">Let's Encrypt</span>
                  </div>
                  <span className="px-1.5 py-0.5 rounded text-[9px] font-bold bg-cyan-500/20 text-cyan-300 font-mono">
                    RECOMMENDED
                  </span>
                </div>
                <p className="text-[11px] text-slate-400">
                  Free trusted SSL with automated Certbot issuance & 90-day auto-renewal.
                </p>
              </div>

              {/* Self-Signed */}
              <div
                onClick={() => setSSLProvider('selfsigned')}
                className={`p-4 rounded-xl border transition-all cursor-pointer space-y-1.5 ${
                  sslProvider === 'selfsigned'
                    ? 'bg-gradient-to-br from-purple-950/40 to-slate-900 border-purple-500/50 shadow-lg shadow-purple-500/10'
                    : 'bg-slate-950/60 border-slate-800 hover:border-slate-700'
                }`}
              >
                <div className="flex items-center gap-2">
                  <Shield className="w-4 h-4 text-purple-400" />
                  <span className="text-xs font-bold text-white">Self-Signed SSL</span>
                </div>
                <p className="text-[11px] text-slate-400">
                  Instant local certificate. Browser will display self-signed certificate warning.
                </p>
              </div>

              {/* None */}
              <div
                onClick={() => setSSLProvider('none')}
                className={`p-4 rounded-xl border transition-all cursor-pointer space-y-1.5 ${
                  sslProvider === 'none'
                    ? 'bg-gradient-to-br from-slate-900 to-slate-950 border-slate-600 shadow-md'
                    : 'bg-slate-950/60 border-slate-800 hover:border-slate-700'
                }`}
              >
                <div className="flex items-center gap-2">
                  <Globe className="w-4 h-4 text-slate-400" />
                  <span className="text-xs font-bold text-white">Plain HTTP Only</span>
                </div>
                <p className="text-[11px] text-slate-400">
                  Port 80 without SSL encryption. Not recommended for production environments.
                </p>
              </div>
            </div>
          </div>

          {/* Force HTTPS Toggle */}
          <div className="bg-slate-950/60 border border-slate-800 rounded-xl p-4 flex items-center justify-between gap-4">
            <div className="space-y-0.5">
              <label htmlFor="force-https-toggle" className="text-xs font-bold text-white cursor-pointer">
                Force HTTPS Redirection (HTTP → HTTPS)
              </label>
              <p className="text-[11px] text-slate-400">
                Automatically redirect unencrypted port 80 traffic to HTTPS port 443 with HSTS header.
              </p>
            </div>
            <label className="relative inline-flex items-center cursor-pointer shrink-0">
              <input
                id="force-https-toggle"
                type="checkbox"
                checked={forceHttps}
                onChange={(e) => setForceHttps(e.target.checked)}
                className="sr-only peer"
              />
              <div className="w-11 h-6 bg-slate-800 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-slate-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-gradient-to-r peer-checked:from-cyan-500 peer-checked:to-blue-600"></div>
            </label>
          </div>

          {/* Form Submit & Actions */}
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pt-2 border-t border-slate-800/80">
            <p className="text-[11px] text-slate-400 font-mono">
              Target: Nginx reverse proxy → <strong className="text-slate-200">http://127.0.0.1:8080</strong>
            </p>

            <div className="flex items-center gap-3">
              <button
                type="button"
                onClick={handleVerifyDns}
                disabled={verifyingDns}
                className="px-4 py-2.5 bg-slate-800 hover:bg-slate-750 text-slate-200 font-semibold text-xs rounded-xl border border-slate-700 transition-all flex items-center gap-1.5 cursor-pointer"
              >
                <RefreshCw className={`w-3.5 h-3.5 text-cyan-400 ${verifyingDns ? 'animate-spin' : ''}`} />
                <span>Verify DNS First</span>
              </button>

              <button
                type="submit"
                disabled={saving}
                className="px-6 py-2.5 bg-gradient-to-r from-cyan-500 via-blue-600 to-indigo-600 hover:from-cyan-400 hover:to-indigo-500 text-white font-bold text-xs rounded-xl shadow-lg shadow-cyan-500/25 transition-all flex items-center gap-2 cursor-pointer disabled:opacity-50"
              >
                {saving ? (
                  <>
                    <RefreshCw className="w-4 h-4 animate-spin" />
                    <span>Provisioning...</span>
                  </>
                ) : (
                  <>
                    <Check className="w-4 h-4" />
                    <span>Save & Provision Custom Domain</span>
                  </>
                )}
              </button>
            </div>
          </div>
        </form>
      </div>

      {/* CloudPanel Architecture & Features Explanation */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-4 space-y-2">
          <div className="w-8 h-8 rounded-xl bg-purple-500/10 border border-purple-500/30 flex items-center justify-center text-purple-400">
            <Shield className="w-4 h-4" />
          </div>
          <h4 className="text-xs font-bold text-white">Let's Encrypt Integration</h4>
          <p className="text-[11px] text-slate-400 leading-relaxed">
            Certbot automatically provisions trusted TLS certificates via HTTP-01 ACME challenge with zero manual certificate management.
          </p>
        </div>

        <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-4 space-y-2">
          <div className="w-8 h-8 rounded-xl bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400">
            <Server className="w-4 h-4" />
          </div>
          <h4 className="text-xs font-bold text-white">Nginx Reverse Proxy</h4>
          <p className="text-[11px] text-slate-400 leading-relaxed">
            Routes port 443 HTTPS directly to the Go control panel backend with WebSocket support and buffer streaming enabled.
          </p>
        </div>

        <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-4 space-y-2">
          <div className="w-8 h-8 rounded-xl bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center text-emerald-400">
            <Lock className="w-4 h-4" />
          </div>
          <h4 className="text-xs font-bold text-white">Zero Port Exposure</h4>
          <p className="text-[11px] text-slate-400 leading-relaxed">
            Eliminates the need to access the panel via unstandardized ports (e.g. :8080 or :8443) behind firewall restrictions.
          </p>
        </div>
      </div>

      {/* Nginx VHost Modal */}
      {showVhostModal && (
        <div className="fixed inset-0 bg-slate-950/80 backdrop-blur-md z-50 flex items-center justify-center p-4 animate-fade-in">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-2xl w-full p-6 shadow-2xl space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2.5">
                <div className="w-8 h-8 rounded-xl bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400">
                  <Terminal className="w-4 h-4" />
                </div>
                <div>
                  <h3 className="text-sm font-bold text-white">Nginx VHost Configuration</h3>
                  <p className="text-xs text-slate-400 font-mono">/etc/nginx/sites-available/panel-domain.conf</p>
                </div>
              </div>
              <button
                onClick={() => setShowVhostModal(false)}
                className="text-slate-400 hover:text-white p-1 rounded-lg cursor-pointer"
              >
                ✕
              </button>
            </div>

            <pre className="bg-slate-950 border border-slate-800 rounded-xl p-4 text-xs font-mono text-cyan-300 overflow-x-auto max-h-96">
              {config?.vhost_content || '# Nginx vhost will be generated upon provisioning.'}
            </pre>

            <div className="flex justify-end gap-3 pt-2">
              <button
                onClick={() => handleCopy(config?.vhost_content || '', 'vhost')}
                className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-xl text-xs font-semibold flex items-center gap-1.5 border border-slate-700 cursor-pointer"
              >
                {copiedVhost ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                <span>{copiedVhost ? 'Copied' : 'Copy Configuration'}</span>
              </button>
              <button
                onClick={() => setShowVhostModal(false)}
                className="px-4 py-2 bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 text-white font-bold text-xs rounded-xl cursor-pointer"
              >
                Done
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
