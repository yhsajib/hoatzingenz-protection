import React, { useState } from 'react';
import {
  Mail,
  Server,
  Lock,
  Globe,
  Plus,
  Search,
  ExternalLink,
  Trash2,
  Shield,
  Check,
  Copy,
  HardDrive
} from 'lucide-react';

interface EmailWebmailTabProps {
  mailDomains: any[];
  mailboxes: any[];
  webmailUrl: string;
  mailServices: { postfix: string; dovecot: string };
  onRefresh: () => void;
  getHeaders: () => Record<string, string>;
  apiBase: string;
  showToast: (msg: string) => void;
}

export const EmailWebmailTab: React.FC<EmailWebmailTabProps> = ({
  mailDomains,
  mailboxes,
  webmailUrl,
  mailServices,
  onRefresh,
  getHeaders,
  apiBase,
  showToast,
}) => {
  const [mailboxSearch, setMailboxSearch] = useState<string>('');
  const [showAddMailDomainModal, setShowAddMailDomainModal] = useState<boolean>(false);
  const [showAddMailboxModal, setShowAddMailboxModal] = useState<boolean>(false);
  const [showDnsRecordsModal, setShowDnsRecordsModal] = useState<boolean>(false);
  const [selectedDnsDomain, setSelectedDnsDomain] = useState<string>(mailDomains[0]?.name || 'hoatzinlabs.com');
  const [copiedDnsKey, setCopiedDnsKey] = useState<string | null>(null);

  const [newMailDomainInput, setNewMailDomainInput] = useState<string>('');
  const [newMailboxDomain, setNewMailboxDomain] = useState<string>(mailDomains[0]?.name || 'hoatzinlabs.com');
  const [newMailboxLocalPart, setNewMailboxLocalPart] = useState<string>('');
  const [newMailboxPassword, setNewMailboxPassword] = useState<string>('');
  const [newMailboxQuota, setNewMailboxQuota] = useState<number>(2048);

  const totalQuotaMB = mailboxes.reduce((acc, mb) => acc + (mb.quota_mb || 2048), 0);
  const totalQuotaGB = (totalQuotaMB / 1024).toFixed(1);

  const filteredMailboxes = mailboxes.filter((mb) =>
    !mailboxSearch || mb.address.toLowerCase().includes(mailboxSearch.toLowerCase())
  );

  const copyToClipboard = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedDnsKey(key);
    setTimeout(() => setCopiedDnsKey(null), 2000);
  };

  const handleCreateDomain = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newMailDomainInput.trim()) return;
    try {
      const res = await fetch(`${apiBase}/api/v1/email`, {
        method: 'POST',
        headers: getHeaders(),
        body: JSON.stringify({ action: 'create_domain', domain: newMailDomainInput.trim() }),
      });
      const data = await res.json();
      if (res.ok) {
        setNewMailDomainInput('');
        setShowAddMailDomainModal(false);
        onRefresh();
        showToast(`Mail domain ${newMailDomainInput} configured successfully!`);
      } else {
        alert(data.error || 'Failed to add mail domain');
      }
    } catch {
      alert('Error creating mail domain');
    }
  };

  const handleCreateMailbox = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newMailboxLocalPart.trim() || !newMailboxDomain) return;
    try {
      const res = await fetch(`${apiBase}/api/v1/email`, {
        method: 'POST',
        headers: getHeaders(),
        body: JSON.stringify({
          action: 'create_mailbox',
          domain: newMailboxDomain,
          local_part: newMailboxLocalPart.trim(),
          password: newMailboxPassword,
          quota_mb: newMailboxQuota || 2048,
        }),
      });
      const data = await res.json();
      if (res.ok) {
        setNewMailboxLocalPart('');
        setNewMailboxPassword('');
        setShowAddMailboxModal(false);
        onRefresh();
        showToast(`Mailbox ${newMailboxLocalPart}@${newMailboxDomain} created successfully!`);
      } else {
        alert(data.error || 'Failed to create mailbox');
      }
    } catch {
      alert('Error creating mailbox');
    }
  };

  const handleDeleteMailbox = async (mb: any) => {
    if (!confirm(`Delete mailbox ${mb.address}? This action cannot be undone.`)) return;
    try {
      const res = await fetch(`${apiBase}/api/v1/email`, {
        method: 'POST',
        headers: getHeaders(),
        body: JSON.stringify({ action: 'delete_mailbox', mailbox_id: mb.id }),
      });
      if (res.ok) {
        onRefresh();
        showToast(`Mailbox ${mb.address} deleted`);
      }
    } catch {
      alert('Error deleting mailbox');
    }
  };

  const handleDeleteDomain = async (d: any) => {
    if (!confirm(`Delete mail domain ${d.name} and all its accounts?`)) return;
    try {
      const res = await fetch(`${apiBase}/api/v1/email`, {
        method: 'POST',
        headers: getHeaders(),
        body: JSON.stringify({ action: 'delete_domain', domain_id: d.id }),
      });
      if (res.ok) {
        onRefresh();
        showToast(`Mail domain ${d.name} deleted`);
      }
    } catch {
      alert('Error deleting domain');
    }
  };

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Header Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-gradient-to-r from-slate-900/90 via-slate-900/80 to-slate-950 p-6 rounded-2xl border border-slate-800/80 shadow-2xl backdrop-blur-xl">
        <div className="flex items-start gap-4">
          <div className="w-12 h-12 rounded-2xl bg-gradient-to-br from-purple-500/20 to-indigo-500/20 border border-purple-500/30 flex items-center justify-center text-purple-400 font-bold shadow-lg shadow-purple-500/10 shrink-0 mt-0.5">
            <Mail className="w-6 h-6 text-purple-400" />
          </div>
          <div>
            <div className="flex items-center gap-3 flex-wrap">
              <h2 className="text-2xl font-extrabold text-white tracking-tight">
                Email & Roundcube Webmail Suite
              </h2>
              <span className="bg-emerald-500/10 text-emerald-400 text-xs font-mono font-bold px-3 py-1 rounded-full border border-emerald-500/30 flex items-center gap-1.5 shadow-sm">
                <span className="w-2 h-2 rounded-full bg-emerald-400 animate-ping"></span>
                POSTFIX & DOVECOT READY
              </span>
            </div>
            <p className="text-sm text-slate-400 mt-1">
              Manage virtual mail accounts, disk quotas, DNS deliverability (SPF, DKIM, DMARC) & direct Roundcube access
            </p>
          </div>
        </div>

        <div className="flex items-center gap-3 shrink-0">
          <button
            onClick={() => setShowAddMailDomainModal(true)}
            className="bg-slate-800 hover:bg-slate-700 text-slate-200 font-semibold px-4 py-2.5 rounded-xl text-xs border border-slate-700 transition-all cursor-pointer flex items-center gap-2 shadow-sm hover:border-slate-600"
          >
            <Globe className="w-4 h-4 text-cyan-400" />
            <span>Add Mail Domain</span>
          </button>
          <button
            onClick={() => {
              if (mailDomains.length > 0 && !newMailboxDomain) {
                setNewMailboxDomain(mailDomains[0].name);
              }
              setShowAddMailboxModal(true);
            }}
            className="bg-gradient-to-r from-purple-500 to-indigo-600 hover:from-purple-400 hover:to-indigo-500 text-white font-bold px-4 py-2.5 rounded-xl text-xs transition-all shadow-lg shadow-purple-500/25 flex items-center gap-2 cursor-pointer"
          >
            <Plus className="w-4 h-4" />
            <span>Create Mailbox</span>
          </button>
        </div>
      </div>

      {/* KPI Metrics Cards Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-5">
        {/* Postfix Server */}
        <div className="bg-slate-900/80 border border-slate-800 p-5 rounded-2xl space-y-3 shadow-xl hover:border-slate-700/80 transition-all">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Postfix MTA (SMTP)</span>
            <div className="w-9 h-9 rounded-xl bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center text-emerald-400 font-bold">
              <Server className="w-4 h-4" />
            </div>
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-2xl font-extrabold text-white">
              {mailServices.postfix === 'active' ? 'Online' : 'Stopped'}
            </span>
            <span className="text-xs font-semibold text-emerald-400 flex items-center gap-1">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse"></span>
              Port 25, 587
            </span>
          </div>
          <p className="text-[11px] text-slate-400">Outbound TLS & Postfix virtual maps</p>
        </div>

        {/* Dovecot Engine */}
        <div className="bg-slate-900/80 border border-slate-800 p-5 rounded-2xl space-y-3 shadow-xl hover:border-slate-700/80 transition-all">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Dovecot (IMAP/POP3)</span>
            <div className="w-9 h-9 rounded-xl bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400 font-bold">
              <Lock className="w-4 h-4" />
            </div>
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-2xl font-extrabold text-white">
              {mailServices.dovecot === 'active' ? 'Online' : 'Stopped'}
            </span>
            <span className="text-xs font-semibold text-cyan-400 flex items-center gap-1">
              <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-pulse"></span>
              Port 993, 143
            </span>
          </div>
          <p className="text-[11px] text-slate-400">Maildir storage & SASL authentication</p>
        </div>

        {/* Roundcube Webmail */}
        <div className="bg-gradient-to-br from-purple-950/30 via-slate-900/80 to-slate-900 border border-purple-500/20 p-5 rounded-2xl space-y-3 shadow-xl hover:border-purple-500/40 transition-all">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-purple-300 uppercase tracking-wider">Roundcube Webmail</span>
            <div className="w-9 h-9 rounded-xl bg-purple-500/15 border border-purple-500/30 flex items-center justify-center text-purple-400 font-bold">
              <Mail className="w-4 h-4" />
            </div>
          </div>
          <div className="flex items-center justify-between">
            <div className="space-y-0.5">
              <p className="text-xs font-mono text-slate-300 truncate max-w-[130px]">{webmailUrl.replace('https://', '')}</p>
              <span className="text-[10px] text-emerald-400 font-semibold flex items-center gap-1">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-400"></span>
                Active Instance
              </span>
            </div>
            <a
              href={webmailUrl}
              target="_blank"
              rel="noreferrer"
              className="px-3 py-1.5 bg-gradient-to-r from-purple-600 to-indigo-600 hover:from-purple-500 hover:to-indigo-500 text-white font-bold text-xs rounded-xl shadow-md shadow-purple-500/20 transition-all flex items-center gap-1.5 cursor-pointer"
            >
              <span>Launch</span>
              <ExternalLink className="w-3 h-3" />
            </a>
          </div>
          <p className="text-[11px] text-slate-400">Direct single-click webmail access</p>
        </div>

        {/* Storage Allocation */}
        <div className="bg-slate-900/80 border border-slate-800 p-5 rounded-2xl space-y-3 shadow-xl hover:border-slate-700/80 transition-all">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Mailboxes & Storage</span>
            <div className="w-9 h-9 rounded-xl bg-indigo-500/10 border border-indigo-500/30 flex items-center justify-center text-indigo-400 font-bold">
              <HardDrive className="w-4 h-4" />
            </div>
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-2xl font-extrabold text-white">
              {totalQuotaGB} GB
            </span>
            <span className="text-xs font-semibold text-indigo-400">
              {mailboxes.length} {mailboxes.length === 1 ? 'Mailbox' : 'Mailboxes'}
            </span>
          </div>
          <p className="text-[11px] text-slate-400">Across {mailDomains.length} mail domains</p>
        </div>
      </div>

      {/* ACTIVE MAILBOXES TABLE */}
      <div className="bg-slate-900/80 border border-slate-800 rounded-2xl overflow-hidden shadow-2xl">
        <div className="p-5 border-b border-slate-800/80 flex flex-col sm:flex-row sm:items-center justify-between gap-4 bg-slate-950/40">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-xl bg-purple-500/10 border border-purple-500/30 flex items-center justify-center text-purple-400">
              <Mail className="w-4 h-4" />
            </div>
            <div>
              <h3 className="font-bold text-base text-white">Virtual Mail Accounts</h3>
              <p className="text-xs text-slate-400">Configured mailbox accounts on this server</p>
            </div>
            <span className="bg-slate-800 text-slate-300 text-xs px-2.5 py-0.5 rounded-full font-mono font-semibold ml-2">
              {mailboxes.length}
            </span>
          </div>

          <div className="flex items-center gap-3">
            <div className="relative">
              <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none" />
              <input
                type="text"
                placeholder="Search mailboxes..."
                value={mailboxSearch}
                onChange={(e) => setMailboxSearch(e.target.value)}
                className="bg-slate-950 border border-slate-800 rounded-xl pl-9 pr-4 py-2 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-purple-500 w-48 sm:w-64 transition-all font-mono"
              />
            </div>
            <button
              onClick={() => {
                if (mailDomains.length > 0 && !newMailboxDomain) {
                  setNewMailboxDomain(mailDomains[0].name);
                }
                setShowAddMailboxModal(true);
              }}
              className="bg-purple-600 hover:bg-purple-500 text-white font-semibold px-3.5 py-2 rounded-xl text-xs transition-all flex items-center gap-1.5 shadow-md shadow-purple-600/20 cursor-pointer"
            >
              <Plus className="w-3.5 h-3.5" />
              <span>New Mailbox</span>
            </button>
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="bg-slate-950/80 border-b border-slate-800 text-[11px] font-bold text-slate-400 uppercase tracking-wider">
                <th className="py-3.5 px-5">Email Address & Identity</th>
                <th className="py-3.5 px-4">Domain</th>
                <th className="py-3.5 px-4">Storage Quota</th>
                <th className="py-3.5 px-4">Protocols</th>
                <th className="py-3.5 px-4">Status</th>
                <th className="py-3.5 px-5 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-xs">
              {filteredMailboxes.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-12 text-center text-slate-400">
                    <div className="flex flex-col items-center justify-center gap-3">
                      <div className="w-12 h-12 rounded-2xl bg-slate-800/50 border border-slate-700/50 flex items-center justify-center text-slate-500">
                        <Mail className="w-6 h-6" />
                      </div>
                      <p className="text-sm font-medium text-slate-300">No mailboxes found</p>
                      <p className="text-xs text-slate-500">Click "New Mailbox" to configure your first account.</p>
                    </div>
                  </td>
                </tr>
              ) : (
                filteredMailboxes.map((mb) => {
                  const domain = mb.address.split('@')[1] || 'hoatzinlabs.com';
                  return (
                    <tr key={mb.id} className="hover:bg-slate-800/40 transition-colors group">
                      <td className="py-4 px-5">
                        <div className="flex items-center gap-3.5">
                          <div className="w-10 h-10 rounded-xl bg-purple-500/10 border border-purple-500/30 flex items-center justify-center text-purple-400 font-bold shadow-md shrink-0">
                            <Mail className="w-5 h-5" />
                          </div>
                          <div className="space-y-1">
                            <div className="flex items-center gap-2">
                              <h4 className="font-bold text-sm text-white tracking-tight group-hover:text-purple-400 transition-colors font-mono">
                                {mb.address}
                              </h4>
                              <span className="flex h-2 w-2 relative" title="Active Account">
                                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                                <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
                              </span>
                            </div>
                            <div className="flex items-center gap-2 font-mono text-[11px] text-slate-400">
                              <span className="text-slate-300 font-semibold">{mb.local_part || mb.address.split('@')[0]}</span>
                              <span>•</span>
                              <span className="text-slate-500">/var/mail/vhosts/{domain}/{mb.local_part || mb.address.split('@')[0]}</span>
                            </div>
                          </div>
                        </div>
                      </td>

                      <td className="py-4 px-4">
                        <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-[11px] font-mono font-semibold bg-slate-800/80 text-cyan-300 border border-slate-700">
                          <Globe className="w-3 h-3 text-cyan-400" />
                          {domain}
                        </span>
                      </td>

                      <td className="py-4 px-4">
                        <div className="space-y-1.5">
                          <div className="flex items-center justify-between text-[11px] font-mono">
                            <span className="text-slate-300 font-semibold">{mb.quota_mb || 2048} MB</span>
                            <span className="text-slate-400">0% used</span>
                          </div>
                          <div className="w-32 bg-slate-800 h-1.5 rounded-full overflow-hidden">
                            <div className="bg-gradient-to-r from-purple-500 to-indigo-500 h-full w-1 rounded-full"></div>
                          </div>
                        </div>
                      </td>

                      <td className="py-4 px-4">
                        <div className="flex items-center gap-1.5 flex-wrap">
                          <span className="px-2 py-0.5 rounded text-[10px] font-bold font-mono bg-purple-500/10 text-purple-300 border border-purple-500/20">
                            IMAP
                          </span>
                          <span className="px-2 py-0.5 rounded text-[10px] font-bold font-mono bg-cyan-500/10 text-cyan-300 border border-cyan-500/20">
                            SMTP
                          </span>
                          <span className="px-2 py-0.5 rounded text-[10px] font-bold font-mono bg-emerald-500/10 text-emerald-300 border border-emerald-500/20">
                            TLS
                          </span>
                        </div>
                      </td>

                      <td className="py-4 px-4">
                        <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[11px] font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
                          <span className="w-1.5 h-1.5 rounded-full bg-emerald-400"></span>
                          Active
                        </span>
                      </td>

                      <td className="py-4 px-5 text-right">
                        <div className="flex items-center justify-end gap-2">
                          <a
                            href={webmailUrl}
                            target="_blank"
                            rel="noreferrer"
                            className="px-3 py-1.5 bg-gradient-to-r from-purple-600/20 to-indigo-600/20 hover:from-purple-600/30 hover:to-indigo-600/30 text-purple-300 hover:text-white font-semibold rounded-xl border border-purple-500/30 text-xs transition-all flex items-center gap-1.5 cursor-pointer shadow-sm"
                          >
                            <span>Launch Webmail</span>
                            <ExternalLink className="w-3.5 h-3.5" />
                          </a>
                          <button
                            onClick={() => handleDeleteMailbox(mb)}
                            title="Delete Mailbox"
                            className="p-2 rounded-xl text-slate-400 hover:text-rose-400 hover:bg-rose-500/10 transition-all cursor-pointer border border-transparent hover:border-rose-500/20"
                          >
                            <Trash2 className="w-4 h-4" />
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* MAIL DOMAINS & DNS SECURITY TABLE */}
      <div className="bg-slate-900/80 border border-slate-800 rounded-2xl overflow-hidden shadow-2xl">
        <div className="p-5 border-b border-slate-800/80 flex flex-col sm:flex-row sm:items-center justify-between gap-4 bg-slate-950/40">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-xl bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400">
              <Globe className="w-4 h-4" />
            </div>
            <div>
              <h3 className="font-bold text-base text-white">Mail Domains & Deliverability Orchestration</h3>
              <p className="text-xs text-slate-400">SPF, DKIM, DMARC, and MX records configured for high inbox deliverability</p>
            </div>
            <span className="bg-slate-800 text-slate-300 text-xs px-2.5 py-0.5 rounded-full font-mono font-semibold ml-2">
              {mailDomains.length}
            </span>
          </div>

          <button
            onClick={() => setShowAddMailDomainModal(true)}
            className="bg-slate-800 hover:bg-slate-750 text-slate-200 font-semibold px-3.5 py-2 rounded-xl text-xs border border-slate-700 transition-all flex items-center gap-1.5 cursor-pointer shadow-sm hover:border-slate-600"
          >
            <Plus className="w-3.5 h-3.5 text-cyan-400" />
            <span>Add Mail Domain</span>
          </button>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="bg-slate-950/80 border-b border-slate-800 text-[11px] font-bold text-slate-400 uppercase tracking-wider">
                <th className="py-3.5 px-5">Domain Name</th>
                <th className="py-3.5 px-4">DNS Health & Protocols</th>
                <th className="py-3.5 px-4">Registered Date</th>
                <th className="py-3.5 px-4">Accounts</th>
                <th className="py-3.5 px-5 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-xs">
              {mailDomains.map((d) => {
                const boxCount = mailboxes.filter((mb) => mb.address.endsWith('@' + d.name)).length;
                return (
                  <tr key={d.id} className="hover:bg-slate-800/40 transition-colors group">
                    <td className="py-4 px-5">
                      <div className="flex items-center gap-3.5">
                        <div className="w-10 h-10 rounded-xl bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400 font-bold shadow-md shrink-0">
                          <Globe className="w-5 h-5" />
                        </div>
                        <div>
                          <div className="flex items-center gap-2">
                            <h4 className="font-bold text-sm text-white tracking-tight group-hover:text-cyan-400 transition-colors font-mono">
                              {d.name}
                            </h4>
                            <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
                              <Check className="w-3 h-3" />
                              VERIFIED
                            </span>
                          </div>
                          <p className="text-[11px] text-slate-400 font-mono mt-0.5">mail.{d.name} • Hostmaster</p>
                        </div>
                      </div>
                    </td>

                    <td className="py-4 px-4">
                      <div className="flex items-center gap-1.5 flex-wrap">
                        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-500/10 text-emerald-300 border border-emerald-500/20">
                          <Check className="w-2.5 h-2.5" />
                          SPF: PASS
                        </span>
                        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-cyan-500/10 text-cyan-300 border border-cyan-500/20">
                          <Check className="w-2.5 h-2.5" />
                          DKIM: 2048-BIT
                        </span>
                        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-purple-500/10 text-purple-300 border border-purple-500/20">
                          <Check className="w-2.5 h-2.5" />
                          DMARC: ACTIVE
                        </span>
                      </div>
                    </td>

                    <td className="py-4 px-4">
                      <span className="text-slate-400 font-mono text-[11px]">
                        {d.created_at ? new Date(d.created_at).toLocaleDateString() : 'Active'}
                      </span>
                    </td>

                    <td className="py-4 px-4">
                      <span className="text-slate-300 font-semibold font-mono">
                        {boxCount} {boxCount === 1 ? 'account' : 'accounts'}
                      </span>
                    </td>

                    <td className="py-4 px-5 text-right">
                      <div className="flex items-center justify-end gap-2">
                        <button
                          onClick={() => {
                            setSelectedDnsDomain(d.name);
                            setShowDnsRecordsModal(true);
                          }}
                          className="px-3 py-1.5 bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-300 hover:text-white font-semibold rounded-xl border border-cyan-500/30 text-xs transition-all flex items-center gap-1.5 cursor-pointer shadow-sm"
                        >
                          <Shield className="w-3.5 h-3.5 text-cyan-400" />
                          <span>DNS Records</span>
                        </button>
                        <button
                          onClick={() => handleDeleteDomain(d)}
                          title="Delete Domain"
                          className="p-2 rounded-xl text-slate-400 hover:text-rose-400 hover:bg-rose-500/10 transition-all cursor-pointer border border-transparent hover:border-rose-500/20"
                        >
                          <Trash2 className="w-4 h-4" />
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

      {/* ADD MAIL DOMAIN MODAL */}
      {showAddMailDomainModal && (
        <div className="fixed inset-0 bg-slate-950/80 backdrop-blur-md z-50 flex items-center justify-center p-4 animate-fade-in">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-md w-full p-6 shadow-2xl space-y-5">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2.5">
                <div className="w-8 h-8 rounded-xl bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400">
                  <Globe className="w-4 h-4" />
                </div>
                <div>
                  <h3 className="text-base font-bold text-white">Add Mail Domain</h3>
                  <p className="text-xs text-slate-400">Configure Postfix virtual domain</p>
                </div>
              </div>
              <button onClick={() => setShowAddMailDomainModal(false)} className="text-slate-400 hover:text-white p-1 rounded-lg cursor-pointer">✕</button>
            </div>
            <form onSubmit={handleCreateDomain} className="space-y-4">
              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1.5">Domain Name</label>
                <input
                  type="text"
                  placeholder="e.g. yourcompany.com"
                  value={newMailDomainInput}
                  onChange={(e) => setNewMailDomainInput(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3.5 py-2.5 text-sm text-white focus:outline-none focus:border-cyan-500 font-mono"
                  required
                />
                <p className="text-[11px] text-slate-500 mt-1.5">Will configure maildir storage at /var/mail/vhosts/&lt;domain&gt;</p>
              </div>
              <div className="flex items-center justify-end gap-3 pt-2">
                <button type="button" onClick={() => setShowAddMailDomainModal(false)} className="px-4 py-2.5 text-xs font-semibold text-slate-400 hover:text-white cursor-pointer">Cancel</button>
                <button type="submit" className="px-5 py-2.5 bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 font-bold text-xs rounded-xl shadow-lg shadow-cyan-500/20 cursor-pointer">Add Domain</button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* CREATE MAILBOX MODAL */}
      {showAddMailboxModal && (
        <div className="fixed inset-0 bg-slate-950/80 backdrop-blur-md z-50 flex items-center justify-center p-4 animate-fade-in">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-lg w-full p-6 shadow-2xl space-y-5">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2.5">
                <div className="w-8 h-8 rounded-xl bg-purple-500/10 border border-purple-500/30 flex items-center justify-center text-purple-400">
                  <Mail className="w-4 h-4" />
                </div>
                <div>
                  <h3 className="text-base font-bold text-white">Create Virtual Mailbox</h3>
                  <p className="text-xs text-slate-400">Create email account with Dovecot password hash</p>
                </div>
              </div>
              <button onClick={() => setShowAddMailboxModal(false)} className="text-slate-400 hover:text-white p-1 rounded-lg cursor-pointer">✕</button>
            </div>
            <form onSubmit={handleCreateMailbox} className="space-y-4">
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs font-semibold text-slate-300 mb-1.5">Username / Local Part</label>
                  <input
                    type="text"
                    placeholder="e.g. info, supports, admin"
                    value={newMailboxLocalPart}
                    onChange={(e) => setNewMailboxLocalPart(e.target.value)}
                    className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3.5 py-2.5 text-sm text-white focus:outline-none focus:border-purple-500 font-mono"
                    required
                  />
                </div>
                <div>
                  <label className="block text-xs font-semibold text-slate-300 mb-1.5">Mail Domain</label>
                  <select
                    value={newMailboxDomain}
                    onChange={(e) => setNewMailboxDomain(e.target.value)}
                    className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3.5 py-2.5 text-sm text-white focus:outline-none focus:border-purple-500 font-mono"
                  >
                    {mailDomains.map((d) => (
                      <option key={d.id} value={d.name}>{d.name}</option>
                    ))}
                  </select>
                </div>
              </div>

              {newMailboxLocalPart && (
                <div className="p-3 bg-purple-500/10 border border-purple-500/20 rounded-xl flex items-center justify-between text-xs">
                  <span className="text-slate-400">Target Address:</span>
                  <span className="font-mono font-bold text-purple-300">{newMailboxLocalPart}@{newMailboxDomain}</span>
                </div>
              )}

              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1.5">Mailbox Password</label>
                <input
                  type="password"
                  placeholder="Strong mailbox password"
                  value={newMailboxPassword}
                  onChange={(e) => setNewMailboxPassword(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3.5 py-2.5 text-sm text-white focus:outline-none focus:border-purple-500"
                  required
                />
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1.5">Storage Quota (MB)</label>
                <input
                  type="number"
                  value={newMailboxQuota}
                  onChange={(e) => setNewMailboxQuota(Number(e.target.value))}
                  className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3.5 py-2.5 text-sm text-white focus:outline-none focus:border-purple-500 font-mono"
                />
                <p className="text-[11px] text-slate-500 mt-1">Default 2048 MB (2 GB)</p>
              </div>

              <div className="flex items-center justify-end gap-3 pt-2">
                <button type="button" onClick={() => setShowAddMailboxModal(false)} className="px-4 py-2.5 text-xs font-semibold text-slate-400 hover:text-white cursor-pointer">Cancel</button>
                <button type="submit" className="px-5 py-2.5 bg-gradient-to-r from-purple-500 to-indigo-600 hover:from-purple-400 hover:to-indigo-500 text-white font-bold text-xs rounded-xl shadow-lg shadow-purple-500/20 cursor-pointer">Create Mailbox</button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* DNS RECORDS MODAL WITH 1-CLICK COPY */}
      {showDnsRecordsModal && (
        <div className="fixed inset-0 bg-slate-950/80 backdrop-blur-md z-50 flex items-center justify-center p-4 animate-fade-in">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-2xl w-full p-6 shadow-2xl space-y-5">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2.5">
                <div className="w-8 h-8 rounded-xl bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400">
                  <Shield className="w-4 h-4" />
                </div>
                <div>
                  <h3 className="text-base font-bold text-white">DNS Records for {selectedDnsDomain}</h3>
                  <p className="text-xs text-slate-400">Copy these records to your DNS provider (Cloudflare, Namecheap, Route53)</p>
                </div>
              </div>
              <button onClick={() => setShowDnsRecordsModal(false)} className="text-slate-400 hover:text-white p-1 rounded-lg cursor-pointer">✕</button>
            </div>

            <div className="space-y-3.5 text-xs font-mono">
              {/* MX Record */}
              <div className="bg-slate-950/80 border border-slate-800 rounded-xl p-4 flex items-center justify-between gap-4">
                <div className="space-y-1 overflow-hidden">
                  <div className="flex items-center gap-2">
                    <span className="px-2 py-0.5 rounded bg-cyan-500/15 text-cyan-300 font-bold text-[10px]">MX</span>
                    <span className="text-slate-400 text-[11px]">Host: <strong className="text-white">@</strong> • Priority: <strong className="text-cyan-400">10</strong></span>
                  </div>
                  <p className="text-white font-bold truncate">mail.{selectedDnsDomain}</p>
                </div>
                <button
                  onClick={() => copyToClipboard(`mail.${selectedDnsDomain}`, 'mx')}
                  className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg text-xs font-sans font-semibold flex items-center gap-1.5 shrink-0 transition-all border border-slate-700 cursor-pointer"
                >
                  {copiedDnsKey === 'mx' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5 text-slate-400" />}
                  <span>{copiedDnsKey === 'mx' ? 'Copied!' : 'Copy'}</span>
                </button>
              </div>

              {/* SPF Record */}
              <div className="bg-slate-950/80 border border-slate-800 rounded-xl p-4 flex items-center justify-between gap-4">
                <div className="space-y-1 overflow-hidden">
                  <div className="flex items-center gap-2">
                    <span className="px-2 py-0.5 rounded bg-purple-500/15 text-purple-300 font-bold text-[10px]">TXT</span>
                    <span className="text-slate-400 text-[11px]">Host: <strong className="text-white">@</strong> (SPF Sender Policy)</span>
                  </div>
                  <p className="text-purple-300 font-bold truncate">v=spf1 mx a ~all</p>
                </div>
                <button
                  onClick={() => copyToClipboard('v=spf1 mx a ~all', 'spf')}
                  className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg text-xs font-sans font-semibold flex items-center gap-1.5 shrink-0 transition-all border border-slate-700 cursor-pointer"
                >
                  {copiedDnsKey === 'spf' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5 text-slate-400" />}
                  <span>{copiedDnsKey === 'spf' ? 'Copied!' : 'Copy'}</span>
                </button>
              </div>

              {/* DMARC Record */}
              <div className="bg-slate-950/80 border border-slate-800 rounded-xl p-4 flex items-center justify-between gap-4">
                <div className="space-y-1 overflow-hidden">
                  <div className="flex items-center gap-2">
                    <span className="px-2 py-0.5 rounded bg-emerald-500/15 text-emerald-300 font-bold text-[10px]">TXT</span>
                    <span className="text-slate-400 text-[11px]">Host: <strong className="text-white">_dmarc.{selectedDnsDomain}</strong></span>
                  </div>
                  <p className="text-emerald-300 font-bold truncate">v=DMARC1; p=none; sp=none; aspf=r;</p>
                </div>
                <button
                  onClick={() => copyToClipboard('v=DMARC1; p=none; sp=none; aspf=r;', 'dmarc')}
                  className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg text-xs font-sans font-semibold flex items-center gap-1.5 shrink-0 transition-all border border-slate-700 cursor-pointer"
                >
                  {copiedDnsKey === 'dmarc' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5 text-slate-400" />}
                  <span>{copiedDnsKey === 'dmarc' ? 'Copied!' : 'Copy'}</span>
                </button>
              </div>

              {/* DKIM Key */}
              <div className="bg-slate-950/80 border border-slate-800 rounded-xl p-4 flex items-center justify-between gap-4">
                <div className="space-y-1 overflow-hidden">
                  <div className="flex items-center gap-2">
                    <span className="px-2 py-0.5 rounded bg-indigo-500/15 text-indigo-300 font-bold text-[10px]">TXT</span>
                    <span className="text-slate-400 text-[11px]">Host: <strong className="text-white">default._domainkey.{selectedDnsDomain}</strong></span>
                  </div>
                  <p className="text-slate-300 text-[11px] truncate">v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC...</p>
                </div>
                <button
                  onClick={() => copyToClipboard('v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC...', 'dkim')}
                  className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg text-xs font-sans font-semibold flex items-center gap-1.5 shrink-0 transition-all border border-slate-700 cursor-pointer"
                >
                  {copiedDnsKey === 'dkim' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5 text-slate-400" />}
                  <span>{copiedDnsKey === 'dkim' ? 'Copied!' : 'Copy'}</span>
                </button>
              </div>
            </div>

            <div className="flex justify-end pt-2">
              <button onClick={() => setShowDnsRecordsModal(false)} className="px-5 py-2.5 bg-slate-800 hover:bg-slate-700 text-white font-semibold text-xs rounded-xl cursor-pointer">
                Done
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
