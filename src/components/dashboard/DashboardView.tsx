import React, { useState } from 'react';
import {
  ShieldCheck,
  AlertTriangle,
  ShieldAlert,
  Search,
  ArrowRight,
  TrendingUp,
  Globe,
  Radio,
  ExternalLink,
  Clock,
  Lock,
  ChevronRight,
  Database,
  Info
} from 'lucide-react';
import { ScanHistoryItem, RiskLevel } from '../../types/security';
import { RiskBadge } from '../common/RiskBadge';

interface DashboardViewProps {
  history: ScanHistoryItem[];
  onStartScan: (url: string) => void;
  onSelectResult: (scanId: string) => void;
  onNavigateToScanner: () => void;
  onNavigateToThreats: () => void;
}

export const DashboardView: React.FC<DashboardViewProps> = ({
  history,
  onStartScan,
  onSelectResult,
  onNavigateToScanner,
  onNavigateToThreats,
}) => {
  const [quickUrl, setQuickUrl] = useState('');
  const [historyFilter, setHistoryFilter] = useState<'all' | 'safe' | 'suspicious' | 'critical'>('all');

  // Compute aggregate statistics
  const totalScans = history.length;
  const safeCount = history.filter(h => h.verdict === 'safe' || h.riskLevel === 'low').length;
  const suspiciousCount = history.filter(h => h.verdict === 'suspicious' || h.riskLevel === 'moderate' || h.riskLevel === 'high').length;
  const criticalCount = history.filter(h => h.verdict === 'critical' || h.riskLevel === 'critical').length;

  const filteredHistory = history.filter(item => {
    if (historyFilter === 'all') return true;
    if (historyFilter === 'safe') return item.verdict === 'safe' || item.riskLevel === 'low';
    if (historyFilter === 'suspicious') return item.verdict === 'suspicious' || item.riskLevel === 'moderate' || item.riskLevel === 'high';
    if (historyFilter === 'critical') return item.verdict === 'critical' || item.riskLevel === 'critical';
    return true;
  });

  const handleQuickSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (quickUrl.trim()) {
      onStartScan(quickUrl.trim());
    }
  };

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Top Hero Banner & Quick Scanner Input */}
      <div className="rounded-xl border border-slate-800 bg-gradient-to-r from-[#0c1527] via-[#0d1830] to-[#12142d] p-6 lg:p-8 shadow-xl relative overflow-hidden">
        {/* Subtle decorative radial grid gradient */}
        <div className="absolute -right-20 -top-20 h-72 w-72 rounded-full bg-blue-500/5 blur-3xl pointer-events-none" />
        <div className="relative z-10 max-w-3xl">
          <div className="text-xs font-semibold text-blue-400 uppercase tracking-wider mb-2">
            Threat Prevention & Website Auditing
          </div>
          <h1 className="text-2xl lg:text-3xl font-extrabold tracking-tight text-white">
            Intelligent Phishing & Web Infrastructure Defense
          </h1>
          <p className="mt-2 text-sm text-slate-300 leading-relaxed">
            Real-time heuristic evaluation of brand impersonation, SSL/TLS cryptographic health, HTTP security headers, and domain reputation.
          </p>

          {/* Quick Scan Input */}
          <form onSubmit={handleQuickSubmit} className="mt-6 flex flex-col sm:flex-row gap-2 max-w-2xl">
            <div className="relative flex-1">
              <div className="absolute inset-y-0 left-0 flex items-center pl-3.5 pointer-events-none text-slate-400">
                <Globe className="h-4 w-4" />
              </div>
              <input
                type="text"
                value={quickUrl}
                onChange={(e) => setQuickUrl(e.target.value)}
                placeholder="Enter domain or URL (e.g. login-secure-portal.com)"
                className="w-full rounded-lg border border-slate-700/80 bg-slate-950/80 py-2.5 pl-10 pr-4 text-sm text-slate-100 placeholder-slate-500 focus:border-blue-500 focus:outline-none focus:ring-1 focus:ring-blue-500 transition-all font-mono"
              />
            </div>
            <button
              type="submit"
              className="flex items-center justify-center gap-2 rounded-lg bg-blue-600 px-5 py-2.5 text-sm font-semibold text-white hover:bg-blue-500 active:bg-blue-700 transition-colors shadow-lg shadow-blue-600/25 shrink-0"
            >
              <span>Scan Target</span>
              <ArrowRight className="h-4 w-4" />
            </button>
          </form>

          {/* Quick sample chips */}
          <div className="mt-3 flex items-center flex-wrap gap-2 text-xs text-slate-400">
            <span className="text-slate-500">Test presets:</span>
            <button
              type="button"
              onClick={() => onStartScan('https://github.com')}
              className="hover:text-emerald-400 transition-colors cursor-pointer text-slate-300 underline underline-offset-2 decoration-slate-600"
            >
              github.com (Safe)
            </button>
            <span aria-hidden="true" className="text-slate-600">·</span>
            <button
              type="button"
              onClick={() => onStartScan('https://secure-login-wellsfargo-verify99.net/auth/portal')}
              className="hover:text-rose-400 transition-colors cursor-pointer text-slate-300 underline underline-offset-2 decoration-slate-600"
            >
              wellsfargo-verify99.net (Phishing)
            </button>
            <span aria-hidden="true" className="text-slate-600">·</span>
            <button
              type="button"
              onClick={() => onStartScan('http://paypa1-update-account.biz/re-login')}
              className="hover:text-amber-400 transition-colors cursor-pointer text-slate-300 underline underline-offset-2 decoration-slate-600"
            >
              paypa1-update.biz (Typosquat)
            </button>
          </div>
        </div>
      </div>

      {/* 4 Metric Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Card 1: Total Scans */}
        <div className="rounded-xl border border-slate-800 bg-[#0d1424] p-5 relative overflow-hidden">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400">Total Scanned Websites</span>
            <div className="rounded-md bg-blue-500/10 p-2 text-blue-400">
              <Globe className="h-4 w-4" />
            </div>
          </div>
          <div className="mt-3 flex items-baseline gap-2">
            <span className="text-2xl font-bold tracking-tight text-white font-mono tabular-nums">
              {totalScans}
            </span>
            <span className="text-xs text-slate-400">inspected URLs</span>
          </div>
          <div className="mt-3 text-xs text-slate-400 flex items-center gap-1.5">
            <span className="h-1.5 w-1.5 rounded-full bg-blue-400" />
            <span>Continuous threat telemetry active</span>
          </div>
        </div>

        {/* Card 2: Safe Websites */}
        <div className="rounded-xl border border-slate-800 bg-[#0d1424] p-5 relative overflow-hidden">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400">Safe Websites</span>
            <div className="rounded-md bg-emerald-500/10 p-2 text-emerald-400">
              <ShieldCheck className="h-4 w-4" />
            </div>
          </div>
          <div className="mt-3 flex items-baseline gap-2">
            <span className="text-2xl font-bold tracking-tight text-emerald-400 font-mono tabular-nums">
              {safeCount}
            </span>
            <span className="text-xs text-slate-400">
              ({totalScans > 0 ? Math.round((safeCount / totalScans) * 100) : 0}%)
            </span>
          </div>
          <div className="mt-3 text-xs text-slate-400 flex items-center gap-1.5">
            <span className="h-1.5 w-1.5 rounded-full bg-emerald-400" />
            <span>Valid TLS & trusted reputation</span>
          </div>
        </div>

        {/* Card 3: Suspicious Websites */}
        <div className="rounded-xl border border-slate-800 bg-[#0d1424] p-5 relative overflow-hidden">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400">Suspicious Websites</span>
            <div className="rounded-md bg-amber-500/10 p-2 text-amber-400">
              <AlertTriangle className="h-4 w-4" />
            </div>
          </div>
          <div className="mt-3 flex items-baseline gap-2">
            <span className="text-2xl font-bold tracking-tight text-amber-400 font-mono tabular-nums">
              {suspiciousCount}
            </span>
            <span className="text-xs text-slate-400">
              ({totalScans > 0 ? Math.round((suspiciousCount / totalScans) * 100) : 0}%)
            </span>
          </div>
          <div className="mt-3 text-xs text-slate-400 flex items-center gap-1.5">
            <span className="h-1.5 w-1.5 rounded-full bg-amber-400" />
            <span>Missing headers or typosquat risk</span>
          </div>
        </div>

        {/* Card 4: Critical Threats */}
        <div className="rounded-xl border border-slate-800 bg-[#0d1424] p-5 relative overflow-hidden">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400">Critical Threats</span>
            <div className="rounded-md bg-rose-500/10 p-2 text-rose-400">
              <ShieldAlert className="h-4 w-4" />
            </div>
          </div>
          <div className="mt-3 flex items-baseline gap-2">
            <span className="text-2xl font-bold tracking-tight text-rose-400 font-mono tabular-nums">
              {criticalCount}
            </span>
            <span className="text-xs text-slate-400">
              ({totalScans > 0 ? Math.round((criticalCount / totalScans) * 100) : 0}%)
            </span>
          </div>
          <div className="mt-3 text-xs text-slate-400 flex items-center gap-1.5">
            <span className="h-1.5 w-1.5 rounded-full bg-rose-400" />
            <span>Phishing lures & credential traps</span>
          </div>
        </div>
      </div>

      {/* Risk Distribution Breakdown Bar */}
      <div className="rounded-xl border border-slate-800 bg-[#0c1322] p-5">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-3 border-b border-slate-800">
          <div>
            <h2 className="text-sm font-semibold text-slate-200">Threat Distribution Breakdown</h2>
            <p className="text-xs text-slate-400">Proportionate assessment across all verified scans</p>
          </div>
          <div className="flex items-center gap-4 text-xs font-mono">
            <span className="flex items-center gap-1 text-emerald-400">
              <span className="h-2 w-2 rounded-full bg-emerald-400" /> Safe: {safeCount}
            </span>
            <span className="flex items-center gap-1 text-amber-400">
              <span className="h-2 w-2 rounded-full bg-amber-400" /> Suspicious: {suspiciousCount}
            </span>
            <span className="flex items-center gap-1 text-rose-400">
              <span className="h-2 w-2 rounded-full bg-rose-400" /> Critical: {criticalCount}
            </span>
          </div>
        </div>

        {/* Visual Bar Ratio */}
        <div className="mt-4">
          <div className="h-3 w-full rounded-full bg-slate-900 flex overflow-hidden p-0.5 border border-slate-800">
            <div
              style={{ width: `${totalScans > 0 ? (safeCount / totalScans) * 100 : 33}%` }}
              className="h-full bg-emerald-500 rounded-l-full transition-all duration-500"
              title={`Safe: ${safeCount}`}
            />
            <div
              style={{ width: `${totalScans > 0 ? (suspiciousCount / totalScans) * 100 : 33}%` }}
              className="h-full bg-amber-500 transition-all duration-500"
              title={`Suspicious: ${suspiciousCount}`}
            />
            <div
              style={{ width: `${totalScans > 0 ? (criticalCount / totalScans) * 100 : 34}%` }}
              className="h-full bg-rose-500 rounded-r-full transition-all duration-500"
              title={`Critical: ${criticalCount}`}
            />
          </div>
          <div className="mt-2 flex justify-between text-[11px] text-slate-500 font-mono">
            <span>Low Risk (0–24)</span>
            <span>Moderate (25–54)</span>
            <span>High Risk (55–79)</span>
            <span>Critical Severity (80–100)</span>
          </div>
        </div>
      </div>

      {/* Main Content Split: Recent Scanning Activity + Community Threat Ticker */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left 2 Cols: Recent Scanning Activity */}
        <div className="lg:col-span-2 rounded-xl border border-slate-800 bg-[#0c1322] p-5 flex flex-col justify-between">
          <div>
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-4 border-b border-slate-800">
              <div>
                <h2 className="text-base font-semibold text-slate-100">Recent Scanning Activity</h2>
                <p className="text-xs text-slate-400">Live feed of websites evaluated by CyberShield AI</p>
              </div>

              {/* Filter Tabs (Interactive segmented buttons adhering to Section 1.A) */}
              <div className="flex items-center gap-1 p-1 bg-slate-900/90 rounded-lg border border-slate-800 self-start sm:self-auto">
                {(['all', 'safe', 'suspicious', 'critical'] as const).map(filter => (
                  <button
                    key={filter}
                    onClick={() => setHistoryFilter(filter)}
                    className={`px-2.5 py-1 text-xs font-medium rounded-md transition-colors capitalize whitespace-nowrap ${
                      historyFilter === filter
                        ? 'bg-slate-800 text-white shadow-sm'
                        : 'text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    {filter}
                  </button>
                ))}
              </div>
            </div>

            {/* Table of Scans */}
            <div className="mt-3 overflow-x-auto">
              {filteredHistory.length === 0 ? (
                <div className="py-12 text-center text-slate-400">
                  <Database className="h-8 w-8 mx-auto text-slate-600 mb-2" />
                  <p className="text-sm">No scanning records found for this filter.</p>
                </div>
              ) : (
                <table className="w-full text-left text-xs">
                  <thead>
                    <tr className="border-b border-slate-800/80 text-slate-400 font-medium">
                      <th className="py-2.5 px-3">Target Domain</th>
                      <th className="py-2.5 px-3">Risk Assessment</th>
                      <th className="py-2.5 px-3 hidden sm:table-cell">SSL Status</th>
                      <th className="py-2.5 px-3 hidden md:table-cell text-right">Duration</th>
                      <th className="py-2.5 px-3 text-right">Action</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60">
                    {filteredHistory.slice(0, 7).map(item => (
                      <tr
                        key={item.id}
                        className="hover:bg-slate-850/40 transition-colors group cursor-pointer"
                        onClick={() => onSelectResult(item.id)}
                      >
                        <td className="py-3 px-3">
                          <div className="font-mono text-slate-200 font-medium truncate max-w-[200px] sm:max-w-xs">
                            {item.url}
                          </div>
                          <div className="text-[11px] text-slate-500 flex items-center gap-2 mt-0.5">
                            <span>{new Date(item.scannedAt).toLocaleTimeString()}</span>
                            {item.isMockData && (
                              <>
                                <span aria-hidden="true">·</span>
                                <span className="text-indigo-400/80">Preview Mock</span>
                              </>
                            )}
                          </div>
                        </td>
                        <td className="py-3 px-3">
                          <RiskBadge score={item.riskScore} level={item.riskLevel} size="sm" />
                        </td>
                        <td className="py-3 px-3 hidden sm:table-cell">
                          <span className={`inline-flex items-center gap-1 ${item.sslValid ? 'text-emerald-400' : 'text-rose-400'}`}>
                            <Lock className="h-3 w-3" />
                            <span>{item.sslValid ? 'Valid' : 'Invalid / Insecure'}</span>
                          </span>
                        </td>
                        <td className="py-3 px-3 hidden md:table-cell text-right font-mono text-slate-400 tabular-nums">
                          {item.scanDurationMs}ms
                        </td>
                        <td className="py-3 px-3 text-right">
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              onSelectResult(item.id);
                            }}
                            className="inline-flex items-center gap-1 text-blue-400 hover:text-blue-300 font-medium transition-colors"
                          >
                            <span>Inspect</span>
                            <ChevronRight className="h-3.5 w-3.5" />
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          </div>

          <div className="pt-4 border-t border-slate-800/80 flex items-center justify-between text-xs text-slate-400">
            <span>Showing recent website audits</span>
            <button
              onClick={onNavigateToScanner}
              className="text-blue-400 hover:text-blue-300 font-medium inline-flex items-center gap-1"
            >
              <span>Open Detailed URL Scanner</span>
              <ChevronRight className="h-3.5 w-3.5" />
            </button>
          </div>
        </div>

        {/* Right 1 Col: Security Intel Highlights */}
        <div className="rounded-xl border border-slate-800 bg-[#0c1322] p-5 flex flex-col justify-between">
          <div>
            <div className="pb-3 border-b border-slate-800 flex items-center justify-between">
              <div>
                <h2 className="text-sm font-semibold text-slate-200">Threat Intelligence Highlights</h2>
                <p className="text-xs text-slate-400">Active phishing campaigns & homoglyphs</p>
              </div>
              <button
                onClick={onNavigateToThreats}
                className="text-xs text-blue-400 hover:text-blue-300 font-medium"
              >
                View Feed
              </button>
            </div>

            <div className="mt-4 space-y-3.5">
              <div className="p-3 rounded-lg border border-slate-800 bg-slate-900/60">
                <div className="flex items-center justify-between text-xs text-rose-400 font-semibold">
                  <span>Banking Clone Detected</span>
                  <span className="text-[11px] text-slate-500 font-mono">1h ago</span>
                </div>
                <div className="mt-1 font-mono text-xs text-slate-300 break-all">
                  secure-login-wellsfargo-verify99.net
                </div>
                <p className="mt-1 text-[11px] text-slate-400">
                  Impersonates Wells Fargo authentication with 2FA intercept logic. Flagged by 14 engines.
                </p>
              </div>

              <div className="p-3 rounded-lg border border-slate-800 bg-slate-900/60">
                <div className="flex items-center justify-between text-xs text-amber-400 font-semibold">
                  <span>Homograph Typosquat</span>
                  <span className="text-[11px] text-slate-500 font-mono">2h ago</span>
                </div>
                <div className="mt-1 font-mono text-xs text-slate-300 break-all">
                  paypa1-update-account.biz
                </div>
                <p className="mt-1 text-[11px] text-slate-400">
                  Replaces lower 'l' with numeral '1'. Unencrypted HTTP endpoint gathering passwords.
                </p>
              </div>

              <div className="p-3 rounded-lg border border-slate-800 bg-slate-900/60">
                <div className="flex items-center justify-between text-xs text-rose-400 font-semibold">
                  <span>Cloud Storage Phish</span>
                  <span className="text-[11px] text-slate-500 font-mono">3h ago</span>
                </div>
                <div className="mt-1 font-mono text-xs text-slate-300 break-all">
                  apple-id-verify-icloud-sync.cc
                </div>
                <p className="mt-1 text-[11px] text-slate-400">
                  Fake storage limit notification harvesting Apple ID credentials.
                </p>
              </div>
            </div>
          </div>

          <div className="mt-4 pt-3 border-t border-slate-800/80">
            <button
              onClick={onNavigateToThreats}
              className="w-full flex items-center justify-center gap-1.5 py-2 px-3 text-xs font-medium text-slate-200 bg-slate-850 hover:bg-slate-800 border border-slate-700/60 rounded-lg transition-colors"
            >
              <span>Submit Suspicious Domain Report</span>
              <ArrowRight className="h-3.5 w-3.5" />
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
