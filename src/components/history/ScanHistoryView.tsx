import React, { useState } from 'react';
import {
  Clock,
  Search,
  Filter,
  Download,
  Trash2,
  ExternalLink,
  Lock,
  RefreshCw,
  ChevronRight,
  Database,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle
} from 'lucide-react';
import { ScanHistoryItem } from '../../types/security';
import { RiskBadge } from '../common/RiskBadge';
import { apiService } from '../../services/api';

interface ScanHistoryViewProps {
  history: ScanHistoryItem[];
  onSelectResult: (scanId: string) => void;
  onRescan: (url: string) => void;
  onClearHistory: () => void;
}

export const ScanHistoryView: React.FC<ScanHistoryViewProps> = ({
  history,
  onSelectResult,
  onRescan,
  onClearHistory,
}) => {
  const [searchQuery, setSearchQuery] = useState('');
  const [riskFilter, setRiskFilter] = useState<'all' | 'safe' | 'suspicious' | 'critical'>('all');

  const filteredHistory = history.filter(item => {
    const matchesSearch =
      searchQuery === '' ||
      item.url.toLowerCase().includes(searchQuery.toLowerCase());

    const matchesFilter =
      riskFilter === 'all' ||
      (riskFilter === 'safe' && (item.verdict === 'safe' || item.riskLevel === 'low')) ||
      (riskFilter === 'suspicious' && (item.verdict === 'suspicious' || item.riskLevel === 'moderate' || item.riskLevel === 'high')) ||
      (riskFilter === 'critical' && (item.verdict === 'critical' || item.riskLevel === 'critical'));

    return matchesSearch && matchesFilter;
  });

  const exportCsv = () => {
    const headers = ['ID', 'URL', 'RiskScore', 'RiskLevel', 'Verdict', 'SSLValid', 'PhishingDetected', 'ScannedAt', 'DurationMs'];
    const rows = filteredHistory.map(item => [
      item.id,
      `"${item.url}"`,
      item.riskScore,
      item.riskLevel,
      item.verdict,
      item.sslValid ? 'true' : 'false',
      item.phishingDetected ? 'true' : 'false',
      `"${item.scannedAt}"`,
      item.scanDurationMs,
    ]);

    const csvContent = 'data:text/csv;charset=utf-8,' + [headers.join(','), ...rows.map(r => r.join(','))].join('\n');
    const encodedUri = encodeURI(csvContent);
    const link = document.createElement('a');
    link.setAttribute('href', encodedUri);
    link.setAttribute('download', `cybershield-history-${new Date().toISOString().split('T')[0]}.csv`);
    document.body.appendChild(link);
    link.click();
    link.remove();
  };

  const exportJson = () => {
    const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(filteredHistory, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute('href', dataStr);
    downloadAnchor.setAttribute('download', `cybershield-history-${new Date().toISOString().split('T')[0]}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  return (
    <div className="space-y-6 max-w-6xl mx-auto animate-fade-in">
      {/* Top Banner */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-slate-800">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2.5">
            <Clock className="h-6 w-6 text-blue-400" />
            <span>Scan History & Audit Logs</span>
          </h1>
          <p className="mt-1 text-sm text-slate-400">
            Chronological register of evaluated domains, SSL certifications, and risk classifications.
          </p>
        </div>

        <div className="flex items-center gap-2 self-start sm:self-auto">
          <button
            onClick={exportCsv}
            disabled={filteredHistory.length === 0}
            className="flex items-center gap-1.5 px-3 py-2 text-xs font-medium rounded-lg bg-slate-900 hover:bg-slate-800 text-slate-200 border border-slate-800 transition-colors disabled:opacity-50"
          >
            <Download className="h-3.5 w-3.5" />
            <span>Export CSV</span>
          </button>
          <button
            onClick={exportJson}
            disabled={filteredHistory.length === 0}
            className="flex items-center gap-1.5 px-3 py-2 text-xs font-medium rounded-lg bg-slate-900 hover:bg-slate-800 text-slate-200 border border-slate-800 transition-colors disabled:opacity-50"
          >
            <Download className="h-3.5 w-3.5" />
            <span>Export JSON</span>
          </button>
          <button
            onClick={onClearHistory}
            disabled={history.length === 0}
            className="flex items-center gap-1.5 px-3 py-2 text-xs font-medium rounded-lg bg-rose-950/40 hover:bg-rose-900/60 text-rose-300 border border-rose-900/40 transition-colors disabled:opacity-50"
          >
            <Trash2 className="h-3.5 w-3.5" />
            <span>Clear</span>
          </button>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="flex flex-col sm:flex-row gap-3 items-stretch sm:items-center justify-between">
        <div className="relative flex-1 max-w-md">
          <Search className="absolute left-3.5 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-400" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search inspected URLs..."
            className="w-full rounded-lg border border-slate-800 bg-slate-900/80 py-2 pl-9 pr-4 text-xs font-mono text-slate-200 placeholder-slate-500 focus:border-blue-500 focus:outline-none"
          />
        </div>

        {/* Filter buttons */}
        <div className="flex items-center gap-1 p-1 bg-slate-900/80 rounded-lg border border-slate-800 self-start sm:self-auto">
          {(['all', 'safe', 'suspicious', 'critical'] as const).map(tab => (
            <button
              key={tab}
              onClick={() => setRiskFilter(tab)}
              className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors capitalize whitespace-nowrap ${
                riskFilter === tab
                  ? 'bg-blue-600 text-white shadow-sm'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              {tab}
            </button>
          ))}
        </div>
      </div>

      {/* History Table */}
      <div className="rounded-xl border border-slate-800 bg-[#0c1322] shadow-xl overflow-hidden">
        {filteredHistory.length === 0 ? (
          <div className="py-16 text-center text-slate-400 space-y-3">
            <Database className="h-8 w-8 mx-auto text-slate-600" />
            <p className="text-sm">No historical scans recorded matching this filter.</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="border-b border-slate-800 bg-slate-900/40 text-slate-400 font-semibold">
                  <th className="py-3 px-4">Scanned Website URL</th>
                  <th className="py-3 px-4">Classification</th>
                  <th className="py-3 px-4 hidden sm:table-cell">SSL Cryptography</th>
                  <th className="py-3 px-4 hidden md:table-cell">Timestamp</th>
                  <th className="py-3 px-4 hidden lg:table-cell text-right">Latency</th>
                  <th className="py-3 px-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {filteredHistory.map(item => (
                  <tr
                    key={item.id}
                    className="hover:bg-slate-850/40 transition-colors group cursor-pointer"
                    onClick={() => onSelectResult(item.id)}
                  >
                    <td className="py-3.5 px-4">
                      <div className="font-mono text-slate-200 font-medium truncate max-w-[220px] sm:max-w-sm md:max-w-md">
                        {item.url}
                      </div>
                      <div className="text-[11px] text-slate-500 flex items-center gap-2 mt-0.5 sm:hidden">
                        <span>{new Date(item.scannedAt).toLocaleDateString()}</span>
                        {item.isMockData && (
                          <>
                            <span aria-hidden="true">·</span>
                            <span className="text-indigo-400">Preview</span>
                          </>
                        )}
                      </div>
                    </td>

                    <td className="py-3.5 px-4">
                      <RiskBadge score={item.riskScore} level={item.riskLevel} size="sm" />
                    </td>

                    <td className="py-3.5 px-4 hidden sm:table-cell">
                      <span className={`inline-flex items-center gap-1.5 ${item.sslValid ? 'text-emerald-400' : 'text-rose-400'}`}>
                        <Lock className="h-3.5 w-3.5" />
                        <span>{item.sslValid ? 'Valid SSL' : 'Untrusted / Insecure'}</span>
                      </span>
                    </td>

                    <td className="py-3.5 px-4 hidden md:table-cell font-mono text-slate-400 tabular-nums">
                      {new Date(item.scannedAt).toLocaleString()}
                      {item.isMockData && (
                        <span className="block text-[10px] text-indigo-400">Preview Mock</span>
                      )}
                    </td>

                    <td className="py-3.5 px-4 hidden lg:table-cell text-right font-mono text-slate-400 tabular-nums">
                      {item.scanDurationMs}ms
                    </td>

                    <td className="py-3.5 px-4 text-right">
                      <div className="flex items-center justify-end gap-2">
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            onRescan(item.url);
                          }}
                          title="Re-run assessment"
                          className="p-1 rounded text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition-colors"
                        >
                          <RefreshCw className="h-3.5 w-3.5" />
                        </button>
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            onSelectResult(item.id);
                          }}
                          className="inline-flex items-center gap-1 text-blue-400 hover:text-blue-300 font-medium px-2 py-1 rounded bg-blue-950/30 border border-blue-800/40 hover:bg-blue-950/60 transition-colors"
                        >
                          <span>Inspect</span>
                          <ChevronRight className="h-3.5 w-3.5" />
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
    </div>
  );
};
