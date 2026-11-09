import React, { useState } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Lock,
  Globe,
  FileCode,
  ArrowRight,
  ExternalLink,
  Download,
  Copy,
  Check,
  RefreshCw,
  Info,
  Server,
  Layers,
  Share2,
  Calendar,
  Key,
  Shield,
  Clock,
  Sparkles,
  Printer
} from 'lucide-react';
import { ScanResult, SecurityHeader } from '../../types/security';
import { RiskBadge } from '../common/RiskBadge';

interface ScanResultsViewProps {
  result: ScanResult | null;
  onRescan: (url: string) => void;
  onNavigateToScanner: () => void;
  onReportThreat: (result: ScanResult) => void;
}

export const ScanResultsView: React.FC<ScanResultsViewProps> = ({
  result,
  onRescan,
  onNavigateToScanner,
  onReportThreat,
}) => {
  const [activeTab, setActiveTab] = useState<'overview' | 'phishing' | 'ssl' | 'headers' | 'redirects' | 'intel'>('overview');
  const [copiedMarkdown, setCopiedMarkdown] = useState(false);
  const [copiedJson, setCopiedJson] = useState(false);

  if (!result) {
    return (
      <div className="max-w-4xl mx-auto py-16 text-center space-y-4">
        <div className="flex h-16 w-16 items-center justify-center rounded-2xl bg-blue-950/40 text-blue-400 border border-blue-800/40 mx-auto">
          <Globe className="h-8 w-8" />
        </div>
        <h2 className="text-xl font-bold text-white">No Website Scan Selected</h2>
        <p className="text-sm text-slate-400 max-w-md mx-auto">
          Run an automated audit on any website address to inspect certificate health, phishing signals, and security headers.
        </p>
        <button
          onClick={onNavigateToScanner}
          className="inline-flex items-center gap-2 rounded-lg bg-blue-600 px-5 py-2.5 text-sm font-semibold text-white hover:bg-blue-500 transition-colors shadow-lg shadow-blue-500/20"
        >
          <span>Open URL Scanner</span>
          <ArrowRight className="h-4 w-4" />
        </button>
      </div>
    );
  }

  // Risk visual colors
  const getRiskColor = (score: number) => {
    if (score >= 80) return { text: 'text-rose-400', stroke: '#f43f5e', bg: 'bg-rose-500/10', border: 'border-rose-900/40' };
    if (score >= 55) return { text: 'text-orange-400', stroke: '#fb923c', bg: 'bg-orange-500/10', border: 'border-orange-900/40' };
    if (score >= 25) return { text: 'text-amber-400', stroke: '#fbbf24', bg: 'bg-amber-500/10', border: 'border-amber-900/40' };
    return { text: 'text-emerald-400', stroke: '#34d399', bg: 'bg-emerald-500/10', border: 'border-emerald-900/40' };
  };

  const riskColors = getRiskColor(result.riskScore);

  // SVG Gauge calculations
  const radius = 64;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (result.riskScore / 100) * circumference;

  const handleExportJson = () => {
    const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(result, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute('href', dataStr);
    downloadAnchor.setAttribute('download', `cybershield-report-${new URL(result.url).hostname}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
    setCopiedJson(true);
    setTimeout(() => setCopiedJson(false), 2000);
  };

  const handleCopyMarkdown = () => {
    const md = `# CyberShield AI Security Audit Report
**Target URL:** ${result.url}
**Risk Score:** ${result.riskScore}/100 (${result.riskLevel.toUpperCase()})
**Verdict:** ${result.verdict.toUpperCase()}
**Timestamp:** ${result.scannedAt}

## Executive Summary
${result.summary}

## Why Suspicious / Risk Factors
${result.whySuspicious.length > 0 ? result.whySuspicious.map(s => `- ${s}`).join('\n') : '- No critical threat factors detected.'}

## Phishing & Heuristics
- Phishing Verdict: ${result.phishing.isPhishing ? 'DETECTED' : 'CLEAN'}
- Confidence: ${result.phishing.confidence}%
- Target Brand: ${result.phishing.targetedBrand || 'None identified'}
- Homograph / Punycode Attack: ${result.phishing.homographAttack ? 'YES' : 'NO'}
- Shannon Entropy: ${result.phishing.entropyScore}

## SSL / TLS Certificate
- Issuer: ${result.ssl.issuer}
- Valid: ${result.ssl.valid ? 'YES' : 'NO'}
- Expiry: ${result.ssl.validTo} (${result.ssl.daysRemaining} days left)
- Protocol: ${result.ssl.tlsVersion}
- Cipher: ${result.ssl.cipherSuite}

## HTTP Security Headers
${result.headers.map(h => `- ${h.name}: ${h.present ? 'PRESENT (PASS)' : 'MISSING (FAIL)'}`).join('\n')}
`;
    navigator.clipboard.writeText(md);
    setCopiedMarkdown(true);
    setTimeout(() => setCopiedMarkdown(false), 2000);
  };

  return (
    <div className="max-w-6xl mx-auto space-y-6 animate-fade-in">
      {/* Explicit Mock Data Banner if data is preview data */}
      {result.isMockData && (
        <div className="rounded-lg border border-indigo-900/60 bg-indigo-950/40 p-3.5 flex items-start justify-between gap-3 text-xs text-indigo-300">
          <div className="flex items-center gap-2">
            <Info className="h-4 w-4 shrink-0 text-indigo-400" />
            <span>
              <strong className="font-semibold text-white">PREVIEW MOCK DATA:</strong> This assessment is a high-fidelity preview dataset. Live scans require the local Python Flask backend running at <code className="font-mono text-indigo-200">http://localhost:5000</code>.
            </span>
          </div>
          <span className="font-mono text-[11px] text-indigo-400 shrink-0 uppercase tracking-wider">
            UI Preview Mode
          </span>
        </div>
      )}

      {/* Main Header / Top Bar of Report */}
      <div className="rounded-xl border border-slate-800 bg-[#0c1322] p-6 lg:p-7 shadow-xl">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6 pb-6 border-b border-slate-800">
          {/* Target URL & Meta */}
          <div className="space-y-2">
            <div className="flex items-center gap-2 text-xs text-slate-400">
              <span>Security Assessment Report</span>
              <span aria-hidden="true">·</span>
              <span className="font-mono">{new Date(result.scannedAt).toLocaleString()}</span>
              <span aria-hidden="true">·</span>
              <span className="font-mono tabular-nums">{result.scanDurationMs}ms</span>
            </div>
            <h1 className="text-xl lg:text-2xl font-bold font-mono text-white break-all flex items-center gap-2">
              <Globe className="h-5 w-5 text-blue-400 shrink-0" />
              <span>{result.url}</span>
            </h1>
          </div>

          {/* Action buttons */}
          <div className="flex items-center flex-wrap gap-2 shrink-0">
            <button
              onClick={() => onRescan(result.url)}
              className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-lg bg-slate-900 hover:bg-slate-800 text-slate-200 border border-slate-700/80 transition-colors"
            >
              <RefreshCw className="h-3.5 w-3.5" />
              <span>Re-scan</span>
            </button>

            <button
              onClick={handleCopyMarkdown}
              className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-lg bg-slate-900 hover:bg-slate-800 text-slate-200 border border-slate-700/80 transition-colors"
            >
              {copiedMarkdown ? <Check className="h-3.5 w-3.5 text-emerald-400" /> : <Copy className="h-3.5 w-3.5" />}
              <span>{copiedMarkdown ? 'Copied' : 'Markdown'}</span>
            </button>

            <button
              onClick={handleExportJson}
              className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-lg bg-slate-900 hover:bg-slate-800 text-slate-200 border border-slate-700/80 transition-colors"
            >
              <Download className="h-3.5 w-3.5" />
              <span>JSON Export</span>
            </button>

            <button
              onClick={() => onReportThreat(result)}
              className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-lg bg-rose-600/90 hover:bg-rose-500 text-white transition-colors"
            >
              <ShieldAlert className="h-3.5 w-3.5" />
              <span>Report Threat</span>
            </button>
          </div>
        </div>

        {/* Hero Score & Executive Summary Split */}
        <div className="mt-6 grid grid-cols-1 md:grid-cols-3 gap-6 items-center">
          {/* Radial Score Meter */}
          <div className="flex flex-col items-center justify-center p-4 rounded-xl border border-slate-800/80 bg-slate-950/60">
            <div className="relative flex items-center justify-center">
              <svg className="w-36 h-36 -rotate-90">
                <circle
                  cx="72"
                  cy="72"
                  r={radius}
                  stroke="#1e293b"
                  strokeWidth="10"
                  fill="transparent"
                />
                <circle
                  cx="72"
                  cy="72"
                  r={radius}
                  stroke={riskColors.stroke}
                  strokeWidth="10"
                  strokeDasharray={circumference}
                  strokeDashoffset={strokeDashoffset}
                  strokeLinecap="round"
                  fill="transparent"
                  className="transition-all duration-1000 ease-out"
                />
              </svg>
              <div className="absolute inset-0 flex flex-col items-center justify-center text-center">
                <span className="text-3xl font-extrabold font-mono text-white tabular-nums tracking-tight">
                  {result.riskScore}
                </span>
                <span className="text-[11px] font-medium text-slate-400">Risk Score / 100</span>
              </div>
            </div>
            <div className="mt-3">
              <RiskBadge score={result.riskScore} level={result.riskLevel} size="md" />
            </div>
          </div>

          {/* Executive Summary & Key Indicators */}
          <div className="md:col-span-2 space-y-4">
            <div>
              <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1">
                Executive Security Verdict
              </div>
              <p className="text-sm font-medium text-slate-200 leading-relaxed">
                {result.summary}
              </p>
            </div>

            {/* Quick Metrics Bar */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 pt-3 border-t border-slate-800/80">
              <div className="p-2.5 rounded-lg bg-slate-900/50 border border-slate-800">
                <div className="text-[11px] text-slate-400">Phishing Status</div>
                <div className={`mt-0.5 text-xs font-bold font-mono ${result.phishing.isPhishing ? 'text-rose-400' : 'text-emerald-400'}`}>
                  {result.phishing.isPhishing ? 'Detected' : 'Clean'}
                </div>
              </div>

              <div className="p-2.5 rounded-lg bg-slate-900/50 border border-slate-800">
                <div className="text-[11px] text-slate-400">SSL Certificate</div>
                <div className={`mt-0.5 text-xs font-bold font-mono ${result.ssl.valid ? 'text-emerald-400' : 'text-rose-400'}`}>
                  {result.ssl.valid ? 'Valid TLS' : 'Invalid / Insecure'}
                </div>
              </div>

              <div className="p-2.5 rounded-lg bg-slate-900/50 border border-slate-800">
                <div className="text-[11px] text-slate-400">Security Headers</div>
                <div className="mt-0.5 text-xs font-bold font-mono text-slate-200">
                  {result.headers.filter(h => h.status === 'pass').length} / {result.headers.length} Pass
                </div>
              </div>

              <div className="p-2.5 rounded-lg bg-slate-900/50 border border-slate-800">
                <div className="text-[11px] text-slate-400">Threat Feeds</div>
                <div className={`mt-0.5 text-xs font-bold font-mono ${result.threatIntel.maliciousDetections > 0 ? 'text-rose-400' : 'text-emerald-400'}`}>
                  {result.threatIntel.maliciousDetections > 0 ? `${result.threatIntel.maliciousDetections} Engines` : 'Clean (0 Flags)'}
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* "Why This Website Is Suspicious" AI/Heuristic Explanation Card */}
      <div className="rounded-xl border border-slate-800 bg-[#0c1322] p-6 shadow-xl">
        <div className="flex items-center gap-2.5 pb-3 border-b border-slate-800">
          <div className="flex h-7 w-7 items-center justify-center rounded-lg bg-blue-500/10 text-blue-400">
            <Sparkles className="h-4 w-4" />
          </div>
          <div>
            <h2 className="text-base font-semibold text-white">Why This Website Is Suspicious</h2>
            <p className="text-xs text-slate-400">Detailed heuristic risk breakdown and contributing signals</p>
          </div>
        </div>

        <div className="mt-4">
          {result.whySuspicious && result.whySuspicious.length > 0 ? (
            <div className="space-y-2.5">
              {result.whySuspicious.map((factor, index) => (
                <div
                  key={index}
                  className="flex items-start gap-3 p-3 rounded-lg border border-slate-800/90 bg-slate-900/50 text-xs text-slate-200"
                >
                  <AlertTriangle className="h-4 w-4 text-amber-400 shrink-0 mt-0.5" />
                  <div className="leading-relaxed">{factor}</div>
                </div>
              ))}
            </div>
          ) : (
            <div className="flex items-center gap-3 p-3.5 rounded-lg border border-emerald-900/40 bg-emerald-950/20 text-xs text-emerald-300">
              <ShieldCheck className="h-4 w-4 text-emerald-400 shrink-0" />
              <div>
                No significant suspicious anomalies detected. Domain maintains valid transport encryption, established reputation, and acceptable HTTP header compliance.
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Deep Inspection Tabs */}
      <div className="rounded-xl border border-slate-800 bg-[#0c1322] p-6 shadow-xl">
        {/* Navigation Tabs (Single-line controls adhering to Section 1.A & 1.D) */}
        <div className="flex items-center gap-1.5 pb-4 border-b border-slate-800 overflow-x-auto">
          {[
            { id: 'overview', label: 'Heuristics & Signals' },
            { id: 'phishing', label: 'Phishing Detection' },
            { id: 'ssl', label: 'SSL / TLS Certificate' },
            { id: 'headers', label: 'Security Headers' },
            { id: 'redirects', label: 'Redirect Chain' },
            { id: 'intel', label: 'Threat Intelligence' },
          ].map(tab => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id as any)}
              className={`px-3 py-1.5 text-xs font-medium rounded-lg transition-colors whitespace-nowrap shrink-0 ${
                activeTab === tab.id
                  ? 'bg-blue-600 text-white shadow-sm'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-850/60'
              }`}
            >
              {tab.label}
            </button>
          ))}
        </div>

        {/* Tab 1: Heuristics & Signals */}
        {activeTab === 'overview' && (
          <div className="mt-4 space-y-3">
            <div className="text-xs text-slate-400 mb-2">
              Automated heuristic indicators detected during the URL feature extraction pipeline:
            </div>
            {result.heuristics.length > 0 ? (
              result.heuristics.map(h => (
                <div
                  key={h.id}
                  className="p-3 rounded-lg border border-slate-800 bg-slate-900/40 flex items-start justify-between gap-4 text-xs"
                >
                  <div className="space-y-1">
                    <div className="font-semibold text-slate-200 flex items-center gap-2">
                      <span>{h.title}</span>
                      <span className="text-[10px] uppercase font-mono px-1.5 py-0.5 rounded bg-slate-800 text-slate-400">
                        {h.category}
                      </span>
                    </div>
                    <div className="text-slate-400">{h.description}</div>
                    {h.detail && (
                      <div className="text-slate-500 font-mono text-[11px]">{h.detail}</div>
                    )}
                  </div>
                  <div className="text-right shrink-0">
                    <span className={`font-mono font-semibold tabular-nums ${h.detected ? 'text-rose-400' : 'text-slate-500'}`}>
                      {h.detected ? `+${h.impactScore} pts` : '0 pts (clean)'}
                    </span>
                  </div>
                </div>
              ))
            ) : (
              <div className="text-xs text-slate-500 p-4 text-center">
                All heuristic rule checks passed cleanly without violations.
              </div>
            )}
          </div>
        )}

        {/* Tab 2: Phishing Detection */}
        {activeTab === 'phishing' && (
          <div className="mt-4 space-y-4 text-xs">
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
              <div className="p-3 rounded-lg border border-slate-800 bg-slate-900/50">
                <span className="text-slate-400">Phishing Classification</span>
                <div className={`mt-1 text-sm font-bold font-mono ${result.phishing.isPhishing ? 'text-rose-400' : 'text-emerald-400'}`}>
                  {result.phishing.isPhishing ? 'Phishing Malicious' : 'Benign / Legitimate'}
                </div>
              </div>

              <div className="p-3 rounded-lg border border-slate-800 bg-slate-900/50">
                <span className="text-slate-400">Detection Confidence</span>
                <div className="mt-1 text-sm font-bold font-mono text-slate-200 tabular-nums">
                  {result.phishing.confidence}%
                </div>
              </div>

              <div className="p-3 rounded-lg border border-slate-800 bg-slate-900/50">
                <span className="text-slate-400">Targeted Brand Spoof</span>
                <div className="mt-1 text-sm font-bold font-mono text-amber-400">
                  {result.phishing.targetedBrand || 'None (No brand spoof)'}
                </div>
              </div>

              <div className="p-3 rounded-lg border border-slate-800 bg-slate-900/50">
                <span className="text-slate-400">Homoglyph / Punycode Check</span>
                <div className={`mt-1 text-sm font-bold font-mono ${result.phishing.homographAttack ? 'text-rose-400' : 'text-emerald-400'}`}>
                  {result.phishing.homographAttack ? 'Active Cyrillic/Greek Spoof' : 'Standard ASCII'}
                </div>
              </div>

              <div className="p-3 rounded-lg border border-slate-800 bg-slate-900/50">
                <span className="text-slate-400">Shannon Entropy Score</span>
                <div className="mt-1 text-sm font-bold font-mono text-slate-200 tabular-nums">
                  {result.phishing.entropyScore} <span className="text-[10px] font-normal text-slate-500">(Typical: 2.0–3.5)</span>
                </div>
              </div>

              <div className="p-3 rounded-lg border border-slate-800 bg-slate-900/50">
                <span className="text-slate-400">Threat Modality</span>
                <div className="mt-1 text-sm font-bold font-mono text-slate-200">
                  {result.phishing.primaryThreatType || 'Benign'}
                </div>
              </div>
            </div>

            {/* Keyword Detection Chips */}
            <div className="p-3.5 rounded-lg border border-slate-800 bg-slate-900/40">
              <span className="text-slate-400 font-medium">Suspicious Lure Keywords Detected in Path / Domain:</span>
              <div className="mt-2 flex flex-wrap gap-1.5">
                {result.phishing.suspiciousKeywordsFound.length > 0 ? (
                  result.phishing.suspiciousKeywordsFound.map(kw => (
                    <span key={kw} className="px-2 py-0.5 rounded bg-rose-950/60 border border-rose-800/60 text-rose-300 font-mono text-[11px]">
                      {kw}
                    </span>
                  ))
                ) : (
                  <span className="text-slate-500 text-xs">No sensitive credential or urgency keywords detected.</span>
                )}
              </div>
            </div>
          </div>
        )}

        {/* Tab 3: SSL / TLS Certificate */}
        {activeTab === 'ssl' && (
          <div className="mt-4 space-y-4 text-xs">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              <div className="p-3 rounded-lg border border-slate-800 bg-slate-900/50">
                <span className="text-slate-400">Certificate Authority (Issuer)</span>
                <div className="mt-1 text-slate-200 font-medium font-mono break-all">{result.ssl.issuer}</div>
              </div>

              <div className="p-3 rounded-lg border border-slate-800 bg-slate-900/50">
                <span className="text-slate-400">Subject Distinguished Name</span>
                <div className="mt-1 text-slate-200 font-mono break-all">{result.ssl.subject}</div>
              </div>

              <div className="p-3 rounded-lg border border-slate-800 bg-slate-900/50">
                <span className="text-slate-400">Validity Period</span>
                <div className="mt-1 text-slate-200 font-mono">
                  {result.ssl.validFrom} to {result.ssl.validTo}
                </div>
                <div className="mt-0.5 text-[11px] text-slate-400">
                  Remaining: <span className="font-mono text-emerald-400 tabular-nums">{result.ssl.daysRemaining} days</span>
                </div>
              </div>

              <div className="p-3 rounded-lg border border-slate-800 bg-slate-900/50">
                <span className="text-slate-400">Protocol & Cipher Suite</span>
                <div className="mt-1 text-slate-200 font-mono">{result.ssl.tlsVersion}</div>
                <div className="text-[11px] text-slate-400 font-mono truncate">{result.ssl.cipherSuite}</div>
              </div>
            </div>

            {/* SANs list */}
            <div className="p-3.5 rounded-lg border border-slate-800 bg-slate-900/40">
              <span className="text-slate-400 font-medium">Subject Alternative Names (SANs):</span>
              <div className="mt-2 flex flex-wrap gap-1.5 font-mono text-[11px]">
                {result.ssl.sans.length > 0 ? (
                  result.ssl.sans.map(san => (
                    <span key={san} className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
                      {san}
                    </span>
                  ))
                ) : (
                  <span className="text-slate-500">None declared</span>
                )}
              </div>
            </div>
          </div>
        )}

        {/* Tab 4: HTTP Security Headers */}
        {activeTab === 'headers' && (
          <div className="mt-4 space-y-3">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="border-b border-slate-800 text-slate-400">
                  <th className="py-2 px-3">Security Header</th>
                  <th className="py-2 px-3">Status</th>
                  <th className="py-2 px-3 hidden md:table-cell">Importance</th>
                  <th className="py-2 px-3">Description & Value</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {result.headers.map(h => (
                  <tr key={h.name} className="hover:bg-slate-900/40">
                    <td className="py-3 px-3 font-mono text-slate-200 font-semibold">{h.name}</td>
                    <td className="py-3 px-3">
                      <span className={`inline-flex items-center gap-1 font-semibold ${h.status === 'pass' ? 'text-emerald-400' : 'text-rose-400'}`}>
                        {h.status === 'pass' ? 'PASS' : 'FAIL / MISSING'}
                      </span>
                    </td>
                    <td className="py-3 px-3 hidden md:table-cell uppercase font-mono text-[11px] text-slate-400">
                      {h.importance}
                    </td>
                    <td className="py-3 px-3">
                      <div className="text-slate-300">{h.description}</div>
                      {h.value && (
                        <div className="mt-1 font-mono text-[11px] text-blue-300/80 break-all bg-slate-950/60 p-1 rounded">
                          {h.value}
                        </div>
                      )}
                      {h.recommendation && (
                        <div className="mt-1 text-[11px] text-amber-300/80">
                          Fix: {h.recommendation}
                        </div>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {/* Tab 5: Redirect Chain */}
        {activeTab === 'redirects' && (
          <div className="mt-4 space-y-4 text-xs">
            <div className="p-3 rounded-lg border border-slate-800 bg-slate-900/40 flex items-center justify-between">
              <div>
                <span className="text-slate-400">Total Redirect Hops:</span>{' '}
                <span className="font-mono font-bold text-white tabular-nums">{result.redirects.hopCount}</span>
              </div>
              <div className="flex items-center gap-3">
                <span className={result.redirects.isHttpsUpgrade ? 'text-emerald-400' : 'text-slate-400'}>
                  {result.redirects.isHttpsUpgrade ? '✓ HTTPS Upgrade' : 'No Upgrade'}
                </span>
                <span className={result.redirects.crossDomainHop ? 'text-amber-400' : 'text-slate-400'}>
                  {result.redirects.crossDomainHop ? '⚠ Cross-Domain Hop' : 'Same Origin'}
                </span>
              </div>
            </div>

            {/* Timeline of hops */}
            <div className="space-y-2">
              {result.redirects.hops.map((hop, index) => (
                <div key={index} className="flex items-center gap-3 p-3 rounded-lg border border-slate-800 bg-slate-900/50">
                  <div className="flex h-6 w-6 items-center justify-center rounded-full bg-slate-800 font-mono font-bold text-[11px] text-slate-300 shrink-0">
                    {hop.hopNumber}
                  </div>
                  <div className="flex-1 font-mono text-slate-200 break-all">
                    {hop.url}
                  </div>
                  <div className="flex items-center gap-2 font-mono shrink-0">
                    <span className={`px-2 py-0.5 rounded text-[11px] ${hop.statusCode === 200 ? 'bg-emerald-950 text-emerald-400' : 'bg-amber-950 text-amber-400'}`}>
                      {hop.statusCode} {hop.statusText}
                    </span>
                    <span className="text-slate-500 tabular-nums">{hop.latencyMs}ms</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Tab 6: Threat Intelligence & WHOIS */}
        {activeTab === 'intel' && (
          <div className="mt-4 space-y-4 text-xs">
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
              <div className="p-3 rounded-lg border border-slate-800 bg-slate-900/50">
                <span className="text-slate-400">Google SafeBrowsing Status</span>
                <div className={`mt-1 font-mono font-bold uppercase ${result.threatIntel.safeBrowsing === 'clean' ? 'text-emerald-400' : 'text-rose-400'}`}>
                  {result.threatIntel.safeBrowsing}
                </div>
              </div>

              <div className="p-3 rounded-lg border border-slate-800 bg-slate-900/50">
                <span className="text-slate-400">Reputation Engines Flagged</span>
                <div className="mt-1 font-mono font-bold text-slate-200 tabular-nums">
                  {result.threatIntel.maliciousDetections} / {result.threatIntel.reputationEnginesChecked}
                </div>
              </div>

              <div className="p-3 rounded-lg border border-slate-800 bg-slate-900/50">
                <span className="text-slate-400">Domain Age Longevity</span>
                <div className="mt-1 font-mono font-bold text-slate-200 tabular-nums">
                  {result.threatIntel.domainAgeDays} days old
                </div>
                <div className="text-[11px] text-slate-500 mt-0.5">
                  Registered: {result.threatIntel.registeredDate}
                </div>
              </div>

              <div className="p-3 rounded-lg border border-slate-800 bg-slate-900/50">
                <span className="text-slate-400">Domain Registrar</span>
                <div className="mt-1 font-mono text-slate-200">{result.threatIntel.registrar}</div>
              </div>

              <div className="p-3 rounded-lg border border-slate-800 bg-slate-900/50">
                <span className="text-slate-400">IP Address & ASN</span>
                <div className="mt-1 font-mono text-slate-200">
                  {result.threatIntel.ipAddress} ({result.threatIntel.asn})
                </div>
                <div className="text-[11px] text-slate-400">{result.threatIntel.hostingProvider}</div>
              </div>

              <div className="p-3 rounded-lg border border-slate-800 bg-slate-900/50">
                <span className="text-slate-400">Geographic Location</span>
                <div className="mt-1 font-mono text-slate-200">{result.threatIntel.country}</div>
              </div>
            </div>

            {/* Nameservers */}
            <div className="p-3.5 rounded-lg border border-slate-800 bg-slate-900/40">
              <span className="text-slate-400 font-medium">Authoritative Nameservers:</span>
              <div className="mt-2 flex flex-wrap gap-2 font-mono text-[11px] text-slate-300">
                {result.threatIntel.nameservers.map(ns => (
                  <span key={ns} className="px-2.5 py-1 rounded bg-slate-800 border border-slate-700">
                    {ns}
                  </span>
                ))}
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
