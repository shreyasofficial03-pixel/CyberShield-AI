import React, { useState, useEffect } from 'react';
import {
  Search,
  Globe,
  Sliders,
  Shield,
  Lock,
  ArrowRight,
  CheckCircle2,
  AlertCircle,
  Radio,
  RefreshCw,
  ExternalLink,
  ShieldAlert,
  Server
} from 'lucide-react';
import { BackendHealth } from '../../types/security';

interface UrlScannerViewProps {
  onScan: (url: string, options: ScannerOptions) => Promise<void>;
  isScanning: boolean;
  scanError: string | null;
  backendHealth: BackendHealth;
  initialUrl?: string;
}

export interface ScannerOptions {
  deepSsl: boolean;
  traceRedirects: boolean;
  threatDbLookup: boolean;
  entropyAnalysis: boolean;
}

export const UrlScannerView: React.FC<UrlScannerViewProps> = ({
  onScan,
  isScanning,
  scanError,
  backendHealth,
  initialUrl = '',
}) => {
  const [url, setUrl] = useState(initialUrl);
  const [protocol, setProtocol] = useState<'https://' | 'http://'>('https://');
  const [options, setOptions] = useState<ScannerOptions>({
    deepSsl: true,
    traceRedirects: true,
    threatDbLookup: true,
    entropyAnalysis: true,
  });

  // Simulated multi-stage scan progress tracker
  const [scanStage, setScanStage] = useState<number>(0);

  const stages = [
    { title: 'DNS Resolution & Host Topology', desc: 'Resolving A/AAAA records, ASN routing, and geolocation' },
    { title: 'TLS / SSL Cryptographic Handshake', desc: 'Verifying X.509 certificate chain, cipher suite, and expiry' },
    { title: 'Lexical & Homoglyph Heuristics', desc: 'Analyzing character entropy, brand keywords, and typosquats' },
    { title: 'HTTP Redirect Graph & Security Headers', desc: 'Tracing 301/302 hops, evaluating HSTS, CSP, and X-Frame' },
    { title: 'Collective Threat Intelligence Feeds', desc: 'Querying SafeBrowsing and multi-engine reputation databases' },
    { title: 'Unified Risk Scoring Synthesis', desc: 'Aggregating vulnerability weights into 0–100 risk score' },
  ];

  useEffect(() => {
    let interval: NodeJS.Timeout;
    if (isScanning) {
      setScanStage(0);
      interval = setInterval(() => {
        setScanStage(prev => {
          if (prev < stages.length - 1) return prev + 1;
          return prev;
        });
      }, 350);
    } else {
      setScanStage(0);
    }
    return () => clearInterval(interval);
  }, [isScanning]);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!url.trim()) return;

    let target = url.trim();
    if (!target.startsWith('http://') && !target.startsWith('https://')) {
      target = `${protocol}${target}`;
    }
    onScan(target, options);
  };

  const handleApplyPreset = (presetUrl: string) => {
    setUrl(presetUrl);
    let target = presetUrl;
    if (!target.startsWith('http://') && !target.startsWith('https://')) {
      target = `${protocol}${target}`;
    }
    onScan(target, options);
  };

  return (
    <div className="max-w-4xl mx-auto space-y-6 animate-fade-in">
      {/* Title & Description */}
      <div>
        <h1 className="text-2xl font-bold tracking-tight text-white">URL Security Scanner</h1>
        <p className="mt-1 text-sm text-slate-400">
          Inspect any domain or URL against active phishing traps, expired certificates, missing security policies, and reputation databases.
        </p>
      </div>

      {/* Main Scanner Card */}
      <div className="rounded-xl border border-slate-800 bg-[#0c1322] p-6 lg:p-8 shadow-xl">
        <form onSubmit={handleSubmit} className="space-y-6">
          {/* URL Input Bar */}
          <div>
            <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-2">
              Target Website Address
            </label>
            <div className="flex rounded-lg border border-slate-700 bg-slate-950/90 focus-within:border-blue-500 focus-within:ring-1 focus-within:ring-blue-500 transition-all overflow-hidden">
              {/* Protocol selector */}
              <div className="flex items-center px-3 border-r border-slate-800 bg-slate-900/60 text-xs font-mono text-slate-400">
                <select
                  value={protocol}
                  onChange={(e) => setProtocol(e.target.value as any)}
                  className="bg-transparent focus:outline-none cursor-pointer"
                  disabled={isScanning}
                >
                  <option value="https://">https://</option>
                  <option value="http://">http://</option>
                </select>
              </div>

              {/* Main input */}
              <input
                type="text"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                placeholder="example.com or secure-auth-login.net/verify"
                disabled={isScanning}
                className="w-full bg-transparent px-4 py-3.5 text-sm font-mono text-slate-100 placeholder-slate-500 focus:outline-none"
              />

              {/* Action Button */}
              <button
                type="submit"
                disabled={isScanning || !url.trim()}
                className="flex items-center gap-2 bg-blue-600 hover:bg-blue-500 active:bg-blue-700 disabled:opacity-50 text-white px-6 font-semibold text-sm transition-colors whitespace-nowrap cursor-pointer shrink-0"
              >
                {isScanning ? (
                  <>
                    <RefreshCw className="h-4 w-4 animate-spin" />
                    <span>Analyzing...</span>
                  </>
                ) : (
                  <>
                    <Search className="h-4 w-4" />
                    <span>Scan Website</span>
                  </>
                )}
              </button>
            </div>

            {/* Error Message if scan failed */}
            {scanError && (
              <div className="mt-3 p-3.5 rounded-lg border border-rose-900/60 bg-rose-950/40 text-rose-300 text-xs flex items-start gap-2.5">
                <AlertCircle className="h-4 w-4 shrink-0 text-rose-400 mt-0.5" />
                <div className="space-y-1">
                  <div className="font-semibold">Scan Execution Error</div>
                  <div className="text-slate-300 leading-relaxed">{scanError}</div>
                </div>
              </div>
            )}
          </div>

          {/* Inspection Pipeline Modules & Toggles */}
          <div className="pt-4 border-t border-slate-800/80">
            <div className="text-xs font-semibold text-slate-300 uppercase tracking-wider mb-3">
              Inspection Parameters
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <label className="flex items-center gap-3 p-3 rounded-lg border border-slate-800/80 bg-slate-900/40 hover:bg-slate-900/80 transition-colors cursor-pointer">
                <input
                  type="checkbox"
                  checked={options.deepSsl}
                  onChange={(e) => setOptions({ ...options, deepSsl: e.target.checked })}
                  disabled={isScanning}
                  className="rounded border-slate-700 text-blue-600 focus:ring-0 focus:ring-offset-0 bg-slate-950"
                />
                <div>
                  <div className="text-xs font-medium text-slate-200">Deep SSL / TLS Certificate Handshake</div>
                  <div className="text-[11px] text-slate-400">Validate cipher strength, SANs, and certificate issuer</div>
                </div>
              </label>

              <label className="flex items-center gap-3 p-3 rounded-lg border border-slate-800/80 bg-slate-900/40 hover:bg-slate-900/80 transition-colors cursor-pointer">
                <input
                  type="checkbox"
                  checked={options.traceRedirects}
                  onChange={(e) => setOptions({ ...options, traceRedirects: e.target.checked })}
                  disabled={isScanning}
                  className="rounded border-slate-700 text-blue-600 focus:ring-0 focus:ring-offset-0 bg-slate-950"
                />
                <div>
                  <div className="text-xs font-medium text-slate-200">Multi-Hop HTTP Redirect Tracing</div>
                  <div className="text-[11px] text-slate-400">Inspect 301/302 hops and detect cross-domain masquerading</div>
                </div>
              </label>

              <label className="flex items-center gap-3 p-3 rounded-lg border border-slate-800/80 bg-slate-900/40 hover:bg-slate-900/80 transition-colors cursor-pointer">
                <input
                  type="checkbox"
                  checked={options.threatDbLookup}
                  onChange={(e) => setOptions({ ...options, threatDbLookup: e.target.checked })}
                  disabled={isScanning}
                  className="rounded border-slate-700 text-blue-600 focus:ring-0 focus:ring-offset-0 bg-slate-950"
                />
                <div>
                  <div className="text-xs font-medium text-slate-200">Collective Threat Database Query</div>
                  <div className="text-[11px] text-slate-400">Match against known malicious hosts and phishing blocklists</div>
                </div>
              </label>

              <label className="flex items-center gap-3 p-3 rounded-lg border border-slate-800/80 bg-slate-900/40 hover:bg-slate-900/80 transition-colors cursor-pointer">
                <input
                  type="checkbox"
                  checked={options.entropyAnalysis}
                  onChange={(e) => setOptions({ ...options, entropyAnalysis: e.target.checked })}
                  disabled={isScanning}
                  className="rounded border-slate-700 text-blue-600 focus:ring-0 focus:ring-offset-0 bg-slate-950"
                />
                <div>
                  <div className="text-xs font-medium text-slate-200">Shannon Entropy & Homoglyph Heuristics</div>
                  <div className="text-[11px] text-slate-400">Detect Cyrillic spoofing, digit replacements, and keyword stuffing</div>
                </div>
              </label>
            </div>
          </div>

          {/* Quick Presets Section */}
          <div className="pt-4 border-t border-slate-800/80">
            <div className="text-xs font-semibold text-slate-300 uppercase tracking-wider mb-2">
              Curated Test Scenarios
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs">
              <button
                type="button"
                onClick={() => handleApplyPreset('https://github.com')}
                disabled={isScanning}
                className="flex items-center justify-between p-2.5 rounded-lg border border-emerald-900/40 bg-emerald-950/20 hover:bg-emerald-950/40 text-left transition-colors cursor-pointer"
              >
                <div>
                  <div className="font-semibold text-emerald-400 font-mono">github.com</div>
                  <div className="text-[11px] text-slate-400">Legitimate enterprise site · Valid TLS · Safe</div>
                </div>
                <ArrowRight className="h-4 w-4 text-emerald-400/60" />
              </button>

              <button
                type="button"
                onClick={() => handleApplyPreset('https://secure-login-wellsfargo-verify99.net/auth/portal')}
                disabled={isScanning}
                className="flex items-center justify-between p-2.5 rounded-lg border border-rose-900/40 bg-rose-950/20 hover:bg-rose-950/40 text-left transition-colors cursor-pointer"
              >
                <div>
                  <div className="font-semibold text-rose-400 font-mono">wellsfargo-verify99.net</div>
                  <div className="text-[11px] text-slate-400">Active banking clone · Phishing lure · Critical</div>
                </div>
                <ArrowRight className="h-4 w-4 text-rose-400/60" />
              </button>

              <button
                type="button"
                onClick={() => handleApplyPreset('http://paypa1-update-account.biz/re-login')}
                disabled={isScanning}
                className="flex items-center justify-between p-2.5 rounded-lg border border-amber-900/40 bg-amber-950/20 hover:bg-amber-950/40 text-left transition-colors cursor-pointer"
              >
                <div>
                  <div className="font-semibold text-amber-400 font-mono">paypa1-update-account.biz</div>
                  <div className="text-[11px] text-slate-400">Homoglyph digit swap ("1" for "l") · High Risk</div>
                </div>
                <ArrowRight className="h-4 w-4 text-amber-400/60" />
              </button>

              <button
                type="button"
                onClick={() => handleApplyPreset('https://apple-id-verify-icloud-sync.cc/account')}
                disabled={isScanning}
                className="flex items-center justify-between p-2.5 rounded-lg border border-rose-900/40 bg-rose-950/20 hover:bg-rose-950/40 text-left transition-colors cursor-pointer"
              >
                <div>
                  <div className="font-semibold text-rose-400 font-mono">apple-id-verify-icloud.cc</div>
                  <div className="text-[11px] text-slate-400">Cloud credential harvester · Critical threat</div>
                </div>
                <ArrowRight className="h-4 w-4 text-rose-400/60" />
              </button>
            </div>
          </div>
        </form>
      </div>

      {/* Live Inspection Stages Card (Visible when scanning is active) */}
      {isScanning && (
        <div className="rounded-xl border border-blue-900/60 bg-[#0a1224] p-6 shadow-2xl animate-pulse">
          <div className="flex items-center justify-between pb-4 border-b border-slate-800">
            <div className="flex items-center gap-3">
              <RefreshCw className="h-5 w-5 text-blue-400 animate-spin" />
              <div>
                <h3 className="font-semibold text-white text-sm">Security Pipeline Inspection in Progress</h3>
                <p className="text-xs text-slate-400 font-mono">{url}</p>
              </div>
            </div>
            <span className="text-xs font-mono text-blue-400 tabular-nums">
              Stage {scanStage + 1} of {stages.length}
            </span>
          </div>

          <div className="mt-5 space-y-3">
            {stages.map((st, idx) => {
              const isPast = idx < scanStage;
              const isCurrent = idx === scanStage;
              return (
                <div
                  key={st.title}
                  className={`flex items-start gap-3 p-2.5 rounded-lg transition-all ${
                    isCurrent
                      ? 'bg-blue-950/40 border border-blue-800/60 text-slate-100'
                      : isPast
                      ? 'text-slate-400'
                      : 'text-slate-600'
                  }`}
                >
                  <div className="mt-0.5 shrink-0">
                    {isPast ? (
                      <CheckCircle2 className="h-4 w-4 text-emerald-400" />
                    ) : isCurrent ? (
                      <RefreshCw className="h-4 w-4 text-blue-400 animate-spin" />
                    ) : (
                      <div className="h-4 w-4 rounded-full border border-slate-700 flex items-center justify-center text-[10px] font-mono text-slate-500">
                        {idx + 1}
                      </div>
                    )}
                  </div>
                  <div>
                    <div className="text-xs font-semibold">{st.title}</div>
                    <div className="text-[11px] text-slate-400">{st.desc}</div>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
};
