import React, { useState } from 'react';
import {
  Shield,
  Server,
  Lock,
  Layers,
  FileCode,
  CheckCircle2,
  AlertTriangle,
  Code2,
  Copy,
  Check,
  ExternalLink,
  Cpu,
  Terminal,
  Globe,
  Database
} from 'lucide-react';
import { apiService } from '../../services/api';

export const AboutView: React.FC = () => {
  const [activeSnippetTab, setActiveSnippetTab] = useState<'curl' | 'python' | 'js'>('python');
  const [copiedSnippet, setCopiedSnippet] = useState(false);

  const snippets = {
    python: `import requests

# CyberShield AI Flask API Client
BASE_URL = "http://localhost:5000"

# 1. Perform Deep Website Security Scan
scan_payload = {
    "url": "https://secure-login-wellsfargo-verify99.net/auth/portal",
    "options": {
        "deepSsl": True,
        "traceRedirects": True,
        "threatDbLookup": True
    }
}

response = requests.post(f"{BASE_URL}/api/scan", json=scan_payload)
result = response.json()

print(f"Risk Score: {result['riskScore']}/100")
print(f"Phishing Verdict: {result['phishing']['isPhishing']}")
print(f"Why Suspicious: {result['whySuspicious']}")

# 2. Query Community Threat Feed
threats = requests.get(f"{BASE_URL}/api/threats?q=wellsfargo").json()
print(f"Known matching threats: {len(threats)}")`,

    curl: `# 1. Test Backend Healthcheck
curl -X GET http://localhost:5000/api/health

# 2. Scan Website for Phishing & Vulnerabilities
curl -X POST http://localhost:5000/api/scan \\
  -H "Content-Type: application/json" \\
  -d '{"url":"https://github.com"}'

# 3. Retrieve Historical Audits
curl -X GET http://localhost:5000/api/scan/history

# 4. Submit Threat Intel Report
curl -X POST http://localhost:5000/api/report \\
  -H "Content-Type: application/json" \\
  -d '{"domain":"phish-example.net","category":"Fake Banking","severity":"critical"}'`,

    js: `// CyberShield AI JavaScript / TypeScript Client
const BASE_URL = 'http://localhost:5000';

async function scanTarget(targetUrl) {
  const res = await fetch(\`\${BASE_URL}/api/scan\`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      url: targetUrl,
      options: { deepSsl: true, traceRedirects: true, threatDbLookup: true }
    })
  });
  
  const report = await res.json();
  console.log(\`Risk Score: \${report.riskScore} (\${report.riskLevel})\`);
  return report;
}`,
  };

  const handleCopySnippet = () => {
    navigator.clipboard.writeText(snippets[activeSnippetTab]);
    setCopiedSnippet(true);
    setTimeout(() => setCopiedSnippet(false), 2000);
  };

  return (
    <div className="space-y-8 max-w-5xl mx-auto animate-fade-in pb-12">
      {/* Hero Section */}
      <div className="rounded-xl border border-slate-800 bg-[#0c1322] p-6 lg:p-8 shadow-xl">
        <div className="flex items-center gap-3 text-blue-400 mb-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-blue-600/20 border border-blue-500/30 text-white">
            <Shield className="h-6 w-6 text-blue-400" />
          </div>
          <div>
            <span className="text-xs font-semibold uppercase tracking-wider text-blue-400">Platform Architecture</span>
            <h1 className="text-2xl font-extrabold text-white">About CyberShield AI</h1>
          </div>
        </div>

        <p className="mt-3 text-sm text-slate-300 leading-relaxed">
          <strong>CyberShield AI</strong> is a next-generation web security assessment engine and real-time phishing detection system. Designed for security operations teams, web administrators, and vigilant internet users, the platform deconstructs modern social engineering lures, cryptographic misconfigurations, and deceptive infrastructure tactics into deterministic, transparent security audits.
        </p>
      </div>

      {/* 5-Layer Security Inspection Engine */}
      <div className="rounded-xl border border-slate-800 bg-[#0c1322] p-6 lg:p-8 shadow-xl space-y-6">
        <div>
          <h2 className="text-lg font-bold text-white flex items-center gap-2">
            <Cpu className="h-5 w-5 text-indigo-400" />
            <span>Multi-Tier Inspection Architecture</span>
          </h2>
          <p className="mt-1 text-xs text-slate-400">
            Every website scan executes a coordinated battery of analytical engines:
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="p-4 rounded-xl border border-slate-800 bg-slate-900/40 space-y-2">
            <div className="flex items-center gap-2 text-sm font-semibold text-blue-400">
              <Layers className="h-4 w-4" />
              <span>1. Lexical & Shannon Entropy Engine</span>
            </div>
            <p className="text-xs text-slate-300 leading-relaxed">
              Analyzes character randomness in domain labels, path depth, and query strings. High entropy combined with hyphen stuffing strongly correlates with algorithmically generated phishing links.
            </p>
          </div>

          <div className="p-4 rounded-xl border border-slate-800 bg-slate-900/40 space-y-2">
            <div className="flex items-center gap-2 text-sm font-semibold text-purple-400">
              <Globe className="h-4 w-4" />
              <span>2. Homoglyph & Punycode Detector</span>
            </div>
            <p className="text-xs text-slate-300 leading-relaxed">
              Detects internationalized domain names (IDN) and leetspeak character substitutions (such as substituting Cyrillic "а" for Latin "a" or "1" for "l" in <code>paypa1</code>), safeguarding against brand impersonation.
            </p>
          </div>

          <div className="p-4 rounded-xl border border-slate-800 bg-slate-900/40 space-y-2">
            <div className="flex items-center gap-2 text-sm font-semibold text-emerald-400">
              <Lock className="h-4 w-4" />
              <span>3. SSL/TLS Cryptographic Validator</span>
            </div>
            <p className="text-xs text-slate-300 leading-relaxed">
              Establishes direct TLS handshakes to examine peer certificate authorities (Let's Encrypt vs DigiCert EV/OV), cipher suites, Subject Alternative Names (SANs), expiration windows, and self-signed certificates.
            </p>
          </div>

          <div className="p-4 rounded-xl border border-slate-800 bg-slate-900/40 space-y-2">
            <div className="flex items-center gap-2 text-sm font-semibold text-amber-400">
              <FileCode className="h-4 w-4" />
              <span>4. HTTP Defense Headers Audit</span>
            </div>
            <p className="text-xs text-slate-300 leading-relaxed">
              Evaluates critical client-side defenses: Strict-Transport-Security (HSTS), Content-Security-Policy (CSP), X-Frame-Options (Clickjacking protection), and X-Content-Type-Options (MIME sniffing defense).
            </p>
          </div>

          <div className="p-4 rounded-xl border border-slate-800 bg-slate-900/40 space-y-2 md:col-span-2">
            <div className="flex items-center gap-2 text-sm font-semibold text-rose-400">
              <Database className="h-4 w-4" />
              <span>5. Collective Threat Feeds & Redirect Graph</span>
            </div>
            <p className="text-xs text-slate-300 leading-relaxed">
              Follows 301/302 HTTP redirect chains, detecting clandestine cross-domain bouncing and malicious cloaking before cross-referencing global SafeBrowsing and VirusTotal reputation databases.
            </p>
          </div>
        </div>
      </div>

      {/* Transparent Risk Score Rubric */}
      <div className="rounded-xl border border-slate-800 bg-[#0c1322] p-6 lg:p-8 shadow-xl space-y-4">
        <div>
          <h2 className="text-lg font-bold text-white">Risk Scoring Calibration</h2>
          <p className="mt-1 text-xs text-slate-400">
            Scores range from 0 (completely benign) to 100 (critical active phishing threat).
          </p>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-4 gap-3 text-xs">
          <div className="p-3 rounded-lg border border-emerald-900/40 bg-emerald-950/20">
            <div className="font-bold text-emerald-400 font-mono">0 – 24: Low Risk (Safe)</div>
            <p className="text-[11px] text-slate-400 mt-1">Established reputation, valid TLS certificate, complete defense headers.</p>
          </div>

          <div className="p-3 rounded-lg border border-amber-900/40 bg-amber-950/20">
            <div className="font-bold text-amber-400 font-mono">25 – 54: Moderate Risk</div>
            <p className="text-[11px] text-slate-400 mt-1">Missing HSTS or CSP policies, newly registered domain, or minor heuristic warnings.</p>
          </div>

          <div className="p-3 rounded-lg border border-orange-900/40 bg-orange-950/20">
            <div className="font-bold text-orange-400 font-mono">55 – 79: High Threat</div>
            <p className="text-[11px] text-slate-400 mt-1">Typosquatting markers, self-signed SSL, or presence on secondary blocklists.</p>
          </div>

          <div className="p-3 rounded-lg border border-rose-900/40 bg-rose-950/20">
            <div className="font-bold text-rose-400 font-mono">80 – 100: Critical Threat</div>
            <p className="text-[11px] text-slate-400 mt-1">Active credential harvesting, blatant trademark impersonation, verified phishing campaign.</p>
          </div>
        </div>
      </div>

      {/* Backend API Documentation & Code Snippets */}
      <div className="rounded-xl border border-slate-800 bg-[#0c1322] p-6 lg:p-8 shadow-xl space-y-6">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div>
            <h2 className="text-lg font-bold text-white flex items-center gap-2">
              <Server className="h-5 w-5 text-blue-400" />
              <span>Python Flask REST API Integration</span>
            </h2>
            <p className="mt-1 text-xs text-slate-400">
              CyberShield AI connects to your Flask backend at <code className="text-blue-300 font-mono">http://localhost:5000</code>.
            </p>
          </div>

          <div className="flex items-center gap-1 p-1 bg-slate-900 rounded-lg border border-slate-800 self-start sm:self-auto">
            {(['python', 'curl', 'js'] as const).map(tab => (
              <button
                key={tab}
                onClick={() => setActiveSnippetTab(tab)}
                className={`px-3 py-1 text-xs font-mono font-medium rounded-md transition-colors uppercase ${
                  activeSnippetTab === tab
                    ? 'bg-blue-600 text-white'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {tab}
              </button>
            ))}
          </div>
        </div>

        {/* API Table */}
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead>
              <tr className="border-b border-slate-800 text-slate-400">
                <th className="py-2.5 px-3">Method</th>
                <th className="py-2.5 px-3">Endpoint</th>
                <th className="py-2.5 px-3">Purpose</th>
                <th className="py-2.5 px-3">Payload / Params</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-slate-300">
              <tr>
                <td className="py-2 px-3 text-emerald-400 font-bold">GET</td>
                <td className="py-2 px-3 text-white">/api/health</td>
                <td className="py-2 px-3 font-sans text-slate-400">Server heartbeat check</td>
                <td className="py-2 px-3 text-slate-500">-</td>
              </tr>
              <tr>
                <td className="py-2 px-3 text-blue-400 font-bold">POST</td>
                <td className="py-2 px-3 text-white">/api/scan</td>
                <td className="py-2 px-3 font-sans text-slate-400">Executes real website security audit</td>
                <td className="py-2 px-3 text-blue-300">{'{ "url": "...", "options": {...} }'}</td>
              </tr>
              <tr>
                <td className="py-2 px-3 text-emerald-400 font-bold">GET</td>
                <td className="py-2 px-3 text-white">/api/scan/history</td>
                <td className="py-2 px-3 font-sans text-slate-400">Retrieves historical scanned domains</td>
                <td className="py-2 px-3 text-slate-500">-</td>
              </tr>
              <tr>
                <td className="py-2 px-3 text-blue-400 font-bold">POST</td>
                <td className="py-2 px-3 text-white">/api/report</td>
                <td className="py-2 px-3 font-sans text-slate-400">Submits suspicious domain report</td>
                <td className="py-2 px-3 text-blue-300">{'{ "domain": "...", "category": "..." }'}</td>
              </tr>
              <tr>
                <td className="py-2 px-3 text-emerald-400 font-bold">GET</td>
                <td className="py-2 px-3 text-white">/api/threats</td>
                <td className="py-2 px-3 font-sans text-slate-400">Fetches collective community threats</td>
                <td className="py-2 px-3 text-slate-400">?q=query</td>
              </tr>
            </tbody>
          </table>
        </div>

        {/* Code Snippet Box */}
        <div className="rounded-lg border border-slate-800 bg-slate-950 overflow-hidden">
          <div className="flex items-center justify-between px-4 py-2 border-b border-slate-800 bg-slate-900/60">
            <span className="text-xs font-mono text-slate-400">
              {activeSnippetTab === 'python' ? 'app_client.py' : activeSnippetTab === 'curl' ? 'terminal cURL' : 'scanner.ts'}
            </span>
            <button
              onClick={handleCopySnippet}
              className="flex items-center gap-1 text-xs text-slate-400 hover:text-slate-200 transition-colors"
            >
              {copiedSnippet ? (
                <>
                  <Check className="h-3.5 w-3.5 text-emerald-400" />
                  <span className="text-emerald-400">Copied</span>
                </>
              ) : (
                <>
                  <Copy className="h-3.5 w-3.5" />
                  <span>Copy Code</span>
                </>
              )}
            </button>
          </div>
          <pre className="p-4 text-xs font-mono text-slate-200 overflow-x-auto leading-relaxed">
            {snippets[activeSnippetTab]}
          </pre>
        </div>
      </div>
    </div>
  );
};
