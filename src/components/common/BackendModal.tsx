import React, { useState } from 'react';
import { X, Server, CheckCircle2, AlertCircle, RefreshCw, Copy, Check, Terminal, ExternalLink } from 'lucide-react';
import { BackendHealth } from '../../types/security';
import { apiService } from '../../services/api';

interface BackendModalProps {
  isOpen: boolean;
  onClose: () => void;
  backendHealth: BackendHealth;
  onRefreshHealth: () => void;
}

export const BackendModal: React.FC<BackendModalProps> = ({
  isOpen,
  onClose,
  backendHealth,
  onRefreshHealth,
}) => {
  const [urlInput, setUrlInput] = useState(apiService.getBackendUrl());
  const [isTesting, setIsTesting] = useState(false);
  const [testResult, setTestResult] = useState<BackendHealth | null>(null);
  const [mockFallback, setMockFallback] = useState(apiService.isMockFallbackEnabled());
  const [copiedCode, setCopiedCode] = useState(false);

  if (!isOpen) return null;

  const handleSaveUrl = () => {
    apiService.setBackendUrl(urlInput);
    onRefreshHealth();
  };

  const handleTestConnection = async () => {
    setIsTesting(true);
    setTestResult(null);
    try {
      apiService.setBackendUrl(urlInput);
      const res = await apiService.checkHealth();
      setTestResult(res);
      onRefreshHealth();
    } finally {
      setIsTesting(false);
    }
  };

  const handleToggleMockFallback = (val: boolean) => {
    setMockFallback(val);
    apiService.setMockFallbackEnabled(val);
  };

  const copyFlaskInstructions = () => {
    const text = `# Step 1: Navigate to the backend directory
cd backend

# Step 2: Install Python dependencies
pip install -r requirements.txt

# Step 3: Run the Flask API server
python app.py

# Server runs at http://localhost:5000`;
    navigator.clipboard.writeText(text);
    setCopiedCode(true);
    setTimeout(() => setCopiedCode(false), 2000);
  };

  const isConnected = (testResult ? testResult.status : backendHealth.status) === 'connected';

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm animate-fade-in">
      <div className="w-full max-w-xl rounded-xl border border-slate-800 bg-[#0c1322] shadow-2xl p-6 text-slate-100">
        {/* Header */}
        <div className="flex items-center justify-between pb-4 border-b border-slate-800">
          <div className="flex items-center gap-2.5">
            <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-blue-600/20 text-blue-400 border border-blue-500/30">
              <Server className="h-4 w-4" />
            </div>
            <div>
              <h3 className="font-semibold text-slate-100">Python Flask Backend Settings</h3>
              <p className="text-xs text-slate-400">Configure connection to your local or remote scanning engine</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="rounded-lg p-1 text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition-colors"
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        {/* Status card */}
        <div className="mt-4 p-3.5 rounded-lg border border-slate-800/80 bg-slate-900/60 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div
              className={`h-3 w-3 rounded-full ${
                isConnected ? 'bg-emerald-400 ring-4 ring-emerald-950' : 'bg-amber-400 ring-4 ring-amber-950'
              }`}
            />
            <div>
              <div className="text-xs font-semibold text-slate-200">
                {isConnected ? 'Flask Backend Connected' : 'Flask Backend Disconnected (Preview Mode)'}
              </div>
              <div className="text-xs text-slate-400 font-mono">
                {isConnected
                  ? `Response latency: ${testResult?.latencyMs || backendHealth.latencyMs || 42}ms · Live Scans Active`
                  : 'UI displays clearly labelled mock data previews'}
              </div>
            </div>
          </div>
          <button
            onClick={handleTestConnection}
            disabled={isTesting}
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-md border border-slate-700/60 transition-colors disabled:opacity-50"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${isTesting ? 'animate-spin' : ''}`} />
            <span>Test Ping</span>
          </button>
        </div>

        {/* Backend URL Input */}
        <div className="mt-4 space-y-2">
          <label className="text-xs font-medium text-slate-300">Backend API Base URL</label>
          <div className="flex gap-2">
            <input
              type="text"
              value={urlInput}
              onChange={(e) => setUrlInput(e.target.value)}
              placeholder="http://localhost:5000"
              className="flex-1 rounded-lg border border-slate-700 bg-slate-950/70 px-3.5 py-2 text-sm text-slate-200 font-mono focus:border-blue-500 focus:outline-none"
            />
            <button
              onClick={handleSaveUrl}
              className="px-4 py-2 text-xs font-medium bg-blue-600 hover:bg-blue-500 text-white rounded-lg transition-colors whitespace-nowrap"
            >
              Update URL
            </button>
          </div>
          <p className="text-[11px] text-slate-400">
            Standard Flask endpoints: <code className="text-slate-300 font-mono">POST /api/scan</code>, <code className="text-slate-300 font-mono">GET /api/scan/history</code>, <code className="text-slate-300 font-mono">POST /api/report</code>, <code className="text-slate-300 font-mono">GET /api/threats</code>.
          </p>
        </div>

        {/* Mock Data Fallback Toggle */}
        <div className="mt-4 p-3.5 rounded-lg border border-slate-800 bg-slate-900/40 flex items-start justify-between gap-4">
          <div>
            <div className="text-xs font-semibold text-slate-200">
              Enable Demo Preview Mode
            </div>
            <div className="text-[11px] text-slate-400 mt-0.5 leading-relaxed">
              When enabled, CyberShield AI serves clearly labelled realistic mock datasets for UI testing if the Flask server is not running on port 5000. When disabled, queries will fail with an explicit network error.
            </div>
          </div>
          <button
            onClick={() => handleToggleMockFallback(!mockFallback)}
            className={`relative inline-flex h-5 w-9 shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none mt-1 ${
              mockFallback ? 'bg-blue-600' : 'bg-slate-700'
            }`}
          >
            <span
              className={`inline-block h-4 w-4 transform rounded-full bg-white shadow ring-0 transition duration-200 ease-in-out ${
                mockFallback ? 'translate-x-4' : 'translate-x-0'
              }`}
            />
          </button>
        </div>

        {/* Python Flask Setup Instructions */}
        <div className="mt-4 rounded-lg border border-slate-800/90 bg-slate-950/90 p-3.5">
          <div className="flex items-center justify-between pb-2 mb-2 border-b border-slate-800/80">
            <span className="flex items-center gap-1.5 text-xs font-semibold text-slate-300">
              <Terminal className="h-3.5 w-3.5 text-blue-400" />
              <span>How to start the Flask Backend:</span>
            </span>
            <button
              onClick={copyFlaskInstructions}
              className="flex items-center gap-1 text-[11px] text-slate-400 hover:text-slate-200 transition-colors"
            >
              {copiedCode ? (
                <>
                  <Check className="h-3 w-3 text-emerald-400" />
                  <span className="text-emerald-400">Copied!</span>
                </>
              ) : (
                <>
                  <Copy className="h-3 w-3" />
                  <span>Copy</span>
                </>
              )}
            </button>
          </div>
          <pre className="text-xs font-mono text-slate-300 overflow-x-auto p-1 leading-relaxed">
            <span className="text-slate-500"># Run inside project directory:</span>{'\n'}
            cd backend{'\n'}
            pip install -r requirements.txt{'\n'}
            python app.py
          </pre>
        </div>

        {/* Footer */}
        <div className="mt-5 flex justify-end">
          <button
            onClick={onClose}
            className="px-4 py-2 text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg transition-colors"
          >
            Done
          </button>
        </div>
      </div>
    </div>
  );
};
