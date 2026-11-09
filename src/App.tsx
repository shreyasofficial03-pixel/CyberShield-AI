import React, { useState, useEffect } from 'react';
import { Header, NavPage } from './components/common/Header';
import { BackendModal } from './components/common/BackendModal';
import { DashboardView } from './components/dashboard/DashboardView';
import { UrlScannerView, ScannerOptions } from './components/scanner/UrlScannerView';
import { ScanResultsView } from './components/results/ScanResultsView';
import { ThreatIntelView } from './components/threats/ThreatIntelView';
import { ScanHistoryView } from './components/history/ScanHistoryView';
import { AboutView } from './components/about/AboutView';
import { ScanResult, ScanHistoryItem, ThreatReport, BackendHealth } from './types/security';
import { apiService } from './services/api';
import { MOCK_SAFE_SCAN, MOCK_PHISHING_SCAN, MOCK_SUSPICIOUS_SCAN, MOCK_HISTORY, MOCK_THREAT_REPORTS } from './services/mockData';

export default function App() {
  const [currentPage, setCurrentPage] = useState<NavPage>('dashboard');
  const [activeResult, setActiveResult] = useState<ScanResult | null>(MOCK_PHISHING_SCAN);
  const [history, setHistory] = useState<ScanHistoryItem[]>(MOCK_HISTORY);
  const [threats, setThreats] = useState<ThreatReport[]>(MOCK_THREAT_REPORTS);
  const [backendHealth, setBackendHealth] = useState<BackendHealth>({
    status: 'checking',
    url: apiService.getBackendUrl(),
  });
  const [isBackendModalOpen, setIsBackendModalOpen] = useState(false);
  const [isScanning, setIsScanning] = useState(false);
  const [scanError, setScanError] = useState<string | null>(null);
  const [scannerInitialUrl, setScannerInitialUrl] = useState('');
  const [prefilledThreatTarget, setPrefilledThreatTarget] = useState<{ url: string; domain?: string } | null>(null);

  // Initial load: ping Flask backend & fetch history/threats
  useEffect(() => {
    refreshBackendHealth();
    loadData();
  }, []);

  const refreshBackendHealth = async () => {
    const health = await apiService.checkHealth();
    setBackendHealth(health);
  };

  const loadData = async () => {
    try {
      const historyData = await apiService.getScanHistory();
      if (historyData && historyData.length > 0) {
        setHistory(historyData);
      }
    } catch {
      // Fallback already handled in apiService
    }

    try {
      const threatData = await apiService.getThreats();
      if (threatData && threatData.length > 0) {
        setThreats(threatData);
      }
    } catch {
      // Fallback
    }
  };

  // Scan handler
  const handleScan = async (url: string, options: ScannerOptions) => {
    setIsScanning(true);
    setScanError(null);
    try {
      const result = await apiService.scanUrl(url, options);
      setActiveResult(result);

      // Refresh history list
      const updatedHistory = await apiService.getScanHistory();
      setHistory(updatedHistory);

      // Navigate to results
      setCurrentPage('results');
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Scan execution failed';
      setScanError(msg);
    } finally {
      setIsScanning(false);
    }
  };

  // Inspect specific scan result by ID
  const handleSelectResult = (scanId: string) => {
    // If it's already active or matches preset mock data
    if (activeResult && activeResult.id === scanId) {
      setCurrentPage('results');
      return;
    }

    if (scanId === 'scan-mock-001') {
      setActiveResult(MOCK_SAFE_SCAN);
    } else if (scanId === 'scan-mock-002') {
      setActiveResult(MOCK_PHISHING_SCAN);
    } else if (scanId === 'scan-mock-003') {
      setActiveResult(MOCK_SUSPICIOUS_SCAN);
    } else {
      // Find from history
      const item = history.find(h => h.id === scanId);
      if (item) {
        // Build or match result
        if (item.url.includes('wellsfargo')) {
          setActiveResult(MOCK_PHISHING_SCAN);
        } else if (item.url.includes('paypa1') || item.url.includes('biz')) {
          setActiveResult(MOCK_SUSPICIOUS_SCAN);
        } else if (item.url.includes('github') || item.url.includes('wikipedia')) {
          setActiveResult(MOCK_SAFE_SCAN);
        } else {
          // Fallback to active or simulated
          setActiveResult({
            ...MOCK_PHISHING_SCAN,
            id: item.id,
            url: item.url,
            scannedAt: item.scannedAt,
            riskScore: item.riskScore,
            riskLevel: item.riskLevel,
            verdict: item.verdict,
            isMockData: item.isMockData,
          });
        }
      }
    }
    setCurrentPage('results');
  };

  const handleStartScanFromDashboard = (targetUrl: string) => {
    setScannerInitialUrl(targetUrl);
    handleScan(targetUrl, {
      deepSsl: true,
      traceRedirects: true,
      threatDbLookup: true,
      entropyAnalysis: true,
    });
  };

  const handleRescan = (url: string) => {
    setScannerInitialUrl(url);
    handleScan(url, {
      deepSsl: true,
      traceRedirects: true,
      threatDbLookup: true,
      entropyAnalysis: true,
    });
  };

  const handleClearHistory = () => {
    apiService.clearLocalHistory();
    setHistory([]);
  };

  const handleReportThreat = (scanResult: ScanResult) => {
    setPrefilledThreatTarget({
      url: scanResult.url,
      domain: new URL(scanResult.url).hostname,
    });
    setCurrentPage('threats');
  };

  const handleThreatReportSubmitted = (report: ThreatReport) => {
    setThreats(prev => [report, ...prev]);
  };

  return (
    <div className="min-h-screen flex flex-col bg-[#070b14] text-slate-100 font-sans selection:bg-blue-600/30 selection:text-blue-200">
      {/* Top Bar Header */}
      <Header
        currentPage={currentPage}
        onNavigate={(page) => {
          setScanError(null);
          setCurrentPage(page);
        }}
        backendHealth={backendHealth}
        onOpenBackendModal={() => setIsBackendModalOpen(true)}
        onQuickScanClick={() => {
          setScanError(null);
          setCurrentPage('scanner');
        }}
      />

      {/* Main Viewport Container */}
      <main className="flex-1 px-4 sm:px-6 lg:px-8 py-6 max-w-7xl mx-auto w-full">
        {currentPage === 'dashboard' && (
          <DashboardView
            history={history}
            onStartScan={handleStartScanFromDashboard}
            onSelectResult={handleSelectResult}
            onNavigateToScanner={() => setCurrentPage('scanner')}
            onNavigateToThreats={() => setCurrentPage('threats')}
          />
        )}

        {currentPage === 'scanner' && (
          <UrlScannerView
            onScan={handleScan}
            isScanning={isScanning}
            scanError={scanError}
            backendHealth={backendHealth}
            initialUrl={scannerInitialUrl}
          />
        )}

        {currentPage === 'results' && (
          <ScanResultsView
            result={activeResult}
            onRescan={handleRescan}
            onNavigateToScanner={() => setCurrentPage('scanner')}
            onReportThreat={handleReportThreat}
          />
        )}

        {currentPage === 'threats' && (
          <ThreatIntelView
            threats={threats}
            onReportSubmitted={handleThreatReportSubmitted}
            onScanTarget={handleRescan}
            initialReportTarget={prefilledThreatTarget}
          />
        )}

        {currentPage === 'history' && (
          <ScanHistoryView
            history={history}
            onSelectResult={handleSelectResult}
            onRescan={handleRescan}
            onClearHistory={handleClearHistory}
          />
        )}

        {currentPage === 'about' && <AboutView />}
      </main>

      {/* Quiet Footer adhering to Section 1.B & 1.F */}
      <footer className="border-t border-slate-800/80 bg-[#070b14] px-6 py-6 text-xs text-slate-400 mt-auto">
        <div className="max-w-7xl mx-auto flex flex-col sm:flex-row items-center justify-between gap-4">
          <div className="flex items-center gap-2">
            <span className="font-semibold text-slate-300">CyberShield AI</span>
            <span aria-hidden="true">·</span>
            <span>Intelligent Phishing & Web Infrastructure Defense</span>
          </div>

          <div className="flex items-center gap-6">
            <button
              onClick={() => setCurrentPage('about')}
              className="hover:text-slate-200 transition-colors cursor-pointer"
            >
              REST API Docs
            </button>
            <button
              onClick={() => setIsBackendModalOpen(true)}
              className="hover:text-slate-200 transition-colors cursor-pointer font-mono"
            >
              Flask: {backendHealth.status === 'connected' ? 'Connected (5000)' : 'Preview Mode'}
            </button>
          </div>
        </div>
      </footer>

      {/* Backend Connection & Configuration Modal */}
      <BackendModal
        isOpen={isBackendModalOpen}
        onClose={() => setIsBackendModalOpen(false)}
        backendHealth={backendHealth}
        onRefreshHealth={refreshBackendHealth}
      />
    </div>
  );
}
