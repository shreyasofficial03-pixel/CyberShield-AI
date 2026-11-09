import { ScanResult, ThreatReport, ScanHistoryItem, BackendHealth } from '../types/security';
import { MOCK_SAFE_SCAN, MOCK_PHISHING_SCAN, MOCK_SUSPICIOUS_SCAN, MOCK_HISTORY, MOCK_THREAT_REPORTS } from './mockData';

const DEFAULT_BACKEND_URL = 'http://localhost:5000';
const STORAGE_KEY_BACKEND_URL = 'cybershield_backend_url';
const STORAGE_KEY_MOCK_FALLBACK = 'cybershield_mock_fallback';
const STORAGE_KEY_HISTORY = 'cybershield_local_history';
const STORAGE_KEY_REPORTS = 'cybershield_local_reports';

class ApiService {
  private backendUrl: string;
  private mockFallbackEnabled: boolean;
  private cachedHealth: BackendHealth = {
    status: 'checking',
    url: DEFAULT_BACKEND_URL,
  };

  constructor() {
    this.backendUrl = localStorage.getItem(STORAGE_KEY_BACKEND_URL) || DEFAULT_BACKEND_URL;
    const storedFallback = localStorage.getItem(STORAGE_KEY_MOCK_FALLBACK);
    this.mockFallbackEnabled = storedFallback === null ? true : storedFallback === 'true';
  }

  public getBackendUrl(): string {
    return this.backendUrl;
  }

  public setBackendUrl(url: string) {
    this.backendUrl = url.trim().replace(/\/+$/, '');
    localStorage.setItem(STORAGE_KEY_BACKEND_URL, this.backendUrl);
    this.cachedHealth = { status: 'checking', url: this.backendUrl };
  }

  public isMockFallbackEnabled(): boolean {
    return this.mockFallbackEnabled;
  }

  public setMockFallbackEnabled(enabled: boolean) {
    this.mockFallbackEnabled = enabled;
    localStorage.setItem(STORAGE_KEY_MOCK_FALLBACK, String(enabled));
  }

  /**
   * Ping backend to check if Python Flask service is running
   */
  public async checkHealth(): Promise<BackendHealth> {
    const startTime = performance.now();
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 2000);

      // Try /api/health or fallback to /api/threats
      const res = await fetch(`${this.backendUrl}/api/health`, {
        method: 'GET',
        headers: { Accept: 'application/json' },
        signal: controller.signal,
      }).catch(async () => {
        // Fallback test
        return await fetch(`${this.backendUrl}/api/threats`, {
          method: 'GET',
          signal: controller.signal,
        });
      });

      clearTimeout(timeoutId);
      const latencyMs = Math.round(performance.now() - startTime);

      if (res.ok) {
        this.cachedHealth = {
          status: 'connected',
          url: this.backendUrl,
          latencyMs,
          version: '1.0.0 (Python/Flask)',
        };
        return this.cachedHealth;
      } else {
        throw new Error(`HTTP ${res.status}: ${res.statusText}`);
      }
    } catch (err: unknown) {
      const errorMsg = err instanceof Error ? err.message : 'Connection failed';
      this.cachedHealth = {
        status: 'disconnected',
        url: this.backendUrl,
        error: errorMsg,
      };
      return this.cachedHealth;
    }
  }

  public getCachedHealth(): BackendHealth {
    return this.cachedHealth;
  }

  /**
   * POST /api/scan
   * Performs real scan using Flask backend, or returns marked mock preview if fallback enabled.
   */
  public async scanUrl(url: string, options?: { deepSsl?: boolean; traceRedirects?: boolean; threatDbLookup?: boolean }): Promise<ScanResult> {
    const trimmedUrl = url.trim();
    if (!trimmedUrl) {
      throw new Error('A valid website URL is required.');
    }

    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 12000);

      const res = await fetch(`${this.backendUrl}/api/scan`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Accept: 'application/json',
        },
        body: JSON.stringify({
          url: trimmedUrl,
          options: options || {
            deepSsl: true,
            traceRedirects: true,
            threatDbLookup: true,
          },
        }),
        signal: controller.signal,
      });

      clearTimeout(timeoutId);

      if (!res.ok) {
        const errorData = await res.json().catch(() => ({}));
        throw new Error(errorData.error || `Backend scan error: HTTP ${res.status}`);
      }

      const scanResult: ScanResult = await res.json();
      scanResult.isMockData = false; // Came from actual live Flask backend!

      // Save to local scan history cache
      this.saveToLocalHistory({
        id: scanResult.id,
        url: scanResult.url,
        scannedAt: scanResult.scannedAt,
        riskScore: scanResult.riskScore,
        riskLevel: scanResult.riskLevel,
        verdict: scanResult.verdict,
        scanDurationMs: scanResult.scanDurationMs,
        sslValid: scanResult.ssl.valid,
        phishingDetected: scanResult.phishing.isPhishing,
        isMockData: false,
      });

      this.cachedHealth.status = 'connected';
      return scanResult;
    } catch (err: unknown) {
      this.cachedHealth.status = 'disconnected';

      // If mock fallback is enabled (for UI preview when Flask server isn't started yet):
      if (this.mockFallbackEnabled) {
        // Return realistic preview dataset matched to query
        const mockResult = this.generateRealisticPreviewResult(trimmedUrl);
        this.saveToLocalHistory({
          id: mockResult.id,
          url: mockResult.url,
          scannedAt: mockResult.scannedAt,
          riskScore: mockResult.riskScore,
          riskLevel: mockResult.riskLevel,
          verdict: mockResult.verdict,
          scanDurationMs: mockResult.scanDurationMs,
          sslValid: mockResult.ssl.valid,
          phishingDetected: mockResult.phishing.isPhishing,
          isMockData: true,
        });
        return mockResult;
      }

      const message = err instanceof Error ? err.message : 'Unknown network failure';
      throw new Error(`Cannot reach Python Flask backend at ${this.backendUrl}. Error: ${message}. Make sure 'python app.py' is running on port 5000, or enable Preview Mode in backend settings.`);
    }
  }

  /**
   * GET /api/scan/history
   */
  public async getScanHistory(): Promise<ScanHistoryItem[]> {
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 3000);

      const res = await fetch(`${this.backendUrl}/api/scan/history`, {
        method: 'GET',
        headers: { Accept: 'application/json' },
        signal: controller.signal,
      });

      clearTimeout(timeoutId);

      if (res.ok) {
        const history: ScanHistoryItem[] = await res.json();
        return history.map(item => ({ ...item, isMockData: false }));
      }
    } catch {
      // Backend unavailable
    }

    if (this.mockFallbackEnabled) {
      // Combine local history + preset mock items
      const local = this.getLocalHistory();
      const combined = [...local, ...MOCK_HISTORY];
      // Deduplicate by URL/ID
      const seen = new Set<string>();
      return combined.filter(item => {
        if (seen.has(item.id)) return false;
        seen.add(item.id);
        return true;
      });
    }

    throw new Error(`Unable to fetch scan history from Flask backend at ${this.backendUrl}`);
  }

  /**
   * POST /api/report
   */
  public async submitReport(report: Omit<ThreatReport, 'id' | 'reportedAt' | 'verificationStatus' | 'upvotes'>): Promise<ThreatReport> {
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 4000);

      const res = await fetch(`${this.backendUrl}/api/report`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Accept: 'application/json',
        },
        body: JSON.stringify(report),
        signal: controller.signal,
      });

      clearTimeout(timeoutId);

      if (res.ok) {
        const saved: ThreatReport = await res.json();
        saved.isMockData = false;
        return saved;
      }
    } catch {
      // Backend unavailable
    }

    if (this.mockFallbackEnabled) {
      const newReport: ThreatReport = {
        id: `rep-user-${Date.now()}`,
        domain: report.domain,
        url: report.url,
        category: report.category,
        targetedBrand: report.targetedBrand,
        evidenceNotes: report.evidenceNotes,
        severity: report.severity,
        reportedAt: new Date().toISOString(),
        reporterHandle: report.reporterHandle || 'community_member',
        verificationStatus: 'pending',
        upvotes: 1,
        isMockData: true,
      };

      this.saveToLocalReports(newReport);
      return newReport;
    }

    throw new Error(`Failed to submit report to Flask backend at ${this.backendUrl}`);
  }

  /**
   * GET /api/threats
   */
  public async getThreats(query?: string): Promise<ThreatReport[]> {
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 3000);

      const url = new URL(`${this.backendUrl}/api/threats`);
      if (query) url.searchParams.set('q', query);

      const res = await fetch(url.toString(), {
        method: 'GET',
        headers: { Accept: 'application/json' },
        signal: controller.signal,
      });

      clearTimeout(timeoutId);

      if (res.ok) {
        const threats: ThreatReport[] = await res.json();
        return threats.map(t => ({ ...t, isMockData: false }));
      }
    } catch {
      // Backend unavailable
    }

    if (this.mockFallbackEnabled) {
      const local = this.getLocalReports();
      const allReports = [...local, ...MOCK_THREAT_REPORTS];
      if (!query || !query.trim()) return allReports;

      const q = query.toLowerCase();
      return allReports.filter(
        r => r.domain.toLowerCase().includes(q) ||
             r.category.toLowerCase().includes(q) ||
             (r.targetedBrand && r.targetedBrand.toLowerCase().includes(q))
      );
    }

    throw new Error(`Unable to fetch threat intel database from ${this.backendUrl}`);
  }

  // Helper storage operations for client-side persistence in preview mode
  private getLocalHistory(): ScanHistoryItem[] {
    try {
      const data = localStorage.getItem(STORAGE_KEY_HISTORY);
      return data ? JSON.parse(data) : [];
    } catch {
      return [];
    }
  }

  private saveToLocalHistory(item: ScanHistoryItem) {
    try {
      const existing = this.getLocalHistory();
      const updated = [item, ...existing.filter(h => h.id !== item.id)].slice(0, 50);
      localStorage.setItem(STORAGE_KEY_HISTORY, JSON.stringify(updated));
    } catch {
      // ignore storage errors
    }
  }

  public clearLocalHistory() {
    localStorage.removeItem(STORAGE_KEY_HISTORY);
  }

  private getLocalReports(): ThreatReport[] {
    try {
      const data = localStorage.getItem(STORAGE_KEY_REPORTS);
      return data ? JSON.parse(data) : [];
    } catch {
      return [];
    }
  }

  private saveToLocalReports(report: ThreatReport) {
    try {
      const existing = this.getLocalReports();
      const updated = [report, ...existing];
      localStorage.setItem(STORAGE_KEY_REPORTS, JSON.stringify(updated));
    } catch {
      // ignore
    }
  }

  /**
   * Generates a contextually realistic mock preview result when Flask backend is not running.
   * Explicitly sets `isMockData: true` per project guidelines.
   */
  private generateRealisticPreviewResult(url: string): ScanResult {
    const lower = url.toLowerCase();
    const isPhishing = lower.includes('verify') ||
                      lower.includes('login') ||
                      lower.includes('bank') ||
                      lower.includes('auth') ||
                      lower.includes('paypa1') ||
                      lower.includes('paypal-update') ||
                      lower.includes('wellsfargo') ||
                      lower.includes('secure-');

    if (lower.includes('wellsfargo') || lower.includes('portal') || lower.includes('auth82')) {
      return {
        ...MOCK_PHISHING_SCAN,
        id: `scan-mock-${Date.now()}`,
        url,
        scannedAt: new Date().toISOString(),
        isMockData: true,
      };
    }

    if (lower.includes('paypa1') || lower.includes('biz') || !lower.startsWith('https://')) {
      return {
        ...MOCK_SUSPICIOUS_SCAN,
        id: `scan-mock-${Date.now()}`,
        url,
        scannedAt: new Date().toISOString(),
        isMockData: true,
      };
    }

    if (isPhishing) {
      return {
        id: `scan-mock-${Date.now()}`,
        url,
        scannedAt: new Date().toISOString(),
        scanDurationMs: 1180,
        riskScore: 84,
        riskLevel: 'high',
        verdict: 'suspicious',
        isMockData: true,
        summary: 'Target domain exhibits suspicious credential harvesting patterns, newly observed host records, and incomplete transport security policies.',
        whySuspicious: [
          'Credential Harvesting Lure: URL contains suspicious authentication terminology.',
          'Missing HSTS Security Header: Vulnerable to man-in-the-middle downgrade attacks.',
          'Domain Age Alert: Registered recently with limited historical reputation records.',
        ],
        phishing: {
          isPhishing: true,
          confidence: 84,
          primaryThreatType: 'Credential Harvester',
          homographAttack: false,
          entropyScore: 3.65,
          suspiciousKeywordsFound: ['login', 'verify'],
        },
        ssl: {
          valid: true,
          issuer: "Let's Encrypt Authority X3",
          subject: `CN=${new URL(url.startsWith('http') ? url : `https://${url}`).hostname}`,
          validFrom: '2026-10-12',
          validTo: '2027-01-10',
          daysRemaining: 63,
          tlsVersion: 'TLSv1.2',
          cipherSuite: 'ECDHE-RSA-AES128-GCM-SHA256',
          sanCount: 1,
          sans: [new URL(url.startsWith('http') ? url : `https://${url}`).hostname],
          selfSigned: false,
          revocationChecked: false,
          keyStrength: 'RSA 2048-bit',
        },
        headers: [
          {
            name: 'Strict-Transport-Security',
            present: false,
            status: 'fail',
            importance: 'critical',
            description: 'Missing HSTS policy.',
          },
          {
            name: 'Content-Security-Policy',
            present: false,
            status: 'fail',
            importance: 'critical',
            description: 'Missing CSP header.',
          },
          {
            name: 'X-Frame-Options',
            present: true,
            value: 'SAMEORIGIN',
            status: 'pass',
            importance: 'high',
            description: 'Restricted to same origin.',
          },
        ],
        redirects: {
          hopCount: 1,
          initialUrl: url,
          finalUrl: url,
          isHttpsUpgrade: url.startsWith('https://'),
          hasSuspiciousRedirect: false,
          crossDomainHop: false,
          hops: [
            {
              hopNumber: 1,
              url,
              statusCode: 200,
              statusText: 'OK',
              latencyMs: 145,
              protocol: url.startsWith('https://') ? 'https:' : 'http:',
            },
          ],
        },
        threatIntel: {
          safeBrowsing: 'suspicious',
          reputationEnginesChecked: 89,
          maliciousDetections: 4,
          suspiciousDetections: 9,
          domainAgeDays: 14,
          registrar: 'Hostinger Operations, UAB',
          registeredDate: '2026-10-24',
          nameservers: ['ns1.dns-parking.com', 'ns2.dns-parking.com'],
          ipAddress: '185.156.73.44',
          hostingProvider: 'Hostinger International Ltd.',
          country: 'Lithuania',
          asn: 'AS47583',
        },
        heuristics: [
          {
            id: 'auth-tokens',
            title: 'Authentication Path Heuristics',
            category: 'lexical',
            severity: 'high',
            impactScore: 28,
            detected: true,
            description: 'Heuristic pattern matches known phishing login gateways.',
          },
        ],
      };
    }

    // Default to safe mock
    return {
      ...MOCK_SAFE_SCAN,
      id: `scan-mock-${Date.now()}`,
      url: url.startsWith('http') ? url : `https://${url}`,
      scannedAt: new Date().toISOString(),
      isMockData: true,
    };
  }
}

export const apiService = new ApiService();
