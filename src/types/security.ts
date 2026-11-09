/**
 * Types for CyberShield AI
 * Intelligent Phishing Detection and Website Security Assessment Platform
 */

export type RiskLevel = 'low' | 'moderate' | 'high' | 'critical';

export interface SSLInfo {
  valid: boolean;
  issuer: string;
  subject: string;
  validFrom: string;
  validTo: string;
  daysRemaining: number;
  tlsVersion: string;
  cipherSuite: string;
  sanCount: number;
  sans: string[];
  selfSigned: boolean;
  revocationChecked: boolean;
  keyStrength: string;
}

export interface SecurityHeader {
  name: string;
  present: boolean;
  value?: string;
  status: 'pass' | 'fail' | 'warn';
  importance: 'critical' | 'high' | 'medium' | 'low';
  description: string;
  recommendation?: string;
}

export interface RedirectHop {
  hopNumber: number;
  url: string;
  statusCode: number;
  statusText: string;
  latencyMs: number;
  protocol: 'http:' | 'https:';
}

export interface RedirectAnalysis {
  hopCount: number;
  hops: RedirectHop[];
  initialUrl: string;
  finalUrl: string;
  isHttpsUpgrade: boolean;
  hasSuspiciousRedirect: boolean;
  crossDomainHop: boolean;
}

export interface HeuristicIndicator {
  id: string;
  title: string;
  category: 'lexical' | 'homograph' | 'dns' | 'reputation' | 'content';
  severity: 'low' | 'medium' | 'high' | 'critical';
  impactScore: number;
  detected: boolean;
  description: string;
  detail?: string;
}

export interface ThreatIntelData {
  safeBrowsing: 'clean' | 'suspicious' | 'malicious' | 'unknown';
  reputationEnginesChecked: number;
  maliciousDetections: number;
  suspiciousDetections: number;
  domainAgeDays: number;
  registrar: string;
  registeredDate: string;
  nameservers: string[];
  ipAddress: string;
  hostingProvider: string;
  country: string;
  asn: string;
}

export interface PhishingVerdict {
  isPhishing: boolean;
  confidence: number; // 0-100%
  primaryThreatType?: 'Brand Impersonation' | 'Credential Harvester' | 'Financial Fraud' | 'Malware Distribution' | 'Typosquatting' | 'Benign';
  targetedBrand?: string;
  homographAttack: boolean;
  punycodeDomain?: string;
  entropyScore: number; // typical range 2.0 to 5.0
  suspiciousKeywordsFound: string[];
}

export interface ScanResult {
  id: string;
  url: string;
  scannedAt: string;
  scanDurationMs: number;
  riskScore: number; // 0-100 (0=safe, 100=critical threat)
  riskLevel: RiskLevel;
  verdict: 'safe' | 'suspicious' | 'critical';
  summary: string;
  whySuspicious: string[];
  phishing: PhishingVerdict;
  ssl: SSLInfo;
  headers: SecurityHeader[];
  redirects: RedirectAnalysis;
  threatIntel: ThreatIntelData;
  heuristics: HeuristicIndicator[];
  isMockData?: boolean; // Flag identifying UI preview data vs live backend
}

export interface ThreatReport {
  id: string;
  domain: string;
  url: string;
  category: 'Phishing' | 'Malware' | 'Fake Banking' | 'Scam' | 'Credential Harvester' | 'Ransomware';
  targetedBrand?: string;
  evidenceNotes: string;
  severity: 'high' | 'critical' | 'medium';
  reportedAt: string;
  reporterHandle: string;
  verificationStatus: 'verified' | 'pending' | 'under-investigation';
  upvotes: number;
  isMockData?: boolean;
}

export interface ScanHistoryItem {
  id: string;
  url: string;
  scannedAt: string;
  riskScore: number;
  riskLevel: RiskLevel;
  verdict: 'safe' | 'suspicious' | 'critical';
  scanDurationMs: number;
  sslValid: boolean;
  phishingDetected: boolean;
  isMockData?: boolean;
}

export interface ScanRequest {
  url: string;
  options?: {
    deepSsl?: boolean;
    traceRedirects?: boolean;
    threatDbLookup?: boolean;
  };
}

export interface BackendHealth {
  status: 'connected' | 'disconnected' | 'checking';
  url: string;
  latencyMs?: number;
  version?: string;
  error?: string;
}
