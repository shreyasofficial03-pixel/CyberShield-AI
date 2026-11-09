import React, { useState } from 'react';
import {
  ShieldAlert,
  Search,
  Filter,
  Plus,
  ThumbsUp,
  CheckCircle2,
  AlertTriangle,
  Clock,
  ExternalLink,
  Tag,
  Building,
  User,
  Info,
  X
} from 'lucide-react';
import { ThreatReport } from '../../types/security';
import { apiService } from '../../services/api';

interface ThreatIntelViewProps {
  threats: ThreatReport[];
  onReportSubmitted: (report: ThreatReport) => void;
  onScanTarget: (url: string) => void;
  initialReportTarget?: { url: string; domain?: string } | null;
}

export const ThreatIntelView: React.FC<ThreatIntelViewProps> = ({
  threats,
  onReportSubmitted,
  onScanTarget,
  initialReportTarget,
}) => {
  const [searchQuery, setSearchQuery] = useState('');
  const [categoryFilter, setCategoryFilter] = useState<string>('all');
  const [isReportModalOpen, setIsReportModalOpen] = useState(Boolean(initialReportTarget));

  // Report form state
  const [formUrl, setFormUrl] = useState(initialReportTarget?.url || '');
  const [formCategory, setFormCategory] = useState<ThreatReport['category']>('Fake Banking');
  const [formBrand, setFormBrand] = useState('');
  const [formSeverity, setFormSeverity] = useState<ThreatReport['severity']>('high');
  const [formNotes, setFormNotes] = useState('');
  const [formReporter, setFormReporter] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [submitSuccess, setSubmitSuccess] = useState(false);

  // Upvotes state map
  const [upvotedIds, setUpvotedIds] = useState<Record<string, number>>({});

  const categories = ['all', 'Fake Banking', 'Phishing', 'Credential Harvester', 'Scam', 'Malware'];

  const filteredThreats = threats.filter(t => {
    const matchesSearch =
      searchQuery === '' ||
      t.domain.toLowerCase().includes(searchQuery.toLowerCase()) ||
      t.evidenceNotes.toLowerCase().includes(searchQuery.toLowerCase()) ||
      (t.targetedBrand && t.targetedBrand.toLowerCase().includes(searchQuery.toLowerCase()));

    const matchesCategory =
      categoryFilter === 'all' || t.category === categoryFilter;

    return matchesSearch && matchesCategory;
  });

  const handleUpvote = (id: string, current: number) => {
    setUpvotedIds(prev => ({
      ...prev,
      [id]: (prev[id] || current) + 1,
    }));
  };

  const handleReportSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!formUrl.trim()) return;

    setIsSubmitting(true);
    try {
      let domain = '';
      try {
        domain = new URL(formUrl.startsWith('http') ? formUrl : `https://${formUrl}`).hostname;
      } catch {
        domain = formUrl;
      }

      const report = await apiService.submitReport({
        url: formUrl.trim(),
        domain,
        category: formCategory,
        targetedBrand: formBrand.trim() || undefined,
        severity: formSeverity,
        evidenceNotes: formNotes.trim() || 'Suspicious domain flagged by user',
        reporterHandle: formReporter.trim() || 'threat_analyst',
      });

      onReportSubmitted(report);
      setSubmitSuccess(true);
      setTimeout(() => {
        setIsReportModalOpen(false);
        setSubmitSuccess(false);
        setFormUrl('');
        setFormNotes('');
        setFormBrand('');
      }, 1500);
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="space-y-6 max-w-6xl mx-auto animate-fade-in">
      {/* Top Banner */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-slate-800">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2.5">
            <ShieldAlert className="h-6 w-6 text-rose-400" />
            <span>Threat Intelligence Database</span>
          </h1>
          <p className="mt-1 text-sm text-slate-400">
            Search community-verified phishing campaigns, reported malicious domains, and credential harvesters.
          </p>
        </div>
        <button
          onClick={() => setIsReportModalOpen(true)}
          className="flex items-center gap-2 rounded-lg bg-rose-600 px-4 py-2.5 text-xs font-semibold text-white shadow-lg shadow-rose-600/20 hover:bg-rose-500 active:bg-rose-700 transition-colors whitespace-nowrap self-start sm:self-auto cursor-pointer"
        >
          <Plus className="h-4 w-4" />
          <span>Report Suspicious Website</span>
        </button>
      </div>

      {/* Search and Category Filter Bar */}
      <div className="flex flex-col md:flex-row gap-3 items-stretch md:items-center justify-between">
        {/* Search input */}
        <div className="relative flex-1 max-w-md">
          <Search className="absolute left-3.5 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-400" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search reported domains or targeted brands..."
            className="w-full rounded-lg border border-slate-800 bg-slate-900/80 py-2 pl-9 pr-4 text-xs font-mono text-slate-200 placeholder-slate-500 focus:border-blue-500 focus:outline-none"
          />
        </div>

        {/* Category Filter Tabs (Single-line controls adhering to Section 1.A) */}
        <div className="flex items-center gap-1 p-1 bg-slate-900/80 rounded-lg border border-slate-800 overflow-x-auto">
          {categories.map(cat => (
            <button
              key={cat}
              onClick={() => setCategoryFilter(cat)}
              className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors capitalize whitespace-nowrap shrink-0 ${
                categoryFilter === cat
                  ? 'bg-blue-600 text-white shadow-sm'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              {cat}
            </button>
          ))}
        </div>
      </div>

      {/* Threat Cards Grid */}
      {filteredThreats.length === 0 ? (
        <div className="rounded-xl border border-slate-800 bg-[#0c1322] p-12 text-center text-slate-400 space-y-3">
          <ShieldAlert className="h-8 w-8 mx-auto text-slate-600" />
          <p className="text-sm">No threat reports match your search query.</p>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {filteredThreats.map(threat => {
            const votes = upvotedIds[threat.id] || threat.upvotes;
            return (
              <div
                key={threat.id}
                className="rounded-xl border border-slate-800 bg-[#0c1322] p-5 hover:border-slate-700 transition-colors flex flex-col justify-between"
              >
                <div>
                  {/* Card Header (Zero-Pill discipline: Lead directly with title or clean metadata separator) */}
                  <div className="flex items-start justify-between gap-3">
                    <div className="space-y-1">
                      <div className="flex items-center gap-2 text-xs text-slate-400">
                        <span className="font-semibold text-rose-400">{threat.category}</span>
                        <span aria-hidden="true">·</span>
                        <span>Severity: {threat.severity.toUpperCase()}</span>
                        {threat.isMockData && (
                          <>
                            <span aria-hidden="true">·</span>
                            <span className="text-indigo-400">Preview Mock</span>
                          </>
                        )}
                      </div>
                      <h3 className="font-mono text-sm font-bold text-white break-all">
                        {threat.domain}
                      </h3>
                    </div>

                    <span
                      className={`text-[11px] font-mono px-2 py-0.5 rounded border ${
                        threat.verificationStatus === 'verified'
                          ? 'border-emerald-800/40 bg-emerald-950/40 text-emerald-400'
                          : 'border-amber-800/40 bg-amber-950/40 text-amber-400'
                      }`}
                    >
                      {threat.verificationStatus === 'verified' ? 'Verified Phish' : 'Pending Review'}
                    </span>
                  </div>

                  {/* Targeted Brand & Evidence Notes */}
                  {threat.targetedBrand && (
                    <div className="mt-2.5 flex items-center gap-1.5 text-xs text-slate-300">
                      <Building className="h-3.5 w-3.5 text-blue-400 shrink-0" />
                      <span>Targeting: <strong className="text-white font-medium">{threat.targetedBrand}</strong></span>
                    </div>
                  )}

                  <p className="mt-2.5 text-xs text-slate-300 leading-relaxed bg-slate-900/50 p-2.5 rounded-lg border border-slate-800/80">
                    {threat.evidenceNotes}
                  </p>
                </div>

                {/* Footer of Card */}
                <div className="mt-4 pt-3 border-t border-slate-800 flex items-center justify-between text-xs text-slate-400">
                  <div className="flex items-center gap-2">
                    <User className="h-3.5 w-3.5 text-slate-500" />
                    <span className="font-mono">{threat.reporterHandle}</span>
                    <span aria-hidden="true">·</span>
                    <span>{new Date(threat.reportedAt).toLocaleDateString()}</span>
                  </div>

                  <div className="flex items-center gap-3">
                    <button
                      onClick={() => handleUpvote(threat.id, threat.upvotes)}
                      className="flex items-center gap-1.5 text-slate-300 hover:text-blue-400 transition-colors"
                      title="Confirm / Upvote this threat report"
                    >
                      <ThumbsUp className="h-3.5 w-3.5" />
                      <span className="font-mono tabular-nums">{votes}</span>
                    </button>

                    <button
                      onClick={() => onScanTarget(threat.url)}
                      className="text-blue-400 hover:text-blue-300 font-medium inline-flex items-center gap-1"
                    >
                      <span>Audit</span>
                      <ExternalLink className="h-3 w-3" />
                    </button>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* Report Suspicious Website Modal */}
      {isReportModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/75 backdrop-blur-sm animate-fade-in">
          <div className="w-full max-w-lg rounded-xl border border-slate-800 bg-[#0c1322] shadow-2xl p-6 text-slate-100">
            <div className="flex items-center justify-between pb-4 border-b border-slate-800">
              <div className="flex items-center gap-2.5">
                <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-rose-600/20 text-rose-400 border border-rose-500/30">
                  <ShieldAlert className="h-4 w-4" />
                </div>
                <div>
                  <h3 className="font-semibold text-slate-100">Submit Suspicious Website</h3>
                  <p className="text-xs text-slate-400">Add to CyberShield AI Community Threat Intelligence</p>
                </div>
              </div>
              <button
                onClick={() => setIsReportModalOpen(false)}
                className="rounded-lg p-1 text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition-colors"
              >
                <X className="h-5 w-5" />
              </button>
            </div>

            {submitSuccess ? (
              <div className="py-8 text-center space-y-2">
                <CheckCircle2 className="h-10 w-10 text-emerald-400 mx-auto" />
                <h4 className="font-semibold text-white">Report Successfully Submitted!</h4>
                <p className="text-xs text-slate-400">Thank you for contributing to the collective threat defense feed.</p>
              </div>
            ) : (
              <form onSubmit={handleReportSubmit} className="mt-4 space-y-4 text-xs">
                <div>
                  <label className="block text-xs font-medium text-slate-300 mb-1">
                    Suspicious Website URL or Domain *
                  </label>
                  <input
                    type="text"
                    required
                    value={formUrl}
                    onChange={(e) => setFormUrl(e.target.value)}
                    placeholder="https://fake-login-example.com/auth"
                    className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-slate-100 font-mono focus:border-blue-500 focus:outline-none"
                  />
                </div>

                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <label className="block text-xs font-medium text-slate-300 mb-1">
                      Threat Category
                    </label>
                    <select
                      value={formCategory}
                      onChange={(e) => setFormCategory(e.target.value as any)}
                      className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-slate-100 focus:border-blue-500 focus:outline-none"
                    >
                      <option value="Fake Banking">Fake Banking</option>
                      <option value="Phishing">Phishing</option>
                      <option value="Credential Harvester">Credential Harvester</option>
                      <option value="Scam">Scam</option>
                      <option value="Malware">Malware</option>
                    </select>
                  </div>

                  <div>
                    <label className="block text-xs font-medium text-slate-300 mb-1">
                      Targeted Brand / Service
                    </label>
                    <input
                      type="text"
                      value={formBrand}
                      onChange={(e) => setFormBrand(e.target.value)}
                      placeholder="e.g. PayPal, Apple, Chase"
                      className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-slate-100 focus:border-blue-500 focus:outline-none"
                    />
                  </div>
                </div>

                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <label className="block text-xs font-medium text-slate-300 mb-1">
                      Assessed Severity
                    </label>
                    <select
                      value={formSeverity}
                      onChange={(e) => setFormSeverity(e.target.value as any)}
                      className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-slate-100 focus:border-blue-500 focus:outline-none"
                    >
                      <option value="critical">Critical (Active credential harvest)</option>
                      <option value="high">High (Known malicious patterns)</option>
                      <option value="medium">Medium (Suspicious typosquat)</option>
                    </select>
                  </div>

                  <div>
                    <label className="block text-xs font-medium text-slate-300 mb-1">
                      Analyst Handle (Optional)
                    </label>
                    <input
                      type="text"
                      value={formReporter}
                      onChange={(e) => setFormReporter(e.target.value)}
                      placeholder="e.g. sec_researcher"
                      className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-slate-100 font-mono focus:border-blue-500 focus:outline-none"
                    />
                  </div>
                </div>

                <div>
                  <label className="block text-xs font-medium text-slate-300 mb-1">
                    Evidence & Lure Description *
                  </label>
                  <textarea
                    rows={3}
                    required
                    value={formNotes}
                    onChange={(e) => setFormNotes(e.target.value)}
                    placeholder="Describe how the attack is conducted (e.g. SMS lure claiming account restriction, deceptive OTP intercept form)..."
                    className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-slate-100 focus:border-blue-500 focus:outline-none leading-relaxed"
                  />
                </div>

                <div className="pt-2 flex justify-end gap-2">
                  <button
                    type="button"
                    onClick={() => setIsReportModalOpen(false)}
                    className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 font-medium transition-colors"
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    disabled={isSubmitting}
                    className="px-4 py-2 rounded-lg bg-rose-600 hover:bg-rose-500 text-white font-semibold transition-colors disabled:opacity-50"
                  >
                    {isSubmitting ? 'Submitting to Flask API...' : 'Submit Report'}
                  </button>
                </div>
              </form>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
