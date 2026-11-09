import React from 'react';
import { Shield, Radio, Server, Search, Terminal } from 'lucide-react';
import { BackendHealth } from '../../types/security';

export type NavPage = 'dashboard' | 'scanner' | 'results' | 'threats' | 'history' | 'about';

interface HeaderProps {
  currentPage: NavPage;
  onNavigate: (page: NavPage) => void;
  backendHealth: BackendHealth;
  onOpenBackendModal: () => void;
  onQuickScanClick: () => void;
}

export const Header: React.FC<HeaderProps> = ({
  currentPage,
  onNavigate,
  backendHealth,
  onOpenBackendModal,
  onQuickScanClick,
}) => {
  const isConnected = backendHealth.status === 'connected';

  return (
    <header className="sticky top-0 z-40 w-full border-b border-slate-800/80 bg-[#070b14]/90 backdrop-blur-md px-6 py-3.5">
      <div className="mx-auto flex max-w-7xl items-center justify-between gap-8">
        {/* Zone 1: Brand Title (single text element wordmark) */}
        <button
          onClick={() => onNavigate('dashboard')}
          className="flex items-center gap-2.5 text-left text-lg font-bold tracking-tight text-white whitespace-nowrap shrink-0 hover:opacity-90 transition-opacity"
        >
          <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-gradient-to-br from-blue-600 to-indigo-700 text-white shadow-sm shadow-blue-500/20">
            <Shield className="h-5 w-5" />
          </div>
          <span className="font-semibold tracking-tight text-slate-100">
            CyberShield <span className="text-blue-400">AI</span>
          </span>
        </button>

        {/* Zone 2: Navigation Links (single-line, clean hover states) */}
        <nav className="hidden lg:flex items-center gap-1 text-sm font-medium text-slate-400">
          <button
            onClick={() => onNavigate('dashboard')}
            className={`px-3 py-1.5 rounded-md transition-colors whitespace-nowrap shrink-0 ${
              currentPage === 'dashboard'
                ? 'text-white bg-slate-800/70 font-semibold'
                : 'hover:text-slate-200 hover:bg-slate-850/40'
            }`}
          >
            Dashboard
          </button>
          <button
            onClick={() => onNavigate('scanner')}
            className={`px-3 py-1.5 rounded-md transition-colors whitespace-nowrap shrink-0 ${
              currentPage === 'scanner'
                ? 'text-white bg-slate-800/70 font-semibold'
                : 'hover:text-slate-200 hover:bg-slate-850/40'
            }`}
          >
            URL Scanner
          </button>
          <button
            onClick={() => onNavigate('results')}
            className={`px-3 py-1.5 rounded-md transition-colors whitespace-nowrap shrink-0 ${
              currentPage === 'results'
                ? 'text-white bg-slate-800/70 font-semibold'
                : 'hover:text-slate-200 hover:bg-slate-850/40'
            }`}
          >
            Scan Results
          </button>
          <button
            onClick={() => onNavigate('threats')}
            className={`px-3 py-1.5 rounded-md transition-colors whitespace-nowrap shrink-0 ${
              currentPage === 'threats'
                ? 'text-white bg-slate-800/70 font-semibold'
                : 'hover:text-slate-200 hover:bg-slate-850/40'
            }`}
          >
            Threat Intelligence
          </button>
          <button
            onClick={() => onNavigate('history')}
            className={`px-3 py-1.5 rounded-md transition-colors whitespace-nowrap shrink-0 ${
              currentPage === 'history'
                ? 'text-white bg-slate-800/70 font-semibold'
                : 'hover:text-slate-200 hover:bg-slate-850/40'
            }`}
          >
            Scan History
          </button>
          <button
            onClick={() => onNavigate('about')}
            className={`px-3 py-1.5 rounded-md transition-colors whitespace-nowrap shrink-0 ${
              currentPage === 'about'
                ? 'text-white bg-slate-800/70 font-semibold'
                : 'hover:text-slate-200 hover:bg-slate-850/40'
            }`}
          >
            About & API
          </button>
        </nav>

        {/* Zone 3: Primary Actions (Backend Status button + New Scan) */}
        <div className="flex items-center gap-3 shrink-0">
          {/* Backend Connection Status Button */}
          <button
            onClick={onOpenBackendModal}
            title="Configure Python Flask Backend (http://localhost:5000)"
            className="flex items-center gap-2 rounded-lg border border-slate-800 bg-slate-900/80 px-3 py-1.5 text-xs font-medium text-slate-300 hover:border-slate-700 hover:bg-slate-800/90 transition-colors whitespace-nowrap shrink-0"
          >
            <Server className="h-3.5 w-3.5 text-slate-400" />
            <span className="hidden sm:inline">Flask API:</span>
            <span className="flex items-center gap-1.5">
              <span
                className={`h-2 w-2 rounded-full ${
                  isConnected
                    ? 'bg-emerald-400'
                    : backendHealth.status === 'checking'
                    ? 'bg-amber-400'
                    : 'bg-indigo-400'
                }`}
              />
              <span className="tabular-nums">
                {isConnected
                  ? 'Connected'
                  : backendHealth.status === 'checking'
                  ? 'Pinging...'
                  : 'Preview Mode'}
              </span>
            </span>
          </button>

          {/* Primary CTA */}
          <button
            onClick={onQuickScanClick}
            className="flex items-center gap-2 rounded-lg bg-blue-600 px-3.5 py-1.5 text-xs font-medium text-white shadow-sm shadow-blue-500/20 hover:bg-blue-500 active:bg-blue-700 transition-colors whitespace-nowrap shrink-0"
          >
            <Search className="h-3.5 w-3.5" />
            <span>Scan Website</span>
          </button>
        </div>
      </div>

      {/* Mobile navigation row */}
      <div className="flex lg:hidden overflow-x-auto gap-2 pt-2.5 pb-0.5 border-t border-slate-800/40 text-xs text-slate-400 mt-2">
        {(['dashboard', 'scanner', 'results', 'threats', 'history', 'about'] as NavPage[]).map(page => (
          <button
            key={page}
            onClick={() => onNavigate(page)}
            className={`px-2.5 py-1 rounded whitespace-nowrap shrink-0 capitalize ${
              currentPage === page ? 'text-white bg-slate-800 font-semibold' : 'hover:text-slate-200'
            }`}
          >
            {page === 'about' ? 'About & API' : page}
          </button>
        ))}
      </div>
    </header>
  );
};
