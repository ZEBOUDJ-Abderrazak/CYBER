/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 * 
 * SENTINEL FUSION - Executive Header & Sensor Telemetry Bar (Expert UI/UX)
 */

import React from 'react';
import { 
  ShieldAlert, 
  Activity, 
  Radio, 
  Terminal, 
  Cpu, 
  FileText, 
  Database, 
  Sparkles, 
  AlertTriangle,
  Lock,
  Download,
  Share2,
  Sun,
  Moon,
  BookOpen,
  Flame,
  UserCheck
} from 'lucide-react';
import { Incident } from '../types/security';

interface HeaderProps {
  currentScenario: string;
  onSelectScenario: (scenarioId: string) => void;
  activeIncident: Incident;
  onOpenReport: () => void;
  onOpenEvidenceLedger: () => void;
  onOpenAIQuery: () => void;
  onOpenReadme?: () => void;
  isDarkMode?: boolean;
  onToggleDarkMode?: () => void;
}

export const Header: React.FC<HeaderProps> = ({
  currentScenario,
  onSelectScenario,
  activeIncident,
  onOpenReport,
  onOpenEvidenceLedger,
  onOpenAIQuery,
  onOpenReadme,
  isDarkMode = false,
  onToggleDarkMode
}) => {
  return (
    <header className={`sticky top-0 z-40 backdrop-blur-md transition-colors ${
      isDarkMode 
        ? 'bg-slate-950 border-b border-cyan-900/40 text-slate-100' 
        : 'bg-white border-b border-slate-200 text-slate-900 shadow-2xs'
    }`}>
      {/* Top Banner */}
      <div className={`px-4 sm:px-6 py-3 flex flex-wrap items-center justify-between gap-3 border-b ${
        isDarkMode ? 'border-slate-900' : 'border-slate-100'
      }`}>
        <div className="flex items-center gap-3">
          <div className="relative flex items-center justify-center w-10 h-10 rounded-xl bg-gradient-to-br from-indigo-600 via-blue-700 to-sky-600 border border-indigo-400/40 shadow-md shadow-indigo-600/10 shrink-0">
            <ShieldAlert className="w-5 h-5 text-white" />
            <span className="absolute -bottom-0.5 -right-0.5 w-2.5 h-2.5 bg-emerald-500 border-2 border-white rounded-full animate-pulse" />
          </div>
          <div>
            <div className="flex items-center gap-2 flex-wrap">
              <span className={`text-lg font-black tracking-wider ${
                isDarkMode 
                  ? 'text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 via-sky-300 to-blue-200' 
                  : 'text-slate-900'
              }`}>
                OPEN SECURITY FUSION
              </span>
              <span className={`px-1.5 py-0.5 text-[10px] font-mono font-bold tracking-wider uppercase rounded-md border ${
                isDarkMode 
                  ? 'bg-cyan-950/80 text-cyan-400 border-cyan-700/50' 
                  : 'bg-indigo-50 text-indigo-700 border-indigo-200'
              }`}>
                UNIFIED v2.4
              </span>

              {/* Lead Architect & Operator Badge */}
              <div className="flex items-center gap-1.5 px-2 py-0.5 rounded-full bg-slate-100 border border-slate-200 text-slate-700 text-[11px] font-medium">
                <UserCheck className="w-3 h-3 text-indigo-600" />
                <span>Lead Architect: <strong className="text-slate-900">Zeboudj Abderarzak</strong></span>
              </div>
            </div>
            <p className="text-xs text-slate-500 hidden sm:block font-medium">
              One Platform · Multiple Security Engines · Nmap · OpenVAS · Suricata · Zeek · Wazuh · Wireshark
            </p>
          </div>
        </div>

        {/* Live Active Sensor Feeds across the 6 Unified Engines */}
        <div className="hidden xl:flex items-center gap-1.5 text-xs font-mono">
          <span className="text-slate-400 text-[11px] uppercase mr-1">6 Engines:</span>
          <div className="flex items-center gap-1 px-2 py-0.5 rounded-lg border bg-slate-50 border-slate-200 text-slate-700 text-[11px]" title="Network Discovery">
            <Radio className="w-3 h-3 text-emerald-500 animate-pulse" /> Nmap
          </div>
          <div className="flex items-center gap-1 px-2 py-0.5 rounded-lg border bg-orange-50 border-orange-200 text-orange-800 text-[11px]" title="Vulnerability Assessment">
            <Flame className="w-3 h-3 text-orange-600" /> OpenVAS
          </div>
          <div className="flex items-center gap-1 px-2 py-0.5 rounded-lg border bg-slate-50 border-slate-200 text-slate-700 text-[11px]" title="Network Threat Detection">
            <Activity className="w-3 h-3 text-rose-500" /> Suricata
          </div>
          <div className="flex items-center gap-1 px-2 py-0.5 rounded-lg border bg-slate-50 border-slate-200 text-slate-700 text-[11px]" title="Behavioral Protocol Telemetry">
            <Cpu className="w-3 h-3 text-purple-500" /> Zeek
          </div>
          <div className="flex items-center gap-1 px-2 py-0.5 rounded-lg border bg-slate-50 border-slate-200 text-slate-700 text-[11px]" title="Endpoint Protection & EDR">
            <Lock className="w-3 h-3 text-emerald-500" /> Wazuh
          </div>
          <div className="flex items-center gap-1 px-2 py-0.5 rounded-lg border bg-slate-50 border-slate-200 text-slate-700 text-[11px]" title="Packet Forensics & Object Carving">
            <Terminal className="w-3 h-3 text-indigo-500" /> Wireshark
          </div>
        </div>

        {/* Scenario Selector & Action Tools */}
        <div className="flex items-center gap-2">
          <div className="relative">
            <select
              value={currentScenario}
              onChange={(e) => onSelectScenario(e.target.value)}
              className={`text-xs rounded-xl px-3 py-1.5 focus:outline-none font-mono cursor-pointer border ${
                isDarkMode 
                  ? 'bg-slate-900 border-cyan-900/60 text-cyan-300' 
                  : 'bg-white border-slate-200 text-slate-800 shadow-2xs hover:border-slate-300'
              }`}
            >
              <option value="scenario_1">Active Case 1: Operation PhantomBeacon (Spring/JNDI RCE Incident)</option>
              <option value="scenario_2">Active Case 2: Ransomware Lateral Pivot (LockBit 3.0 Live Intrusions)</option>
              <option value="scenario_3">Active Case 3: Covert DNS Tunneling & High-Entropy Exfiltration</option>
            </select>
          </div>

          <button
            onClick={onOpenAIQuery}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-indigo-600 hover:bg-indigo-700 text-white text-xs font-semibold rounded-xl shadow-xs transition cursor-pointer"
            title="Ask Evidence-Grounded AI Investigator"
          >
            <Sparkles className="w-3.5 h-3.5 text-indigo-200" />
            <span className="hidden sm:inline">AI Investigator</span>
          </button>

          <button
            onClick={onOpenEvidenceLedger}
            className={`flex items-center gap-1.5 px-2.5 py-1.5 border text-xs rounded-xl transition cursor-pointer ${
              isDarkMode 
                ? 'bg-slate-900 hover:bg-slate-800 border-slate-700 text-slate-300' 
                : 'bg-white hover:bg-slate-50 border-slate-200 text-slate-700 shadow-2xs'
            }`}
            title="View SHA-256 Tamper-Proof Evidence Ledger"
          >
            <Lock className="w-3.5 h-3.5 text-indigo-600" />
            <span className="hidden sm:inline">Ledger</span>
          </button>

          <button
            onClick={onOpenReport}
            className={`flex items-center gap-1.5 px-2.5 py-1.5 border text-xs rounded-xl transition cursor-pointer ${
              isDarkMode 
                ? 'bg-slate-900 hover:bg-slate-800 border-slate-700 text-slate-300' 
                : 'bg-white hover:bg-slate-50 border-slate-200 text-slate-700 shadow-2xs'
            }`}
            title="Export Forensic Incident Report"
          >
            <Download className="w-3.5 h-3.5 text-slate-500" />
            <span className="hidden sm:inline">Report</span>
          </button>

          {onOpenReadme && (
            <button
              onClick={onOpenReadme}
              className={`flex items-center gap-1.5 px-2.5 py-1.5 border text-xs rounded-xl transition cursor-pointer ${
                isDarkMode 
                  ? 'bg-slate-900 hover:bg-slate-800 border-slate-700 text-slate-300' 
                  : 'bg-white hover:bg-slate-50 border-slate-200 text-slate-700 shadow-2xs'
              }`}
              title="View & Download Platform README.md Architecture Dossier"
            >
              <BookOpen className="w-3.5 h-3.5 text-indigo-600" />
              <span className="hidden sm:inline">README</span>
            </button>
          )}

          {onToggleDarkMode && (
            <button
              onClick={onToggleDarkMode}
              className={`p-1.5 rounded-xl border transition cursor-pointer ${
                isDarkMode 
                  ? 'bg-slate-900 border-slate-700 text-amber-400 hover:bg-slate-800' 
                  : 'bg-white border-slate-200 text-slate-600 hover:bg-slate-50 shadow-2xs'
              }`}
              title={isDarkMode ? 'Switch to Light (White) Mode' : 'Switch to Dark Mode'}
            >
              {isDarkMode ? <Sun className="w-4 h-4" /> : <Moon className="w-4 h-4" />}
            </button>
          )}
        </div>
      </div>

      {/* Incident Status Alert Ribbon */}
      <div className={`px-4 sm:px-6 py-2 flex flex-wrap items-center justify-between text-xs gap-3 border-b ${
        isDarkMode 
          ? 'bg-slate-900/90 border-slate-800' 
          : 'bg-slate-50/90 border-slate-200'
      }`}>
        <div className="flex items-center gap-2.5 flex-wrap">
          <div className="flex items-center gap-1.5 px-2 py-0.5 rounded-full bg-rose-50 border border-rose-200 text-rose-700 font-bold tracking-wide">
            <AlertTriangle className="w-3.5 h-3.5 text-rose-600" />
            <span>{activeIncident.severity}</span>
          </div>

          <span className="font-mono text-indigo-600 font-bold">{activeIncident.id}</span>
          <span className="text-slate-400">•</span>
          <span className={`font-semibold truncate max-w-md sm:max-w-xl ${isDarkMode ? 'text-slate-200' : 'text-slate-800'}`}>
            {activeIncident.title}
          </span>
        </div>

        {/* Explainable Confidence Metric */}
        <div className="flex items-center gap-3 font-mono">
          <div className="flex items-center gap-1.5">
            <span className="text-slate-500 text-[11px] font-medium">CORRELATION CONFIDENCE:</span>
            <span className="text-emerald-600 font-black text-sm">
              {activeIncident.confidenceScore}%
            </span>
          </div>
          <div className="w-24 h-2 bg-slate-200 rounded-full overflow-hidden hidden sm:block">
            <div 
              className="h-full bg-emerald-500 rounded-full"
              style={{ width: `${activeIncident.confidenceScore}%` }}
            />
          </div>
          <span className="text-slate-500 text-[11px] hidden md:inline">
            ({activeIncident.events.length} Telemetry Points Corroborated)
          </span>
        </div>
      </div>
    </header>
  );
};
