/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 * 
 * SENTINEL FUSION - Incident Investigation Workbench
 * Correlated multi-source timeline, competing hypotheses, baseline diffs, and evidence chain.
 */

import React, { useState } from 'react';
import { 
  Incident, 
  NormalizedEvent, 
  ToolSource 
} from '../types/security';
import { 
  AlertCircle, 
  CheckCircle2, 
  Clock, 
  Copy, 
  ExternalLink, 
  FileCode, 
  Filter, 
  Hash, 
  HelpCircle, 
  Layers, 
  Lock, 
  Radio, 
  Server, 
  ShieldAlert, 
  Terminal, 
  Zap, 
  ChevronDown, 
  ChevronRight,
  Sparkles
} from 'lucide-react';

interface IncidentWorkbenchProps {
  incident: Incident;
  onSelectEventForInspector?: (event: NormalizedEvent) => void;
  onNavigateToTab?: (tab: string) => void;
  onOpenAIWithQuestion?: (question: string) => void;
  isDarkMode?: boolean;
}

export const IncidentWorkbench: React.FC<IncidentWorkbenchProps> = ({
  incident,
  onNavigateToTab,
  onOpenAIWithQuestion,
  isDarkMode = false
}) => {
  const [selectedToolFilter, setSelectedToolFilter] = useState<string>('ALL');
  const [expandedRawEventId, setExpandedRawEventId] = useState<string | null>(null);
  const [copiedHash, setCopiedHash] = useState<string | null>(null);

  const filteredEvents = incident.events.filter(e => {
    if (selectedToolFilter === 'ALL') return true;
    return e.sourceTool === selectedToolFilter;
  });

  const handleCopyHash = (hash: string) => {
    navigator.clipboard.writeText(hash);
    setCopiedHash(hash);
    setTimeout(() => setCopiedHash(null), 2000);
  };

  const getToolBadgeStyle = (tool: ToolSource) => {
    if (isDarkMode) {
      switch (tool) {
        case 'NMAP': return 'bg-amber-950/70 text-amber-300 border-amber-700/50';
        case 'OPENVAS_GREENBONE': return 'bg-orange-950/70 text-orange-300 border-orange-700/50';
        case 'SURICATA': return 'bg-rose-950/70 text-rose-300 border-rose-700/50';
        case 'ZEEK': return 'bg-purple-950/70 text-purple-300 border-purple-700/50';
        case 'WIRESHARK_TSHARK': return 'bg-sky-950/70 text-sky-300 border-sky-700/50';
        case 'WAZUH': return 'bg-emerald-950/70 text-emerald-300 border-emerald-700/50';
        case 'MISP': return 'bg-pink-950/70 text-pink-300 border-pink-700/50';
        default: return 'bg-slate-800 text-slate-300 border-slate-700';
      }
    }
    // Clean, crisp enterprise light mode styling
    switch (tool) {
      case 'NMAP': return 'bg-amber-50 text-amber-800 border-amber-200';
      case 'OPENVAS_GREENBONE': return 'bg-orange-50 text-orange-800 border-orange-200';
      case 'SURICATA': return 'bg-rose-50 text-rose-800 border-rose-200';
      case 'ZEEK': return 'bg-purple-50 text-purple-800 border-purple-200';
      case 'WIRESHARK_TSHARK': return 'bg-sky-50 text-sky-800 border-sky-200';
      case 'WAZUH': return 'bg-emerald-50 text-emerald-800 border-emerald-200';
      case 'MISP': return 'bg-pink-50 text-pink-800 border-pink-200';
      default: return 'bg-slate-100 text-slate-700 border-slate-200';
    }
  };

  const primaryAsset = incident.affectedAssets[0];

  return (
    <div className="p-4 sm:p-6 space-y-6 max-w-7xl mx-auto font-sans">
      {/* Top Incident Summary Card */}
      <div className={`border rounded-2xl p-6 shadow-sm relative overflow-hidden transition-colors ${
        isDarkMode 
          ? 'bg-slate-900/90 border-slate-800' 
          : 'bg-white border-slate-200 shadow-sm'
      }`}>
        <div className="flex flex-col lg:flex-row lg:items-start justify-between gap-6 relative z-10">
          <div className="space-y-3 flex-1">
            <div className="flex items-center gap-2.5 flex-wrap">
              <span className="px-2.5 py-1 text-xs font-bold rounded-full bg-rose-50 border border-rose-200 text-rose-700">
                CRITICAL INCIDENT
              </span>
              <span className="font-mono text-indigo-600 font-bold text-sm">
                {incident.id}
              </span>
              <span className="text-slate-300">•</span>
              <span className="text-xs text-slate-500 flex items-center gap-1 font-mono">
                <Clock className="w-3.5 h-3.5 text-slate-400" />
                First Seen: {new Date(incident.firstObservedAt).toLocaleTimeString()} UTC
              </span>
              <span className="text-slate-300">•</span>
              <span className="text-xs text-slate-500 flex items-center gap-1 font-mono">
                Last Seen: {new Date(incident.lastObservedAt).toLocaleTimeString()} UTC
              </span>
            </div>

            <h1 className={`text-xl sm:text-2xl font-bold tracking-tight ${
              isDarkMode ? 'text-white' : 'text-slate-900'
            }`}>
              {incident.title}
            </h1>

            <p className={`text-sm leading-relaxed max-w-4xl font-normal ${
              isDarkMode ? 'text-slate-300' : 'text-slate-600'
            }`}>
              {incident.summary}
            </p>

            <div className="flex flex-wrap items-center gap-3 pt-2 text-xs font-mono">
              <div className={`flex items-center gap-1.5 px-3 py-1.5 border rounded-xl ${
                isDarkMode ? 'bg-slate-950 border-slate-800' : 'bg-slate-50 border-slate-200 text-slate-700'
              }`}>
                <Server className="w-3.5 h-3.5 text-indigo-600" />
                <span className="text-slate-400">Target Asset:</span>
                <span className="font-bold text-slate-900">{primaryAsset?.hostname || 'Corp-DB01'}</span>
                <span className="text-indigo-600 font-bold">({primaryAsset?.ip})</span>
              </div>

              <div className={`flex items-center gap-1.5 px-3 py-1.5 border rounded-xl ${
                isDarkMode ? 'bg-slate-950 border-rose-900/60' : 'bg-rose-50/70 border-rose-200 text-slate-700'
              }`}>
                <AlertCircle className="w-3.5 h-3.5 text-rose-600" />
                <span className="text-slate-500">Attacker Ingress:</span>
                <span className="text-rose-700 font-bold">{incident.attackerIps.join(', ')}</span>
              </div>

              <div className={`flex items-center gap-1.5 px-3 py-1.5 border rounded-xl ${
                isDarkMode ? 'bg-slate-950 border-slate-800' : 'bg-slate-50 border-slate-200 text-slate-700'
              }`}>
                <Layers className="w-3.5 h-3.5 text-indigo-600" />
                <span className="text-slate-400">Vector:</span>
                <span className="text-slate-800 font-semibold">{incident.primaryAttackVector}</span>
              </div>
            </div>
          </div>

          {/* Explainable Confidence Radar Panel */}
          <div className={`border rounded-2xl p-5 lg:w-80 shrink-0 space-y-3.5 shadow-2xs ${
            isDarkMode 
              ? 'bg-slate-950/90 border-slate-800/80' 
              : 'bg-slate-50/90 border-slate-200'
          }`}>
            <div className="flex items-center justify-between">
              <span className="text-xs font-bold uppercase tracking-wider text-slate-500">
                Confidence Breakdown
              </span>
              <span className="text-base font-mono font-black text-emerald-600">
                {incident.confidenceScore}%
              </span>
            </div>

            <div className="space-y-2 text-xs">
              <div>
                <div className="flex justify-between text-[11px] text-slate-400 mb-1">
                  <span>Network Discovery (Nmap)</span>
                  <span className="font-mono text-cyan-300">+{incident.confidenceBreakdown.networkDiscoveryCorroboration}%</span>
                </div>
                <div className="h-1.5 bg-slate-900 rounded-full overflow-hidden">
                  <div className="h-full bg-cyan-500 rounded-full" style={{ width: `${(incident.confidenceBreakdown.networkDiscoveryCorroboration / 25) * 100}%` }} />
                </div>
              </div>

              <div>
                <div className="flex justify-between text-[11px] text-slate-400 mb-1">
                  <span>NIDS Exploit Detection (Suricata)</span>
                  <span className="font-mono text-rose-300">+{incident.confidenceBreakdown.idsPayloadDetection}%</span>
                </div>
                <div className="h-1.5 bg-slate-900 rounded-full overflow-hidden">
                  <div className="h-full bg-rose-500 rounded-full" style={{ width: `${(incident.confidenceBreakdown.idsPayloadDetection / 30) * 100}%` }} />
                </div>
              </div>

              <div>
                <div className="flex justify-between text-[11px] text-slate-400 mb-1">
                  <span>Packet Payload Match (TShark)</span>
                  <span className="font-mono text-sky-300">+{incident.confidenceBreakdown.packetForensicsVerification}%</span>
                </div>
                <div className="h-1.5 bg-slate-900 rounded-full overflow-hidden">
                  <div className="h-full bg-sky-500 rounded-full" style={{ width: `${(incident.confidenceBreakdown.packetForensicsVerification / 20) * 100}%` }} />
                </div>
              </div>

              <div>
                <div className="flex justify-between text-[11px] text-slate-400 mb-1">
                  <span>Endpoint Child Spawn (Wazuh)</span>
                  <span className="font-mono text-emerald-300">+{incident.confidenceBreakdown.endpointExecutionConfirmation}%</span>
                </div>
                <div className="h-1.5 bg-slate-900 rounded-full overflow-hidden">
                  <div className="h-full bg-emerald-500 rounded-full" style={{ width: `${(incident.confidenceBreakdown.endpointExecutionConfirmation / 15) * 100}%` }} />
                </div>
              </div>

              <div>
                <div className="flex justify-between text-[11px] text-slate-400 mb-1">
                  <span>Threat Intel Attribution (MISP)</span>
                  <span className="font-mono text-purple-300">+{incident.confidenceBreakdown.threatIntelReputationMatch}%</span>
                </div>
                <div className="h-1.5 bg-slate-900 rounded-full overflow-hidden">
                  <div className="h-full bg-purple-500 rounded-full" style={{ width: `${(incident.confidenceBreakdown.threatIntelReputationMatch / 10) * 100}%` }} />
                </div>
              </div>
            </div>

            <p className="text-[10px] text-slate-500 italic pt-1">
              Score is calculated deterministically from multi-source cross-corroboration. No unexplained black-box scores.
            </p>
          </div>
        </div>
      </div>

      {/* Grid: Competing Hypotheses & Asset Baseline Diff */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Competing Hypotheses */}
        <div className={`border rounded-2xl p-6 space-y-4 shadow-sm transition-colors ${
          isDarkMode ? 'bg-slate-900/90 border-slate-800' : 'bg-white border-slate-200'
        }`}>
          <div className="flex items-center justify-between pb-2 border-b border-slate-100">
            <div className="flex items-center gap-2">
              <HelpCircle className="w-4 h-4 text-indigo-600" />
              <h2 className="text-sm font-bold uppercase tracking-wider text-slate-800">
                Competing Hypotheses Evaluation
              </h2>
            </div>
            <span className="text-xs text-slate-400 font-mono">Adversarial Reasoning</span>
          </div>

          <div className="space-y-3">
            {incident.hypotheses.map(hyp => {
              const isHigh = hyp.likelihood === 'HIGH';
              return (
                <div 
                  key={hyp.id}
                  className={`p-4 rounded-xl border transition-all ${
                    isHigh 
                      ? isDarkMode 
                        ? 'bg-slate-950/80 border-cyan-800/80 shadow-md' 
                        : 'bg-indigo-50/40 border-indigo-200 shadow-2xs'
                      : isDarkMode 
                      ? 'bg-slate-950/40 border-slate-800 opacity-75' 
                      : 'bg-slate-50/60 border-slate-200 opacity-80'
                  }`}
                >
                  <div className="flex items-start justify-between gap-3">
                    <div className="space-y-1">
                      <div className="flex items-center gap-2">
                        <span className={`text-xs font-mono font-bold px-2 py-0.5 rounded-full ${
                          isHigh 
                            ? 'bg-indigo-100 text-indigo-800 border border-indigo-200' 
                            : 'bg-slate-200 text-slate-700'
                        }`}>
                          {hyp.likelihood} LIKELIHOOD ({hyp.confidencePercentage}%)
                        </span>
                        <h3 className={`text-sm font-bold ${isDarkMode ? 'text-slate-100' : 'text-slate-900'}`}>{hyp.title}</h3>
                      </div>
                      <p className={`text-xs leading-relaxed pt-1 ${isDarkMode ? 'text-slate-300' : 'text-slate-600'}`}>
                        {hyp.rationale}
                      </p>
                    </div>
                  </div>

                  <div className={`mt-3 pt-3 border-t flex flex-wrap items-center gap-3 text-xs ${
                    isDarkMode ? 'border-slate-800/80' : 'border-slate-200'
                  }`}>
                    <div className="flex items-center gap-1.5">
                      <span className="text-[11px] text-emerald-700 font-bold">Supporting Evidence:</span>
                      <div className="flex gap-1 flex-wrap">
                        {hyp.supportingEvidenceIds.map(id => (
                          <span key={id} className="font-mono text-[10px] px-1.5 py-0.5 bg-emerald-50 border border-emerald-200 text-emerald-800 rounded font-semibold">
                            {id}
                          </span>
                        ))}
                      </div>
                    </div>

                    {hyp.refutingEvidenceIds.length > 0 && (
                      <div className="flex items-center gap-1.5">
                        <span className="text-[11px] text-rose-700 font-bold">Refuting Evidence:</span>
                        <div className="flex gap-1 flex-wrap">
                          {hyp.refutingEvidenceIds.map(id => (
                            <span key={id} className="font-mono text-[10px] px-1.5 py-0.5 bg-rose-50 border border-rose-200 text-rose-800 rounded font-semibold">
                              {id}
                            </span>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Asset Exposure & Port Baseline Diff */}
        <div className={`border rounded-2xl p-6 space-y-4 shadow-sm transition-colors ${
          isDarkMode ? 'bg-slate-900/90 border-slate-800' : 'bg-white border-slate-200'
        }`}>
          <div className="flex items-center justify-between pb-2 border-b border-slate-100">
            <div className="flex items-center gap-2">
              <Server className="w-4 h-4 text-indigo-600" />
              <h2 className="text-sm font-bold uppercase tracking-wider text-slate-800">
                Port Baseline Diff
              </h2>
            </div>
            <span className="text-[11px] font-mono text-indigo-600 font-bold bg-indigo-50 px-2 py-0.5 rounded border border-indigo-200">
              Nmap Change Audit
            </span>
          </div>

          <div className={`p-3.5 rounded-xl border text-xs space-y-2 ${
            isDarkMode ? 'bg-slate-950 border-slate-800' : 'bg-slate-50 border-slate-200'
          }`}>
            <div className="flex justify-between text-slate-500">
              <span>Host:</span>
              <span className="font-mono font-bold text-slate-900">{primaryAsset?.hostname}</span>
            </div>
            <div className="flex justify-between text-slate-500">
              <span>Segment:</span>
              <span className="text-indigo-600 font-mono font-bold">{primaryAsset?.segment}</span>
            </div>
            <div className="flex justify-between text-slate-500">
              <span>OS:</span>
              <span className="text-slate-800 truncate max-w-[160px] font-medium">{primaryAsset?.os}</span>
            </div>
          </div>

          <div className="space-y-2">
            <span className="text-xs font-bold text-slate-600 block">Listening Services:</span>
            {primaryAsset?.services.map(srv => {
              const isAnomaly = srv.baselineStatus === 'UNEXPECTED_NEW';
              return (
                <div 
                  key={srv.port}
                  className={`p-2.5 rounded-xl border text-xs flex items-center justify-between ${
                    isAnomaly 
                      ? 'bg-rose-50 border-rose-300 text-rose-900 animate-pulse'
                      : isDarkMode 
                      ? 'bg-slate-950 border-slate-800 text-slate-300' 
                      : 'bg-white border-slate-200 text-slate-800'
                  }`}
                >
                  <div className="flex items-center gap-2">
                    <span className="font-mono font-bold text-slate-900 text-xs">
                      {srv.port}/{srv.protocol}
                    </span>
                    <span className="text-slate-500 truncate max-w-[120px]">{srv.service}</span>
                  </div>

                  <span className={`text-[10px] font-mono px-2 py-0.5 rounded-full font-bold ${
                    isAnomaly ? 'bg-rose-600 text-white' : 'bg-emerald-50 text-emerald-800 border border-emerald-200'
                  }`}>
                    {srv.baselineStatus === 'UNEXPECTED_NEW' ? 'UNAPPROVED PORT' : 'AUTHORIZED'}
                  </span>
                </div>
              );
            })}
          </div>

          <button
            onClick={() => onNavigateToTab && onNavigateToTab('visibility')}
            className={`w-full py-2.5 border text-xs rounded-xl transition font-semibold flex items-center justify-center gap-2 cursor-pointer shadow-2xs ${
              isDarkMode 
                ? 'bg-slate-950 hover:bg-slate-800 border-slate-700 text-cyan-400' 
                : 'bg-slate-50 hover:bg-slate-100 border-slate-200 text-indigo-700'
            }`}
          >
            <span>Audit Network Visibility Matrix</span>
            <ChevronRight className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      {/* Synchronized Multi-Source Timeline Section */}
      <div className={`border rounded-2xl p-6 space-y-5 shadow-sm transition-colors ${
        isDarkMode ? 'bg-slate-900/90 border-slate-800' : 'bg-white border-slate-200'
      }`}>
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-slate-100">
          <div className="flex items-center gap-2">
            <Clock className="w-4 h-4 text-indigo-600" />
            <h2 className={`text-base font-bold tracking-tight ${isDarkMode ? 'text-white' : 'text-slate-900'}`}>
              Synchronized Multi-Source Telemetry Timeline
            </h2>
            <span className={`text-xs font-mono font-bold px-2 py-0.5 rounded-lg border ${
              isDarkMode ? 'text-cyan-400 bg-slate-950 border-slate-800' : 'text-indigo-700 bg-indigo-50 border-indigo-200'
            }`}>
              {filteredEvents.length} Events
            </span>
          </div>

          {/* Tool Filters */}
          <div className="flex items-center gap-1.5 flex-wrap">
            <span className="text-xs text-slate-400 mr-1 flex items-center gap-1">
              <Filter className="w-3 h-3" /> Filter:
            </span>
            {['ALL', 'NMAP', 'SURICATA', 'WIRESHARK_TSHARK', 'ZEEK', 'WAZUH', 'MISP'].map(tool => (
              <button
                key={tool}
                onClick={() => setSelectedToolFilter(tool)}
                className={`px-2.5 py-1 text-xs rounded-lg font-mono transition cursor-pointer border ${
                  selectedToolFilter === tool
                    ? 'bg-indigo-600 text-white border-indigo-600 font-bold shadow-2xs'
                    : isDarkMode 
                    ? 'bg-slate-950 hover:bg-slate-800 text-slate-400 border-slate-800' 
                    : 'bg-slate-50 hover:bg-slate-100 text-slate-600 border-slate-200'
                }`}
              >
                {tool}
              </button>
            ))}
          </div>
        </div>

        {/* Timeline Events List */}
        <div className={`space-y-3 relative before:absolute before:inset-0 before:left-5 before:w-0.5 pl-2 ${
          isDarkMode ? 'before:bg-slate-800' : 'before:bg-slate-200'
        }`}>
          {filteredEvents.map((event) => {
            const isExpanded = expandedRawEventId === event.id;
            const isCritical = event.severity === 'CRITICAL';
            const isHigh = event.severity === 'HIGH';

            return (
              <div 
                key={event.id}
                className="relative pl-8 group"
              >
                {/* Timeline Node Dot */}
                <div className={`absolute left-3.5 top-4 -translate-x-1/2 w-3.5 h-3.5 rounded-full border-2 z-10 transition-transform group-hover:scale-125 ${
                  isDarkMode ? 'border-slate-950' : 'border-white ring-1 ring-slate-300'
                } ${
                  isCritical 
                    ? 'bg-rose-600 shadow-xs' 
                    : isHigh 
                    ? 'bg-amber-500' 
                    : 'bg-indigo-600'
                }`} />

                {/* Event Card */}
                <div className={`border rounded-xl p-4 transition shadow-2xs space-y-3 ${
                  isDarkMode 
                    ? 'bg-slate-950 border-slate-800 hover:border-cyan-800/80' 
                    : 'bg-white border-slate-200 hover:border-indigo-300 hover:shadow-xs'
                }`}>
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className={`px-2.5 py-0.5 text-xs font-mono font-bold rounded-md border ${getToolBadgeStyle(event.sourceTool)}`}>
                        {event.sourceTool}
                      </span>
                      <span className="font-mono text-indigo-600 text-xs font-bold">
                        {event.id}
                      </span>
                      <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full ${
                        isCritical 
                          ? 'bg-rose-50 text-rose-700 border border-rose-200' 
                          : 'bg-slate-100 text-slate-700'
                      }`}>
                        {event.severity}
                      </span>
                      <span className="text-slate-400 text-xs font-mono">
                        {new Date(event.timestamp).toISOString().replace('T', ' ').replace('Z', ' UTC')}
                      </span>
                    </div>

                    {/* MITRE Tags */}
                    <div className="flex items-center gap-1.5 flex-wrap">
                      {event.mitreTechniques.map(tid => (
                        <span 
                          key={tid}
                          className="px-2 py-0.5 text-[10px] font-mono font-bold bg-indigo-50 border border-indigo-200 text-indigo-700 rounded-md"
                        >
                          MITRE {tid}
                        </span>
                      ))}
                    </div>
                  </div>

                  <div>
                    <h3 className={`text-sm font-bold mb-1 ${isDarkMode ? 'text-slate-100' : 'text-slate-900'}`}>
                      {event.title}
                    </h3>
                    <p className={`text-xs leading-relaxed ${isDarkMode ? 'text-slate-300' : 'text-slate-600'}`}>
                      {event.description}
                    </p>
                  </div>

                  {/* Cryptographic Evidence Provenance Strip */}
                  <div className={`border rounded-xl p-2.5 flex flex-wrap items-center justify-between gap-2 text-xs font-mono ${
                    isDarkMode ? 'bg-slate-900/80 border-slate-800/80' : 'bg-slate-50 border-slate-200'
                  }`}>
                    <div className="flex items-center gap-2 text-slate-500">
                      <Hash className="w-3.5 h-3.5 text-indigo-600 shrink-0" />
                      <span className="text-[11px] text-slate-400">SHA-256:</span>
                      <span className="text-slate-700 text-[11px] truncate max-w-[200px] sm:max-w-md font-bold">
                        {event.evidenceHash}
                      </span>
                      <button
                        onClick={() => handleCopyHash(event.evidenceHash)}
                        className="text-indigo-600 hover:text-indigo-700 transition cursor-pointer p-0.5"
                        title="Copy SHA-256 hash"
                      >
                        <Copy className="w-3 h-3" />
                      </button>
                      {copiedHash === event.evidenceHash && (
                        <span className="text-[10px] text-emerald-600 font-sans font-bold">Copied!</span>
                      )}
                    </div>

                    <div className="flex items-center gap-2">
                      <button
                        onClick={() => setExpandedRawEventId(isExpanded ? null : event.id)}
                        className={`flex items-center gap-1 text-[11px] px-2.5 py-1 rounded-lg border transition cursor-pointer font-sans font-medium ${
                          isDarkMode 
                            ? 'bg-slate-800 hover:bg-slate-700 text-slate-300 border-slate-700' 
                            : 'bg-white hover:bg-slate-100 text-slate-700 border-slate-200 shadow-2xs'
                        }`}
                      >
                        <FileCode className="w-3 h-3 text-indigo-600" />
                        <span>{isExpanded ? 'Hide Raw Log' : 'Inspect Raw Log'}</span>
                        {isExpanded ? <ChevronDown className="w-3 h-3" /> : <ChevronRight className="w-3 h-3" />}
                      </button>
                    </div>
                  </div>

                  {/* Expandable Raw Telemetry Viewer */}
                  {isExpanded && (
                    <div className="mt-2 p-3.5 bg-slate-900 border border-slate-800 rounded-xl font-mono text-[11px] text-slate-200 overflow-x-auto">
                      <div className="text-[10px] text-slate-400 uppercase tracking-wider mb-1 flex items-center justify-between">
                        <span>Original Ingestion Payload ({event.sourceTool})</span>
                        <span className="text-emerald-400 font-semibold">Integrity Verified ✓</span>
                      </div>
                      <pre className="whitespace-pre-wrap break-all text-slate-300">
                        {event.rawEvent}
                      </pre>
                    </div>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Controlled Action Recommendations Preview */}
      <div className={`border rounded-2xl p-6 shadow-sm space-y-4 transition-colors ${
        isDarkMode 
          ? 'bg-gradient-to-r from-slate-900 to-indigo-950 border-indigo-900/50' 
          : 'bg-gradient-to-r from-white via-indigo-50/20 to-white border-slate-200'
      }`}>
        <div className="flex items-center justify-between flex-wrap gap-2">
          <div className="flex items-center gap-2">
            <Zap className="w-4 h-4 text-amber-500" />
            <h2 className="text-sm font-bold uppercase tracking-wider text-slate-800">
              Recommended Investigation & Containment Actions
            </h2>
          </div>
          <button
            onClick={() => onNavigateToTab && onNavigateToTab('response')}
            className="text-xs text-indigo-600 hover:text-indigo-700 font-bold flex items-center gap-1 cursor-pointer"
          >
            <span>Open Response Queue</span>
            <ChevronRight className="w-3.5 h-3.5" />
          </button>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {incident.recommendations.map(rec => (
            <div 
              key={rec.id} 
              className={`p-3.5 rounded-xl border space-y-1.5 ${
                isDarkMode ? 'bg-slate-950/80 border-slate-800' : 'bg-white border-slate-200 shadow-2xs'
              }`}
            >
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold text-slate-900">{rec.title}</span>
                <span className={`text-[10px] font-mono px-2 py-0.5 rounded-full font-bold ${
                  rec.priority === 'IMMEDIATE' 
                    ? 'bg-rose-50 text-rose-700 border border-rose-200' 
                    : 'bg-amber-50 text-amber-800 border border-amber-200'
                }`}>
                  {rec.priority}
                </span>
              </div>
              <p className="text-xs text-slate-600">{rec.reason}</p>
              {rec.suggestedCommand && (
                <div className="p-2 bg-slate-900 rounded-lg font-mono text-[11px] text-cyan-300 truncate">
                  $ {rec.suggestedCommand}
                </div>
              )}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
