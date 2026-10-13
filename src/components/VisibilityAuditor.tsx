/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 * 
 * SENTINEL FUSION - Security Visibility & Telemetry Quality Auditor
 * Distinguishes "No threat detected" from "Insufficient visibility / silent sensors".
 */

import React from 'react';
import { TelemetryCoverageSegment } from '../types/security';
import { MOCK_COVERAGE_SEGMENTS } from '../engine/sample-data';
import { 
  Eye, 
  AlertTriangle, 
  CheckCircle2, 
  ShieldAlert, 
  Radio, 
  Cpu, 
  Activity, 
  Terminal, 
  Lock, 
  PlusCircle 
} from 'lucide-react';

interface VisibilityAuditorProps {
  segments?: TelemetryCoverageSegment[];
}

export const VisibilityAuditor: React.FC<VisibilityAuditorProps> = ({
  segments = MOCK_COVERAGE_SEGMENTS
}) => {
  return (
    <div className="p-4 sm:p-6 space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <div className="flex items-center gap-2">
            <Eye className="w-5 h-5 text-cyan-400" />
            <h1 className="text-xl font-bold text-white tracking-tight">
              Security Visibility & Sensor Health Auditor
            </h1>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Audits coverage across network discovery, NIDS, protocol behavior, EDR agents, and packet capture.
          </p>
        </div>

        <div className="flex items-center gap-2 text-xs font-mono">
          <span className="px-3 py-1 bg-rose-950/80 text-rose-300 border border-rose-800 rounded font-semibold flex items-center gap-1.5">
            <AlertTriangle className="w-3.5 h-3.5 text-rose-400" />
            1 Critical Blind Spot Identified (User LAN PCAP)
          </span>
        </div>
      </div>

      {/* Summary KPI Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 space-y-2">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>Asset Discovery Coverage</span>
            <Radio className="w-4 h-4 text-amber-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-white">88%</div>
          <div className="text-[11px] text-emerald-400">Daily Nmap scan audits configured</div>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 space-y-2">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>NIDS Threat Inspection</span>
            <Activity className="w-4 h-4 text-rose-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-white">85%</div>
          <div className="text-[11px] text-slate-400">Suricata inline on DMZ & Core</div>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 space-y-2">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>Endpoint EDR Coverage</span>
            <Lock className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-white">90%</div>
          <div className="text-[11px] text-emerald-400">Wazuh active on 552/602 agents</div>
        </div>

        <div className="bg-slate-900 border border-rose-950/60 rounded-xl p-4 space-y-2">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>Full Packet Retention</span>
            <Terminal className="w-4 h-4 text-sky-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-rose-400">60%</div>
          <div className="text-[11px] text-rose-400 font-semibold">User LAN lacks PCAP ring buffers</div>
        </div>
      </div>

      {/* Segment Matrix Table */}
      <div className="bg-slate-950 border border-slate-800 rounded-xl overflow-hidden shadow-xl">
        <div className="px-5 py-3 bg-slate-900 border-b border-slate-800 flex items-center justify-between">
          <h2 className="text-sm font-bold text-slate-200 uppercase tracking-wider">
            Organizational Network Segments & Sensor Quality
          </h2>
          <span className="text-xs text-slate-400 font-mono">4 Subnets Monitored</span>
        </div>

        <div className="divide-y divide-slate-800/80">
          {segments.map((seg, idx) => {
            const isCritical = seg.gapSeverity === 'CRITICAL_GAP';
            const isPartial = seg.gapSeverity === 'PARTIAL_GAP';

            return (
              <div key={idx} className="p-5 space-y-4 hover:bg-slate-900/40 transition">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                  <div className="flex items-center gap-3">
                    <span className="font-bold text-white text-base">{seg.segmentName}</span>
                    <span className="font-mono text-xs text-cyan-400 bg-slate-900 px-2 py-0.5 rounded border border-slate-800">
                      {seg.cidr}
                    </span>
                    <span className="text-xs text-slate-400 font-mono">({seg.totalHosts} Managed Hosts)</span>
                  </div>

                  <span className={`px-2.5 py-1 text-xs font-mono font-bold rounded ${
                    isCritical 
                      ? 'bg-rose-950 text-rose-300 border border-rose-800' 
                      : isPartial 
                      ? 'bg-amber-950 text-amber-300 border border-amber-800' 
                      : 'bg-emerald-950 text-emerald-300 border border-emerald-800'
                  }`}>
                    {seg.gapSeverity.replace('_', ' ')}
                  </span>
                </div>

                {/* 5-Column Sensor Bars */}
                <div className="grid grid-cols-2 sm:grid-cols-5 gap-3 text-xs">
                  <div className="p-2.5 bg-slate-900 rounded-lg border border-slate-800 space-y-1">
                    <div className="flex justify-between text-slate-400 text-[11px]">
                      <span>Nmap Discovery</span>
                      <span className="font-mono text-slate-200">{seg.nmapCoverage}%</span>
                    </div>
                    <div className="h-1.5 bg-slate-800 rounded-full overflow-hidden">
                      <div className="h-full bg-amber-500 rounded-full" style={{ width: `${seg.nmapCoverage}%` }} />
                    </div>
                  </div>

                  <div className="p-2.5 bg-slate-900 rounded-lg border border-slate-800 space-y-1">
                    <div className="flex justify-between text-slate-400 text-[11px]">
                      <span>Suricata NIDS</span>
                      <span className="font-mono text-slate-200">{seg.suricataCoverage}%</span>
                    </div>
                    <div className="h-1.5 bg-slate-800 rounded-full overflow-hidden">
                      <div className="h-full bg-rose-500 rounded-full" style={{ width: `${seg.suricataCoverage}%` }} />
                    </div>
                  </div>

                  <div className="p-2.5 bg-slate-900 rounded-lg border border-slate-800 space-y-1">
                    <div className="flex justify-between text-slate-400 text-[11px]">
                      <span>Zeek Behavior</span>
                      <span className="font-mono text-slate-200">{seg.zeekCoverage}%</span>
                    </div>
                    <div className="h-1.5 bg-slate-800 rounded-full overflow-hidden">
                      <div className="h-full bg-purple-500 rounded-full" style={{ width: `${seg.zeekCoverage}%` }} />
                    </div>
                  </div>

                  <div className="p-2.5 bg-slate-900 rounded-lg border border-slate-800 space-y-1">
                    <div className="flex justify-between text-slate-400 text-[11px]">
                      <span>Wazuh EDR</span>
                      <span className="font-mono text-slate-200">{seg.wazuhCoverage}%</span>
                    </div>
                    <div className="h-1.5 bg-slate-800 rounded-full overflow-hidden">
                      <div className="h-full bg-emerald-500 rounded-full" style={{ width: `${seg.wazuhCoverage}%` }} />
                    </div>
                  </div>

                  <div className="p-2.5 bg-slate-900 rounded-lg border border-slate-800 space-y-1">
                    <div className="flex justify-between text-slate-400 text-[11px]">
                      <span>TShark PCAP</span>
                      <span className={`font-mono font-bold ${seg.pcapCoverage < 30 ? 'text-rose-400' : 'text-slate-200'}`}>
                        {seg.pcapCoverage}%
                      </span>
                    </div>
                    <div className="h-1.5 bg-slate-800 rounded-full overflow-hidden">
                      <div 
                        className={`h-full rounded-full ${seg.pcapCoverage < 30 ? 'bg-rose-500' : 'bg-sky-500'}`} 
                        style={{ width: `${seg.pcapCoverage}%` }} 
                      />
                    </div>
                  </div>
                </div>

                {/* Audit Finding & Risk Assessment */}
                <div className="p-3 bg-slate-900/60 rounded-lg border border-slate-800/80 flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs">
                  <div className="space-y-0.5">
                    <span className="text-[11px] font-bold text-slate-400 uppercase tracking-wider">
                      Visibility Audit Finding:
                    </span>
                    <p className="text-slate-300">
                      {seg.blindSpotAssessment}
                    </p>
                  </div>

                  {isCritical && (
                    <button className="px-3 py-1.5 bg-rose-900/80 hover:bg-rose-800 border border-rose-700 text-rose-100 rounded-lg font-semibold text-xs whitespace-nowrap transition cursor-pointer shrink-0">
                      Deploy Passive Network Tap
                    </button>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
};
