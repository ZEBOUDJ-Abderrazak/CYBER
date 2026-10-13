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
    <div className="p-4 sm:p-6 space-y-6 max-w-7xl mx-auto font-sans">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <div className="flex items-center gap-2">
            <Eye className="w-5 h-5 text-indigo-600" />
            <h1 className="text-xl font-bold text-slate-900 tracking-tight">
              Security Visibility & Sensor Quality Auditor
            </h1>
          </div>
          <p className="text-xs text-slate-500 mt-1">
            Audits coverage across network discovery, NIDS, protocol behavior, EDR agents, and packet capture.
          </p>
        </div>

        <div className="flex items-center gap-2 text-xs font-mono">
          <span className="px-3 py-1 bg-rose-50 text-rose-700 border border-rose-200 rounded-lg font-semibold flex items-center gap-1.5 shadow-2xs">
            <AlertTriangle className="w-3.5 h-3.5 text-rose-600" />
            1 Critical Blind Spot Identified (User LAN PCAP)
          </span>
        </div>
      </div>

      {/* Summary KPI Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="bg-white border border-slate-200 rounded-2xl p-5 shadow-sm space-y-2">
          <div className="flex items-center justify-between text-xs text-slate-500 font-medium">
            <span>Asset Discovery Coverage</span>
            <Radio className="w-4 h-4 text-amber-500" />
          </div>
          <div className="text-2xl font-bold font-mono text-slate-900">88%</div>
          <div className="text-[11px] text-emerald-700 font-medium">Daily Nmap scan audits configured</div>
        </div>

        <div className="bg-white border border-slate-200 rounded-2xl p-5 shadow-sm space-y-2">
          <div className="flex items-center justify-between text-xs text-slate-500 font-medium">
            <span>NIDS Threat Inspection</span>
            <Activity className="w-4 h-4 text-rose-600" />
          </div>
          <div className="text-2xl font-bold font-mono text-slate-900">85%</div>
          <div className="text-[11px] text-slate-500 font-medium">Suricata inline on DMZ & Core</div>
        </div>

        <div className="bg-white border border-slate-200 rounded-2xl p-5 shadow-sm space-y-2">
          <div className="flex items-center justify-between text-xs text-slate-500 font-medium">
            <span>Endpoint EDR Coverage</span>
            <Lock className="w-4 h-4 text-emerald-600" />
          </div>
          <div className="text-2xl font-bold font-mono text-slate-900">90%</div>
          <div className="text-[11px] text-emerald-700 font-medium">Wazuh active on 552/602 agents</div>
        </div>

        <div className="bg-white border border-rose-200 rounded-2xl p-5 shadow-sm space-y-2">
          <div className="flex items-center justify-between text-xs text-slate-500 font-medium">
            <span>Full Packet Retention</span>
            <Terminal className="w-4 h-4 text-sky-600" />
          </div>
          <div className="text-2xl font-bold font-mono text-rose-600">60%</div>
          <div className="text-[11px] text-rose-600 font-semibold">User LAN lacks PCAP ring buffers</div>
        </div>
      </div>

      {/* Segment Matrix Table */}
      <div className="bg-white border border-slate-200 rounded-2xl overflow-hidden shadow-sm">
        <div className="px-6 py-4 bg-slate-50 border-b border-slate-200 flex items-center justify-between">
          <h2 className="text-sm font-bold text-slate-900 uppercase tracking-wider">
            Organizational Network Segments & Sensor Quality
          </h2>
          <span className="text-xs text-slate-500 font-mono font-bold">4 Subnets Monitored</span>
        </div>

        <div className="divide-y divide-slate-100">
          {segments.map((seg, idx) => {
            const isCritical = seg.gapSeverity === 'CRITICAL_GAP';
            const isPartial = seg.gapSeverity === 'PARTIAL_GAP';

            return (
              <div key={idx} className="p-6 space-y-4 hover:bg-slate-50/60 transition">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                  <div className="flex items-center gap-3">
                    <span className="font-bold text-slate-900 text-base">{seg.segmentName}</span>
                    <span className="font-mono text-xs text-indigo-700 bg-indigo-50 px-2.5 py-0.5 rounded-lg border border-indigo-200 font-bold">
                      {seg.cidr}
                    </span>
                    <span className="text-xs text-slate-500 font-mono">({seg.totalHosts} Managed Hosts)</span>
                  </div>

                  <span className={`px-2.5 py-1 text-xs font-mono font-bold rounded-full ${
                    isCritical 
                      ? 'bg-rose-50 text-rose-700 border border-rose-200' 
                      : isPartial 
                      ? 'bg-amber-50 text-amber-800 border border-amber-200' 
                      : 'bg-emerald-50 text-emerald-800 border border-emerald-200'
                  }`}>
                    {seg.gapSeverity.replace(/_/g, ' ')}
                  </span>
                </div>

                {/* 5-Column Sensor Bars */}
                <div className="grid grid-cols-2 sm:grid-cols-5 gap-3 text-xs">
                  <div className="p-3 bg-slate-50 rounded-xl border border-slate-200 space-y-1">
                    <div className="flex justify-between text-slate-500 text-[11px] font-medium">
                      <span>Nmap Discovery</span>
                      <span className="font-mono text-slate-900 font-bold">{seg.nmapCoverage}%</span>
                    </div>
                    <div className="h-1.5 bg-slate-200 rounded-full overflow-hidden">
                      <div className="h-full bg-amber-500 rounded-full" style={{ width: `${seg.nmapCoverage}%` }} />
                    </div>
                  </div>

                  <div className="p-3 bg-slate-50 rounded-xl border border-slate-200 space-y-1">
                    <div className="flex justify-between text-slate-500 text-[11px] font-medium">
                      <span>Suricata NIDS</span>
                      <span className="font-mono text-slate-900 font-bold">{seg.suricataCoverage}%</span>
                    </div>
                    <div className="h-1.5 bg-slate-200 rounded-full overflow-hidden">
                      <div className="h-full bg-rose-500 rounded-full" style={{ width: `${seg.suricataCoverage}%` }} />
                    </div>
                  </div>

                  <div className="p-3 bg-slate-50 rounded-xl border border-slate-200 space-y-1">
                    <div className="flex justify-between text-slate-500 text-[11px] font-medium">
                      <span>Zeek Behavior</span>
                      <span className="font-mono text-slate-900 font-bold">{seg.zeekCoverage}%</span>
                    </div>
                    <div className="h-1.5 bg-slate-200 rounded-full overflow-hidden">
                      <div className="h-full bg-purple-500 rounded-full" style={{ width: `${seg.zeekCoverage}%` }} />
                    </div>
                  </div>

                  <div className="p-3 bg-slate-50 rounded-xl border border-slate-200 space-y-1">
                    <div className="flex justify-between text-slate-500 text-[11px] font-medium">
                      <span>Wazuh EDR</span>
                      <span className="font-mono text-slate-900 font-bold">{seg.wazuhCoverage}%</span>
                    </div>
                    <div className="h-1.5 bg-slate-200 rounded-full overflow-hidden">
                      <div className="h-full bg-emerald-500 rounded-full" style={{ width: `${seg.wazuhCoverage}%` }} />
                    </div>
                  </div>

                  <div className="p-3 bg-slate-50 rounded-xl border border-slate-200 space-y-1">
                    <div className="flex justify-between text-slate-500 text-[11px] font-medium">
                      <span>TShark PCAP</span>
                      <span className={`font-mono font-bold ${seg.pcapCoverage < 30 ? 'text-rose-600' : 'text-slate-900'}`}>
                        {seg.pcapCoverage}%
                      </span>
                    </div>
                    <div className="h-1.5 bg-slate-200 rounded-full overflow-hidden">
                      <div 
                        className={`h-full rounded-full ${seg.pcapCoverage < 30 ? 'bg-rose-500' : 'bg-sky-500'}`} 
                        style={{ width: `${seg.pcapCoverage}%` }} 
                      />
                    </div>
                  </div>
                </div>

                {/* Audit Finding & Risk Assessment */}
                <div className="p-4 bg-slate-50/70 rounded-xl border border-slate-200 flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs">
                  <div className="space-y-0.5">
                    <span className="text-[11px] font-bold text-slate-500 uppercase tracking-wider">
                      Visibility Audit Finding:
                    </span>
                    <p className="text-slate-800">
                      {seg.blindSpotAssessment}
                    </p>
                  </div>

                  {isCritical && (
                    <button className="px-3.5 py-2 bg-rose-600 hover:bg-rose-700 text-white rounded-xl font-bold text-xs whitespace-nowrap transition cursor-pointer shrink-0 shadow-2xs">
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
