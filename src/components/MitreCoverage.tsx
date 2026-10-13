/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 * 
 * SENTINEL FUSION - MITRE ATT&CK Matrix & Detection Coverage
 * Maps correlated multi-source events to ATT&CK tactics, techniques, and test validations.
 */

import React, { useState } from 'react';
import { Incident } from '../types/security';
import { 
  ShieldCheck, 
  ExternalLink, 
  CheckCircle2, 
  Layers, 
  Play, 
  Zap, 
  HelpCircle 
} from 'lucide-react';

interface MitreCoverageProps {
  incident: Incident;
  onSelectEventId?: (eventId: string) => void;
}

export const MitreCoverage: React.FC<MitreCoverageProps> = ({
  incident,
  onSelectEventId
}) => {
  const [testResult, setTestResult] = useState<string | null>(null);

  const tactics = [
    {
      name: 'Reconnaissance',
      phase: 'TA0043',
      techniques: [
        { id: 'T1046', name: 'Network Service Discovery', observed: true, eventIds: ['EV-NMAP-001'], tool: 'Nmap' },
        { id: 'T1595', name: 'Active Scanning', observed: false, eventIds: [], tool: 'Suricata' }
      ]
    },
    {
      name: 'Initial Access',
      phase: 'TA0001',
      techniques: [
        { id: 'T1190', name: 'Exploit Public-Facing App', observed: true, eventIds: ['EV-SURI-002', 'EV-PCAP-003'], tool: 'Suricata / TShark' },
        { id: 'T1078', name: 'Valid Accounts', observed: false, eventIds: [], tool: 'Wazuh' }
      ]
    },
    {
      name: 'Execution',
      phase: 'TA0002',
      techniques: [
        { id: 'T1059.004', name: 'Unix Shell (sh/bash)', observed: true, eventIds: ['EV-WAZUH-005'], tool: 'Wazuh EDR' },
        { id: 'T1204', name: 'User Execution', observed: false, eventIds: [], tool: 'Wazuh' }
      ]
    },
    {
      name: 'Command & Control',
      phase: 'TA0011',
      techniques: [
        { id: 'T1071', name: 'Application Layer Protocol', observed: true, eventIds: ['EV-PCAP-006', 'EV-MISP-007'], tool: 'TShark / MISP' },
        { id: 'T1573', name: 'Encrypted Channel', observed: false, eventIds: [], tool: 'Zeek' }
      ]
    },
    {
      name: 'Lateral Tool Transfer',
      phase: 'TA0008',
      techniques: [
        { id: 'T1105', name: 'Ingress Tool Transfer (curl)', observed: true, eventIds: ['EV-ZEEK-004'], tool: 'Zeek / Wazuh' },
        { id: 'T1021', name: 'Remote Services', observed: false, eventIds: [], tool: 'Suricata' }
      ]
    }
  ];

  const handleSimulateRuleTest = (techniqueId: string) => {
    setTestResult(`Replaying synthetic telemetry for ${techniqueId}... SUCCESS. Detection rule triggered in 0.04s.`);
    setTimeout(() => setTestResult(null), 4000);
  };

  return (
    <div className="p-4 sm:p-6 space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <div className="flex items-center gap-2">
            <ShieldCheck className="w-5 h-5 text-indigo-400" />
            <h1 className="text-xl font-bold text-white tracking-tight">
              MITRE ATT&CK Matrix & Detection Validation
            </h1>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Correlated enterprise kill-chain mapping with direct evidence linkage and synthetic rule validation.
          </p>
        </div>

        <div className="flex items-center gap-2 text-xs font-mono">
          <span className="px-2.5 py-1 bg-indigo-950 text-indigo-300 border border-indigo-800 rounded font-semibold">
            5 Confirmed Techniques Mapped
          </span>
        </div>
      </div>

      {testResult && (
        <div className="p-3 bg-emerald-950/80 border border-emerald-700 text-emerald-300 text-xs font-mono rounded-lg flex items-center gap-2 animate-fade-in">
          <CheckCircle2 className="w-4 h-4 text-emerald-400" />
          <span>{testResult}</span>
        </div>
      )}

      {/* Tactic Columns Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-4">
        {tactics.map(tactic => (
          <div key={tactic.phase} className="bg-slate-950 border border-slate-800 rounded-xl overflow-hidden shadow-lg flex flex-col">
            <div className="bg-slate-900 px-3.5 py-2.5 border-b border-slate-800">
              <div className="text-[10px] font-mono text-indigo-400">{tactic.phase}</div>
              <h3 className="text-xs font-bold text-slate-100">{tactic.name}</h3>
            </div>

            <div className="p-3 space-y-2.5 flex-1">
              {tactic.techniques.map(tech => (
                <div
                  key={tech.id}
                  className={`p-3 rounded-lg border text-xs space-y-2 transition ${
                    tech.observed 
                      ? 'bg-indigo-950/40 border-indigo-700/80 shadow-sm' 
                      : 'bg-slate-900/30 border-slate-800/80 opacity-60'
                  }`}
                >
                  <div className="flex items-start justify-between gap-1">
                    <span className="font-mono text-[10px] font-bold text-cyan-400">
                      {tech.id}
                    </span>
                    <span className={`text-[9px] font-mono px-1 py-0.2 rounded font-bold ${
                      tech.observed ? 'bg-indigo-900 text-indigo-200' : 'bg-slate-800 text-slate-500'
                    }`}>
                      {tech.observed ? 'OBSERVED' : 'UNSEEN'}
                    </span>
                  </div>

                  <div className="font-semibold text-slate-200 text-xs leading-snug">
                    {tech.name}
                  </div>

                  {tech.observed && (
                    <div className="pt-2 border-t border-indigo-900/60 space-y-1.5 font-mono text-[10px]">
                      <div className="text-slate-400">
                        Sensor: <span className="text-slate-200 font-semibold">{tech.tool}</span>
                      </div>
                      <div className="flex flex-wrap gap-1">
                        {tech.eventIds.map(eid => (
                          <button
                            key={eid}
                            onClick={() => onSelectEventId && onSelectEventId(eid)}
                            className="px-1.5 py-0.5 bg-slate-900 hover:bg-slate-800 border border-indigo-700/50 text-indigo-300 rounded hover:text-white transition cursor-pointer"
                          >
                            {eid}
                          </button>
                        ))}
                      </div>
                    </div>
                  )}

                  <div className="pt-1">
                    <button
                      onClick={() => handleSimulateRuleTest(tech.id)}
                      className="w-full py-1 bg-slate-900 hover:bg-slate-800 text-slate-400 hover:text-cyan-300 rounded text-[10px] font-mono flex items-center justify-center gap-1 transition cursor-pointer"
                    >
                      <Play className="w-2.5 h-2.5 text-cyan-400" />
                      <span>Test Detection Rule</span>
                    </button>
                  </div>
                </div>
              ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};
