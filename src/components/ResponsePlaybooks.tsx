/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 * 
 * SENTINEL FUSION - Controlled Defensive Response & SOAR Playbooks
 * Approval-gated containment, risk categorization, rollback planning, and immutable audit trail.
 */

import React, { useState } from 'react';
import { PlaybookResponseAction } from '../types/security';
import { MOCK_RESPONSE_ACTIONS_S1 } from '../engine/sample-data';
import { 
  Zap, 
  ShieldAlert, 
  CheckCircle2, 
  AlertTriangle, 
  Play, 
  RotateCcw, 
  FileText, 
  UserCheck, 
  Lock,
  ChevronDown,
  Terminal,
  Clock
} from 'lucide-react';

interface ResponsePlaybooksProps {
  initialActions?: PlaybookResponseAction[];
}

export const ResponsePlaybooks: React.FC<ResponsePlaybooksProps> = ({
  initialActions = MOCK_RESPONSE_ACTIONS_S1
}) => {
  const [actions, setActions] = useState<PlaybookResponseAction[]>(initialActions);
  const [selectedActionId, setSelectedActionId] = useState<string>('ACT-001');
  const [approverName, setApproverName] = useState<string>('Commander Sarah Jenkins (Lead SOC)');
  const [auditLog, setAuditLog] = useState<Array<{ timestamp: string; actionId: string; user: string; event: string }>>([
    {
      timestamp: '2026-10-13T08:15:30Z',
      actionId: 'ACT-004',
      user: 'Sentinel SOAR Engine',
      event: 'Auto-executed PCAP Ring-Buffer dump. Extracted 42.8 MB.'
    },
    {
      timestamp: '2026-10-13T08:20:00Z',
      actionId: 'ACT-002',
      user: 'Alex Mercer (SOC-L2)',
      event: 'Approved perimeter firewall block for 194.26.29.112.'
    }
  ]);

  const activeAction = actions.find(a => a.id === selectedActionId) || actions[0];

  const handleApprove = (actionId: string) => {
    setActions(prev => prev.map(a => {
      if (a.id === actionId) {
        return {
          ...a,
          status: 'EXECUTING',
          approverName,
          approvedAt: new Date().toISOString()
        };
      }
      return a;
    }));

    // Simulate completion after 1.5s
    setTimeout(() => {
      setActions(prev => prev.map(a => {
        if (a.id === actionId) {
          return {
            ...a,
            status: 'EXECUTED',
            executionLogs: [
              `[${new Date().toLocaleTimeString()}] Authenticated against agent API.`,
              `[${new Date().toLocaleTimeString()}] Dispatched command with safety flags.`,
              `[${new Date().toLocaleTimeString()}] Host isolation confirmed. Verification handshake OK.`
            ]
          };
        }
        return a;
      }));

      setAuditLog(prev => [
        {
          timestamp: new Date().toISOString(),
          actionId,
          user: approverName,
          event: `Authorized and executed playbook: "${activeAction.title}". Safety guarantees met.`
        },
        ...prev
      ]);
    }, 1200);
  };

  const handleRollback = (actionId: string) => {
    setActions(prev => prev.map(a => {
      if (a.id === actionId) {
        return {
          ...a,
          status: 'ROLLED_BACK'
        };
      }
      return a;
    }));

    setAuditLog(prev => [
      {
        timestamp: new Date().toISOString(),
        actionId,
        user: approverName,
        event: `Rolled back playbook: "${activeAction.title}" using command "${activeAction.rollbackCommand}".`
      },
      ...prev
    ]);
  };

  return (
    <div className="p-4 sm:p-6 space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <div className="flex items-center gap-2">
            <Zap className="w-5 h-5 text-amber-400" />
            <h1 className="text-xl font-bold text-white tracking-tight">
              Controlled Defense & SOAR Response Queue
            </h1>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Human-in-the-loop containment workflows with explicit dry-run simulation and verified rollback procedures.
          </p>
        </div>

        <div className="flex items-center gap-2 text-xs font-mono">
          <span className="px-3 py-1 bg-amber-950/80 text-amber-300 border border-amber-800 rounded font-semibold flex items-center gap-1.5">
            <Lock className="w-3.5 h-3.5 text-amber-400" />
            Zero Unrestricted AI Authority Enforcement
          </span>
        </div>
      </div>

      {/* Main 2-Column Split: Action List & Approval Detail Inspector */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Column: Action Queue */}
        <div className="space-y-3">
          <h2 className="text-xs font-bold uppercase tracking-wider text-slate-400 flex items-center justify-between">
            <span>Playbook Action Queue</span>
            <span className="font-mono text-cyan-400">{actions.length} Total</span>
          </h2>

          <div className="space-y-2.5">
            {actions.map(act => {
              const isSelected = act.id === selectedActionId;
              const isPending = act.status === 'PENDING_APPROVAL';
              const isExecuted = act.status === 'EXECUTED';

              return (
                <div
                  key={act.id}
                  onClick={() => setSelectedActionId(act.id)}
                  className={`p-3.5 rounded-xl border transition cursor-pointer ${
                    isSelected 
                      ? 'bg-slate-900 border-cyan-500 shadow-md' 
                      : 'bg-slate-950 border-slate-800 hover:border-slate-700'
                  }`}
                >
                  <div className="flex items-start justify-between gap-2">
                    <span className="font-mono text-[10px] font-bold text-slate-400">
                      {act.id}
                    </span>
                    <span className={`text-[10px] font-mono px-2 py-0.5 rounded font-bold ${
                      isPending ? 'bg-amber-950 text-amber-300 border border-amber-800 animate-pulse' :
                      isExecuted ? 'bg-emerald-950 text-emerald-300 border border-emerald-800' :
                      act.status === 'APPROVED' ? 'bg-blue-950 text-blue-300 border border-blue-800' :
                      'bg-slate-800 text-slate-400'
                    }`}>
                      {act.status.replace('_', ' ')}
                    </span>
                  </div>

                  <h3 className="text-xs font-semibold text-slate-100 mt-1 line-clamp-1">
                    {act.title}
                  </h3>

                  <div className="flex items-center justify-between text-[11px] text-slate-400 mt-2 font-mono">
                    <span>Tool: {act.tool}</span>
                    <span className={act.riskLevel === 'HIGH_DISRUPTION' ? 'text-rose-400 font-bold' : 'text-slate-400'}>
                      {act.riskLevel.replace('_', ' ')}
                    </span>
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Right 2 Columns: Action Detail Inspector, Dry Run & Approval Gate */}
        <div className="lg:col-span-2 bg-slate-950 border border-slate-800 rounded-xl p-5 shadow-xl space-y-5">
          <div className="flex items-start justify-between gap-3 pb-3 border-b border-slate-800">
            <div>
              <div className="flex items-center gap-2">
                <span className="font-mono text-xs font-bold text-cyan-400">{activeAction.id}</span>
                <span className={`text-[10px] font-mono px-2 py-0.5 rounded font-bold ${
                  activeAction.riskLevel === 'HIGH_DISRUPTION' 
                    ? 'bg-rose-950 text-rose-300 border border-rose-800' 
                    : 'bg-amber-950 text-amber-300 border border-amber-800'
                }`}>
                  {activeAction.riskLevel.replace('_', ' ')} RISK
                </span>
              </div>
              <h2 className="text-base font-bold text-white mt-1">
                {activeAction.title}
              </h2>
            </div>

            <div className="text-right">
              <span className="text-[10px] text-slate-500 uppercase tracking-wider block">Target Entity</span>
              <span className="text-xs font-mono font-semibold text-cyan-300">{activeAction.target}</span>
            </div>
          </div>

          {/* Dry Run Simulation Box */}
          <div className="space-y-2">
            <span className="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center gap-2">
              <Terminal className="w-4 h-4 text-cyan-400" />
              <span>Dry-Run Impact Simulation:</span>
            </span>
            <div className="p-3 bg-slate-900 border border-slate-800 rounded-lg text-xs font-mono text-cyan-300 leading-relaxed">
              {activeAction.simulationOutput}
            </div>
          </div>

          {/* Safeguards Checklist */}
          <div className="space-y-2">
            <span className="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center gap-2">
              <UserCheck className="w-4 h-4 text-emerald-400" />
              <span>Required Defense Safeguards:</span>
            </span>
            <div className="space-y-1.5">
              {activeAction.safeguards.map((sg, idx) => (
                <div key={idx} className="flex items-center gap-2 text-xs text-slate-300 bg-slate-900/60 p-2 rounded border border-slate-800/80">
                  <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                  <span>{sg}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Rollback Command Display */}
          <div className="space-y-1.5">
            <span className="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center gap-2">
              <RotateCcw className="w-4 h-4 text-amber-400" />
              <span>Rollback Procedure (Disaster Recovery Plan):</span>
            </span>
            <div className="p-2.5 bg-slate-900 border border-slate-800 rounded font-mono text-xs text-amber-300">
              $ {activeAction.rollbackCommand}
            </div>
          </div>

          {/* Execution Logs if executed */}
          {activeAction.executionLogs && (
            <div className="space-y-1.5">
              <span className="text-xs font-bold uppercase tracking-wider text-emerald-400">
                Execution Logs:
              </span>
              <div className="p-2.5 bg-slate-900 border border-slate-800 rounded font-mono text-xs text-emerald-300 space-y-0.5">
                {activeAction.executionLogs.map((log, i) => (
                  <div key={i}>{log}</div>
                ))}
              </div>
            </div>
          )}

          {/* Approval Controls */}
          <div className="pt-3 border-t border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div className="text-xs space-y-1">
              <span className="text-slate-400">Required Role:</span>
              <span className="font-semibold text-slate-200 ml-1.5">{activeAction.approverRole}</span>
              {activeAction.approverName && (
                <div className="text-[11px] text-emerald-400 font-mono">
                  Signed by: {activeAction.approverName} ({new Date(activeAction.approvedAt || '').toLocaleTimeString()} UTC)
                </div>
              )}
            </div>

            <div className="flex items-center gap-2">
              {activeAction.status === 'PENDING_APPROVAL' && (
                <button
                  onClick={() => handleApprove(activeAction.id)}
                  className="px-4 py-2 bg-gradient-to-r from-emerald-600 to-teal-600 hover:from-emerald-500 hover:to-teal-500 text-white font-bold rounded-lg text-xs shadow-lg transition flex items-center gap-1.5 cursor-pointer"
                >
                  <UserCheck className="w-4 h-4" />
                  <span>Authorize & Execute Action</span>
                </button>
              )}

              {activeAction.status === 'EXECUTED' && (
                <button
                  onClick={() => handleRollback(activeAction.id)}
                  className="px-3.5 py-2 bg-slate-800 hover:bg-slate-700 text-amber-300 border border-amber-700/50 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition cursor-pointer"
                >
                  <RotateCcw className="w-4 h-4 text-amber-400" />
                  <span>Execute Rollback</span>
                </button>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* Immutable Action Audit Log */}
      <div className="bg-slate-950 border border-slate-800 rounded-xl p-5 shadow-lg space-y-3 font-mono text-xs">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2 text-slate-300 font-bold uppercase tracking-wider">
            <Clock className="w-4 h-4 text-cyan-400" />
            <span>Cryptographic Action Audit Log</span>
          </div>
          <span className="text-[11px] text-slate-500">Append-Only Immutable Ledger</span>
        </div>

        <div className="divide-y divide-slate-800/80">
          {auditLog.map((log, i) => (
            <div key={i} className="py-2.5 flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-[11px]">
              <div className="flex items-center gap-2">
                <span className="text-slate-500">{new Date(log.timestamp).toLocaleTimeString()} UTC</span>
                <span className="px-1.5 py-0.5 bg-slate-900 text-cyan-300 rounded font-semibold">{log.actionId}</span>
                <span className="text-slate-300">{log.event}</span>
              </div>
              <span className="text-slate-400 shrink-0">Operator: {log.user}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
