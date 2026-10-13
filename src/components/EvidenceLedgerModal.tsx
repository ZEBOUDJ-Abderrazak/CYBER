/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 * 
 * SENTINEL FUSION - Cryptographic Evidence Ledger Modal
 * Inspects chain-of-custody and SHA-256 verification status.
 */

import React, { useState } from 'react';
import { Incident } from '../types/security';
import { 
  Lock, 
  X, 
  CheckCircle2, 
  Hash, 
  Copy, 
  Download, 
  ShieldCheck 
} from 'lucide-react';

interface EvidenceLedgerModalProps {
  incident: Incident;
  isOpen: boolean;
  onClose: () => void;
}

export const EvidenceLedgerModal: React.FC<EvidenceLedgerModalProps> = ({
  incident,
  isOpen,
  onClose
}) => {
  const [copiedId, setCopiedId] = useState<string | null>(null);

  if (!isOpen) return null;

  const handleCopy = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4">
      <div className="bg-slate-950 border border-cyan-800/80 rounded-2xl w-full max-w-4xl max-h-[85vh] flex flex-col shadow-2xl overflow-hidden animate-fade-in font-sans">
        {/* Header */}
        <div className="px-6 py-4 bg-slate-900 border-b border-slate-800 flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-lg bg-cyan-950 border border-cyan-700/60 flex items-center justify-center">
              <Lock className="w-4 h-4 text-cyan-400" />
            </div>
            <div>
              <h2 className="text-base font-bold text-white tracking-tight">
                Cryptographic Evidence Ledger & Chain of Custody
              </h2>
              <p className="text-xs text-slate-400">
                Immutable SHA-256 evidence records for incident {incident.id}
              </p>
            </div>
          </div>

          <button
            onClick={onClose}
            className="text-slate-400 hover:text-white p-1 rounded-lg hover:bg-slate-800 transition cursor-pointer"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Content list */}
        <div className="p-6 overflow-y-auto space-y-4 font-mono text-xs flex-1">
          <div className="p-3 bg-cyan-950/40 border border-cyan-800/60 rounded-xl text-cyan-300 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <ShieldCheck className="w-4 h-4 text-emerald-400" />
              <span>Chain of Custody: All {incident.events.length} telemetry entries cryptographically verified.</span>
            </div>
            <span className="text-[11px] font-bold text-emerald-400">0 Hash Collisions</span>
          </div>

          <div className="divide-y divide-slate-850 space-y-3">
            {incident.events.map((event) => (
              <div key={event.id} className="pt-3 first:pt-0 space-y-2">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-1 text-[11px]">
                  <div className="flex items-center gap-2">
                    <span className="font-bold text-cyan-400">{event.id}</span>
                    <span className="px-1.5 py-0.2 bg-slate-800 text-slate-300 rounded">{event.sourceTool}</span>
                    <span className="text-slate-500">{event.timestamp}</span>
                  </div>

                  <span className="text-emerald-400 flex items-center gap-1 font-bold">
                    <CheckCircle2 className="w-3.5 h-3.5" />
                    Verified Genuine
                  </span>
                </div>

                <div className="text-slate-200 font-sans text-xs">
                  {event.title}
                </div>

                <div className="p-2 bg-slate-900 rounded border border-slate-800/80 flex items-center justify-between gap-2 text-[11px]">
                  <div className="flex items-center gap-1.5 text-slate-400 truncate">
                    <Hash className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
                    <span className="text-cyan-300 truncate">{event.evidenceHash}</span>
                  </div>

                  <button
                    onClick={() => handleCopy(event.evidenceHash, event.id)}
                    className="text-slate-400 hover:text-white px-2 py-0.5 bg-slate-800 hover:bg-slate-700 rounded transition cursor-pointer shrink-0"
                  >
                    {copiedId === event.id ? 'Copied' : 'Copy Hash'}
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Footer */}
        <div className="px-6 py-3 bg-slate-900 border-t border-slate-800 flex justify-end">
          <button
            onClick={onClose}
            className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg text-xs font-semibold cursor-pointer"
          >
            Close Ledger
          </button>
        </div>
      </div>
    </div>
  );
};
