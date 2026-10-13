/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 * 
 * SENTINEL FUSION - Forensic Incident Report Generator
 * Exports comprehensive CISO / DFIR briefing in Markdown and JSON formats.
 */

import React, { useState } from 'react';
import { Incident } from '../types/security';
import { 
  FileText, 
  X, 
  Download, 
  Copy, 
  CheckCircle2, 
  ShieldAlert 
} from 'lucide-react';

interface ExportReportModalProps {
  incident: Incident;
  isOpen: boolean;
  onClose: () => void;
}

export const ExportReportModal: React.FC<ExportReportModalProps> = ({
  incident,
  isOpen,
  onClose
}) => {
  const [reportFormat, setReportFormat] = useState<'markdown' | 'json'>('markdown');
  const [copied, setCopied] = useState(false);

  if (!isOpen) return null;

  const generateMarkdownReport = (): string => {
    return `# SENTINEL FUSION — FORENSIC INCIDENT INVESTIGATION REPORT
**Incident ID:** ${incident.id}  
**Classification:** ${incident.severity} | **Correlation Confidence:** ${incident.confidenceScore}%  
**Generated At:** ${new Date().toISOString()}  
**Target Asset:** ${incident.affectedAssets.map(a => `${a.hostname} (${a.ip})`).join(', ')}  
**Attacker IP(s):** ${incident.attackerIps.join(', ')}  
**Primary Vector:** ${incident.primaryAttackVector}  

---

## 1. EXECUTIVE SUMMARY
${incident.summary}

### Explainable Confidence Breakdown
- **Network Discovery Corroboration (Nmap):** +${incident.confidenceBreakdown.networkDiscoveryCorroboration}%
- **NIDS Exploit Payload Detection (Suricata):** +${incident.confidenceBreakdown.idsPayloadDetection}%
- **Packet Forensics Verification (TShark):** +${incident.confidenceBreakdown.packetForensicsVerification}%
- **Endpoint Execution Confirmation (Wazuh):** +${incident.confidenceBreakdown.endpointExecutionConfirmation}%
- **Threat Intelligence Reputation (MISP):** +${incident.confidenceBreakdown.threatIntelReputationMatch}%

---

## 2. CHRONOLOGICAL EVIDENCE TIMELINE & PROVENANCE LEDGER
${incident.events.map((e, idx) => `
### [${idx + 1}] ${e.id} — ${e.sourceTool} (${e.severity})
- **Timestamp:** ${e.timestamp}
- **Summary:** ${e.title}
- **Description:** ${e.description}
- **MITRE Techniques:** ${e.mitreTechniques.join(', ')}
- **SHA-256 Provenance Hash:** \`${e.evidenceHash}\`
- **Raw Telemetry Snippet:**
\`\`\`
${e.rawEvent.slice(0, 300)}
\`\`\`
`).join('\n')}

---

## 3. ADVERSARIAL HYPOTHESES EVALUATION
${incident.hypotheses.map(h => `
### ${h.title}
- **Likelihood:** ${h.likelihood} (${h.confidencePercentage}%)
- **Rationale:** ${h.rationale}
- **Supporting Evidence:** ${h.supportingEvidenceIds.join(', ')}
- **Refuting Evidence:** ${h.refutingEvidenceIds.length ? h.refutingEvidenceIds.join(', ') : 'None'}
`).join('\n')}

---

## 4. MITRE ATT&CK MAPPING
${incident.mitreMatrix.map(m => `- **${m.id} (${m.name})** — Tactic: ${m.tactic} | Corroborating Events: ${m.eventIds.join(', ')}`).join('\n')}

---

## 5. RECOMMENDED DEFENSIVE RESPONSE ACTIONS
${incident.recommendations.map(r => `
- **[${r.priority}] ${r.title}**
  - Reason: ${r.reason}
  - Required Tool: ${r.requiredTool}
  - Suggested Command: \`${r.suggestedCommand || 'N/A'}\`
`).join('\n')}

---
*Report certified by SENTINEL FUSION Intelligence Core v2.4*
`;
  };

  const reportText = reportFormat === 'markdown' 
    ? generateMarkdownReport() 
    : JSON.stringify(incident, null, 2);

  const handleCopy = () => {
    navigator.clipboard.writeText(reportText);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownload = () => {
    const blob = new Blob([reportText], { type: reportFormat === 'markdown' ? 'text/markdown' : 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${incident.id}_Forensic_Report.${reportFormat === 'markdown' ? 'md' : 'json'}`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4">
      <div className="bg-slate-950 border border-slate-800 rounded-2xl w-full max-w-4xl max-h-[85vh] flex flex-col shadow-2xl overflow-hidden font-sans">
        {/* Header */}
        <div className="px-6 py-4 bg-slate-900 border-b border-slate-800 flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-lg bg-blue-950 border border-blue-700/60 flex items-center justify-center">
              <FileText className="w-4 h-4 text-blue-400" />
            </div>
            <div>
              <h2 className="text-base font-bold text-white tracking-tight">
                Forensic Incident Investigation Report
              </h2>
              <p className="text-xs text-slate-400">
                Audit-ready briefing for CISO, SOC Lead, and regulatory bodies
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <div className="flex items-center bg-slate-800 rounded-lg p-0.5 text-xs font-mono">
              <button
                onClick={() => setReportFormat('markdown')}
                className={`px-2.5 py-1 rounded transition cursor-pointer ${
                  reportFormat === 'markdown' ? 'bg-cyan-900 text-cyan-200 font-bold' : 'text-slate-400'
                }`}
              >
                Markdown
              </button>
              <button
                onClick={() => setReportFormat('json')}
                className={`px-2.5 py-1 rounded transition cursor-pointer ${
                  reportFormat === 'json' ? 'bg-cyan-900 text-cyan-200 font-bold' : 'text-slate-400'
                }`}
              >
                Raw JSON
              </button>
            </div>

            <button
              onClick={onClose}
              className="text-slate-400 hover:text-white p-1 rounded-lg hover:bg-slate-800 transition cursor-pointer"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>

        {/* Report Preview */}
        <div className="p-6 overflow-y-auto flex-1 font-mono text-xs bg-slate-950 text-slate-300">
          <pre className="whitespace-pre-wrap leading-relaxed select-text font-mono">
            {reportText}
          </pre>
        </div>

        {/* Footer */}
        <div className="px-6 py-3.5 bg-slate-900 border-t border-slate-800 flex items-center justify-between">
          <span className="text-xs text-slate-400 font-mono">
            {reportFormat.toUpperCase()} • Ready for export
          </span>

          <div className="flex items-center gap-2">
            <button
              onClick={handleCopy}
              className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition cursor-pointer"
            >
              <Copy className="w-3.5 h-3.5 text-cyan-400" />
              <span>{copied ? 'Copied!' : 'Copy to Clipboard'}</span>
            </button>

            <button
              onClick={handleDownload}
              className="px-4 py-1.5 bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg text-xs font-semibold flex items-center gap-1.5 transition cursor-pointer shadow"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Download File</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
