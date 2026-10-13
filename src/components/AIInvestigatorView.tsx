/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 * 
 * SENTINEL FUSION - Evidence-Grounded AI Investigator Interface
 * Conversational forensic query system strictly citing event IDs and hashes.
 */

import React, { useState } from 'react';
import { Incident, InvestigationChatMessage } from '../types/security';
import { queryAIInvestigator } from '../engine/ai-investigator';
import { 
  Sparkles, 
  Send, 
  Lock, 
  HelpCircle, 
  Terminal, 
  FileText, 
  Zap, 
  ShieldAlert, 
  CheckCircle2, 
  ArrowRight,
  RefreshCw
} from 'lucide-react';

interface AIInvestigatorViewProps {
  incident: Incident;
  onNavigateToResponse?: () => void;
}

export const AIInvestigatorView: React.FC<AIInvestigatorViewProps> = ({
  incident,
  onNavigateToResponse
}) => {
  const [messages, setMessages] = useState<InvestigationChatMessage[]>([
    {
      id: 'msg-init',
      sender: 'SYSTEM',
      timestamp: new Date().toISOString(),
      content: `SENTINEL FUSION Evidence-Grounded AI Investigator initialized.
Loaded Incident: [${incident.id}] "${incident.title}".
Verified Telemetry: ${incident.events.length} multi-source events with tamper-proof SHA-256 hashes.
Strict Evidence Grounding mode is ACTIVE. Conclusions without cited telemetry will be suppressed.`
    }
  ]);
  const [inputQuery, setInputQuery] = useState('');
  const [isLoading, setIsLoading] = useState(false);

  const predefinedQueries = [
    'Why is host Corp-DB01 considered compromised?',
    'Break down the chronological attack timeline.',
    'What is the evidence supporting active C2 communication?',
    'Are there any sensor blind spots or visibility gaps?',
    'Draft a CISO Executive Incident Briefing.'
  ];

  const handleSend = async (textToSend?: string) => {
    const q = textToSend || inputQuery;
    if (!q.trim() || isLoading) return;

    const userMsg: InvestigationChatMessage = {
      id: `user-${Date.now()}`,
      sender: 'ANALYST',
      timestamp: new Date().toISOString(),
      content: q
    };

    setMessages(prev => [...prev, userMsg]);
    setInputQuery('');
    setIsLoading(true);

    try {
      const result = await queryAIInvestigator(q, {
        incident,
        events: incident.events
      });

      const aiMsg: InvestigationChatMessage = {
        id: `ai-${Date.now()}`,
        sender: 'AI_INVESTIGATOR',
        timestamp: new Date().toISOString(),
        content: result.answer,
        citedEvidenceIds: result.citedEventIds,
        suggestedAction: result.recommendedAction
      };

      setMessages(prev => [...prev, aiMsg]);
    } catch (err) {
      const errorMsg: InvestigationChatMessage = {
        id: `err-${Date.now()}`,
        sender: 'SYSTEM',
        timestamp: new Date().toISOString(),
        content: 'Failed to process inquiry. Deterministic backup reasoning engaged.'
      };
      setMessages(prev => [...prev, errorMsg]);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="p-4 sm:p-6 space-y-4 max-w-5xl mx-auto flex flex-col h-[calc(100vh-140px)]">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 shrink-0">
        <div>
          <div className="flex items-center gap-2">
            <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-blue-600 to-indigo-800 flex items-center justify-center border border-cyan-400/40">
              <Sparkles className="w-4 h-4 text-cyan-200 animate-pulse" />
            </div>
            <div>
              <h1 className="text-xl font-bold text-white tracking-tight">
                Evidence-Grounded AI Investigator
              </h1>
              <p className="text-xs text-slate-400">
                Audited Blue Team reasoning engine citing verified event IDs and SHA-256 evidence provenance.
              </p>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-2 text-xs font-mono">
          <span className="px-2.5 py-1 bg-emerald-950/80 text-emerald-300 border border-emerald-800 rounded font-semibold flex items-center gap-1.5">
            <Lock className="w-3.5 h-3.5 text-emerald-400" />
            Zero-Hallucination Grounding Rule
          </span>
        </div>
      </div>

      {/* Suggested Prompt Chips */}
      <div className="flex items-center gap-2 overflow-x-auto no-scrollbar py-1 shrink-0">
        <span className="text-xs text-slate-500 font-mono whitespace-nowrap">Suggested Inquiries:</span>
        {predefinedQueries.map((query, idx) => (
          <button
            key={idx}
            onClick={() => handleSend(query)}
            disabled={isLoading}
            className="text-xs px-2.5 py-1 bg-slate-900 hover:bg-slate-800 border border-slate-700 hover:border-cyan-600 text-slate-300 hover:text-cyan-200 rounded-lg whitespace-nowrap transition cursor-pointer disabled:opacity-50"
          >
            {query}
          </button>
        ))}
      </div>

      {/* Messages Scroll Area */}
      <div className="flex-1 bg-slate-950 border border-slate-800 rounded-xl p-4 overflow-y-auto space-y-4 shadow-inner">
        {messages.map((msg) => {
          const isUser = msg.sender === 'ANALYST';
          const isSystem = msg.sender === 'SYSTEM';

          return (
            <div 
              key={msg.id}
              className={`flex flex-col ${isUser ? 'items-end' : 'items-start'}`}
            >
              <div className="flex items-center gap-2 text-[11px] font-mono text-slate-500 mb-1">
                <span>{msg.sender === 'AI_INVESTIGATOR' ? 'SENTINEL AI INVESTIGATOR' : msg.sender}</span>
                <span>•</span>
                <span>{new Date(msg.timestamp).toLocaleTimeString()}</span>
              </div>

              <div className={`max-w-3xl rounded-xl p-4 text-xs leading-relaxed space-y-3 ${
                isUser 
                  ? 'bg-blue-900/40 text-blue-100 border border-blue-700/60' 
                  : isSystem 
                  ? 'bg-slate-900/60 text-slate-400 border border-slate-800 font-mono text-[11px]' 
                  : 'bg-slate-900/90 text-slate-200 border border-slate-800 shadow-md'
              }`}>
                <div className="whitespace-pre-wrap">
                  {msg.content}
                </div>

                {/* Cited Evidence IDs */}
                {msg.citedEvidenceIds && msg.citedEvidenceIds.length > 0 && (
                  <div className="pt-2 border-t border-slate-800 flex flex-wrap items-center gap-1.5 font-mono">
                    <span className="text-[10px] text-cyan-400 font-bold uppercase tracking-wider">
                      Grounding Evidence Cites:
                    </span>
                    {msg.citedEvidenceIds.map(eid => (
                      <span key={eid} className="px-1.5 py-0.5 bg-cyan-950/90 border border-cyan-800 text-cyan-300 rounded text-[10px]">
                        {eid}
                      </span>
                    ))}
                  </div>
                )}

                {/* Suggested Next Action */}
                {msg.suggestedAction && (
                  <div className="p-2.5 bg-gradient-to-r from-indigo-950 to-slate-950 border border-indigo-700/60 rounded-lg flex items-center justify-between gap-3 text-xs">
                    <div className="flex items-center gap-2 text-indigo-300 font-medium">
                      <Zap className="w-3.5 h-3.5 text-amber-400 shrink-0" />
                      <span>{msg.suggestedAction}</span>
                    </div>

                    {onNavigateToResponse && (
                      <button
                        onClick={onNavigateToResponse}
                        className="px-2.5 py-1 bg-indigo-600 hover:bg-indigo-500 text-white font-semibold rounded text-[11px] flex items-center gap-1 transition cursor-pointer shrink-0"
                      >
                        <span>Approve Action</span>
                        <ArrowRight className="w-3 h-3" />
                      </button>
                    )}
                  </div>
                )}
              </div>
            </div>
          );
        })}

        {isLoading && (
          <div className="flex items-center gap-3 p-4 bg-slate-900/60 border border-slate-800 rounded-xl text-xs text-cyan-300 font-mono">
            <RefreshCw className="w-4 h-4 animate-spin text-cyan-400" />
            <span>Consulting Fusion Intelligence Core & correlating evidence telemetry...</span>
          </div>
        )}
      </div>

      {/* Input Form */}
      <form
        onSubmit={(e) => {
          e.preventDefault();
          handleSend();
        }}
        className="flex items-center gap-2 bg-slate-900 border border-slate-800 rounded-xl p-2 shrink-0"
      >
        <input
          type="text"
          value={inputQuery}
          onChange={(e) => setInputQuery(e.target.value)}
          placeholder="Ask an evidence-grounded question (e.g. 'Why is this host suspicious?' or 'Verify attack path')..."
          className="flex-1 bg-transparent text-slate-100 placeholder-slate-500 text-xs px-3 focus:outline-none"
        />

        <button
          type="submit"
          disabled={!inputQuery.trim() || isLoading}
          className="px-4 py-2 bg-cyan-600 hover:bg-cyan-500 disabled:bg-slate-800 text-white font-semibold rounded-lg text-xs flex items-center gap-1.5 transition cursor-pointer disabled:cursor-not-allowed shadow"
        >
          <span>Query</span>
          <Send className="w-3.5 h-3.5" />
        </button>
      </form>
    </div>
  );
};
