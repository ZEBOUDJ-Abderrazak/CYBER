/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 * 
 * SENTINEL FUSION - Main Application Entrypoint
 * Unified Cyber Defense, Network Intelligence & Autonomous Investigation Platform
 */

import React, { useState } from 'react';
import { Header } from './components/Header';
import { Navigation, TabId } from './components/Navigation';
import { IncidentWorkbench } from './components/IncidentWorkbench';
import { AttackGraph } from './components/AttackGraph';
import { PacketInspector } from './components/PacketInspector';
import { PcapFileCarver } from './components/PcapFileCarver';
import { VoipCallAnalyzer } from './components/VoipCallAnalyzer';
import { FortinetSophosBenchmark } from './components/FortinetSophosBenchmark';
import { GlobalThreatMap } from './components/GlobalThreatMap';
import { AIInvestigatorView } from './components/AIInvestigatorView';
import { MitreCoverage } from './components/MitreCoverage';
import { VisibilityAuditor } from './components/VisibilityAuditor';
import { ResponsePlaybooks } from './components/ResponsePlaybooks';
import { IngestionLab } from './components/IngestionLab';
import { EvidenceLedgerModal } from './components/EvidenceLedgerModal';
import { ExportReportModal } from './components/ExportReportModal';
import { VulnerabilityCenter } from './components/VulnerabilityCenter';
import { ArchitectureModal } from './components/ArchitectureModal';
import { getScenarioData, MOCK_INCIDENT_S1, MOCK_ASSETS } from './engine/sample-data';
import { Incident, NormalizedEvent, UnifiedAsset } from './types/security';
import { correlateEvents } from './engine/correlation';

export default function App() {
  const [currentScenario, setCurrentScenario] = useState<string>('scenario_1');
  const [activeIncident, setActiveIncident] = useState<Incident>(MOCK_INCIDENT_S1);
  const [activeTab, setActiveTab] = useState<TabId>('workbench');
  const [isDarkMode, setIsDarkMode] = useState<boolean>(false); // Defaults to white background UI as requested

  const [isReportModalOpen, setIsReportModalOpen] = useState(false);
  const [isEvidenceLedgerModalOpen, setIsEvidenceLedgerModalOpen] = useState(false);
  const [isReadmeModalOpen, setIsReadmeModalOpen] = useState(false);
  const [toastMessage, setToastMessage] = useState<string | null>(null);

  const showToast = (msg: string) => {
    setToastMessage(msg);
    setTimeout(() => setToastMessage(null), 3500);
  };

  const handleSelectScenario = (scenarioId: string) => {
    setCurrentScenario(scenarioId);
    const incidentData = getScenarioData(scenarioId);
    setActiveIncident(incidentData);
    showToast(`Loaded ${incidentData.title.slice(0, 48)}...`);
  };

  const handleIngestSuccess = (newEvents: NormalizedEvent[], newAssets: UnifiedAsset[]) => {
    const combinedAssets = [...MOCK_ASSETS, ...newAssets];
    const correlated = correlateEvents(newEvents, combinedAssets);

    if (correlated.length > 0) {
      setActiveIncident(correlated[0]);
      setCurrentScenario('custom');
      setActiveTab('workbench');
      showToast(`Correlated ${newEvents.length} events into Incident [${correlated[0].id}]!`);
    } else {
      showToast(`Parsed ${newEvents.length} events successfully.`);
    }
  };

  return (
    <div className={`min-h-screen flex flex-col font-sans transition-colors ${
      isDarkMode 
        ? 'bg-slate-950 text-slate-100 selection:bg-cyan-500 selection:text-slate-950' 
        : 'bg-slate-50 text-slate-900 selection:bg-indigo-600 selection:text-white'
    }`}>
      {/* Executive Command Header */}
      <Header
        currentScenario={currentScenario}
        onSelectScenario={handleSelectScenario}
        activeIncident={activeIncident}
        onOpenReport={() => setIsReportModalOpen(true)}
        onOpenEvidenceLedger={() => setIsEvidenceLedgerModalOpen(true)}
        onOpenAIQuery={() => setActiveTab('ai')}
        onOpenReadme={() => setIsReadmeModalOpen(true)}
        isDarkMode={isDarkMode}
        onToggleDarkMode={() => setIsDarkMode(prev => !prev)}
      />

      {/* Primary SOC Navigation Bar */}
      <Navigation
        activeTab={activeTab}
        onTabChange={(tab) => setActiveTab(tab)}
        pendingApprovalsCount={2}
        isDarkMode={isDarkMode}
      />

      {/* Toast Notification Banner */}
      {toastMessage && (
        <div className={`text-xs py-2 px-4 flex items-center justify-between font-mono animate-fade-in shadow-sm border-b ${
          isDarkMode 
            ? 'bg-gradient-to-r from-cyan-950 via-blue-950 to-slate-950 border-cyan-800 text-cyan-200' 
            : 'bg-indigo-50 border-indigo-200 text-indigo-900'
        }`}>
          <span>[SENTINEL CORE] {toastMessage}</span>
          <button 
            onClick={() => setToastMessage(null)}
            className="text-slate-500 hover:text-slate-900 text-xs cursor-pointer"
          >
            ✕
          </button>
        </div>
      )}

      {/* Main Investigation Workspace */}
      <main className="flex-1 overflow-y-auto">
        {activeTab === 'workbench' && (
          <IncidentWorkbench
            incident={activeIncident}
            onNavigateToTab={(tab) => setActiveTab(tab as TabId)}
            isDarkMode={isDarkMode}
          />
        )}

        {activeTab === 'vulnerabilities' && (
          <VulnerabilityCenter onNavigateToWorkbench={() => setActiveTab('workbench')} />
        )}

        {activeTab === 'carver' && (
          <PcapFileCarver />
        )}

        {activeTab === 'voip' && (
          <VoipCallAnalyzer />
        )}

        {activeTab === 'fortinet-sophos' && (
          <FortinetSophosBenchmark incident={activeIncident} />
        )}

        {activeTab === 'threat-map' && (
          <GlobalThreatMap />
        )}

        {activeTab === 'topology' && (
          <AttackGraph incident={activeIncident} />
        )}

        {activeTab === 'packets' && (
          <PacketInspector />
        )}

        {activeTab === 'ai' && (
          <AIInvestigatorView 
            incident={activeIncident}
            onNavigateToResponse={() => setActiveTab('response')}
          />
        )}

        {activeTab === 'mitre' && (
          <MitreCoverage
            incident={activeIncident}
            onSelectEventId={(eid) => {
              setActiveTab('workbench');
              showToast(`Highlighting evidence event ${eid}`);
            }}
          />
        )}

        {activeTab === 'visibility' && (
          <VisibilityAuditor />
        )}

        {activeTab === 'response' && (
          <ResponsePlaybooks />
        )}

        {activeTab === 'ingestion' && (
          <IngestionLab onIngestSuccess={handleIngestSuccess} />
        )}
      </main>

      {/* Modals */}
      <EvidenceLedgerModal
        incident={activeIncident}
        isOpen={isEvidenceLedgerModalOpen}
        onClose={() => setIsEvidenceLedgerModalOpen(false)}
      />

      <ExportReportModal
        incident={activeIncident}
        isOpen={isReportModalOpen}
        onClose={() => setIsReportModalOpen(false)}
      />

      <ArchitectureModal
        isOpen={isReadmeModalOpen}
        onClose={() => setIsReadmeModalOpen(false)}
      />
    </div>
  );
}
