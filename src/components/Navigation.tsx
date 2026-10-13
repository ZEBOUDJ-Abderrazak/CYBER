/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 * 
 * SENTINEL FUSION - Primary SOC Navigation Bar
 */

import React from 'react';
import { 
  Compass, 
  GitBranch, 
  FileSearch, 
  Sparkles, 
  ShieldCheck, 
  Eye, 
  Zap, 
  UploadCloud,
  Binary,
  PhoneCall,
  Globe
} from 'lucide-react';

export type TabId = 
  | 'workbench' 
  | 'topology' 
  | 'packets' 
  | 'carver'
  | 'voip'
  | 'threat-map'
  | 'ai' 
  | 'mitre' 
  | 'visibility' 
  | 'response' 
  | 'ingestion';

interface NavigationProps {
  activeTab: TabId;
  onTabChange: (tab: TabId) => void;
  pendingApprovalsCount: number;
  isDarkMode?: boolean;
}

export const Navigation: React.FC<NavigationProps> = ({
  activeTab,
  onTabChange,
  pendingApprovalsCount,
  isDarkMode = false
}) => {
  const tabs = [
    { id: 'workbench', label: 'Investigation Workbench', icon: Compass },
    { id: 'carver', label: 'Wireshark Object Carving', icon: Binary, badge: 'Files & Images' },
    { id: 'voip', label: 'VoIP & Voice RTP', icon: PhoneCall, badge: 'Audio Player' },
    { id: 'threat-map', label: 'Global Threat Radar', icon: Globe, badge: 'Fortinet / Sophos' },
    { id: 'topology', label: 'Attack Path Graph', icon: GitBranch },
    { id: 'packets', label: 'Packet Inspector', icon: FileSearch },
    { id: 'ai', label: 'AI Investigator', icon: Sparkles },
    { id: 'mitre', label: 'MITRE ATT&CK', icon: ShieldCheck },
    { id: 'visibility', label: 'Visibility Auditor', icon: Eye },
    { 
      id: 'response', 
      label: 'Controlled Response', 
      icon: Zap, 
      counter: pendingApprovalsCount > 0 ? pendingApprovalsCount : undefined 
    },
    { id: 'ingestion', label: 'Ingestion Lab', icon: UploadCloud }
  ];

  return (
    <nav className={`px-4 sm:px-6 flex items-center gap-1.5 overflow-x-auto no-scrollbar py-2 border-b transition-colors ${
      isDarkMode 
        ? 'bg-slate-950 border-slate-800' 
        : 'bg-white border-slate-200 shadow-2xs'
    }`}>
      {tabs.map((tab) => {
        const Icon = tab.icon;
        const isActive = activeTab === tab.id;

        return (
          <button
            key={tab.id}
            onClick={() => onTabChange(tab.id as TabId)}
            className={`flex items-center gap-2 px-3 py-2 text-xs font-medium rounded-xl whitespace-nowrap transition-all cursor-pointer ${
              isActive
                ? isDarkMode
                  ? 'bg-cyan-950/80 text-cyan-300 border border-cyan-800/80 shadow-xs font-semibold'
                  : 'bg-indigo-50 text-indigo-700 border border-indigo-200 shadow-2xs font-bold'
                : isDarkMode
                ? 'text-slate-400 hover:text-slate-200 hover:bg-slate-900 border border-transparent'
                : 'text-slate-600 hover:text-slate-900 hover:bg-slate-50 border border-transparent'
            }`}
          >
            <Icon className={`w-3.5 h-3.5 ${
              isActive 
                ? isDarkMode ? 'text-cyan-400' : 'text-indigo-600' 
                : 'text-slate-400'
            }`} />
            <span>{tab.label}</span>

            {tab.counter !== undefined && (
              <span className="px-1.5 py-0.2 text-[10px] font-bold rounded-full bg-rose-600 text-white animate-pulse">
                {tab.counter}
              </span>
            )}

            {tab.badge && (
              <span className={`text-[9px] uppercase tracking-wider px-1.5 py-0.2 rounded font-mono hidden md:inline border ${
                isActive
                  ? 'bg-indigo-100/70 border-indigo-300 text-indigo-800 font-bold'
                  : 'bg-slate-100 border-slate-200 text-slate-500'
              }`}>
                {tab.badge}
              </span>
            )}
          </button>
        );
      })}
    </nav>
  );
};
