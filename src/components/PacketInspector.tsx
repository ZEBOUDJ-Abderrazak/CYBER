/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 * 
 * SENTINEL FUSION - Deep Packet Inspector (Wireshark / TShark Forensics)
 * 3-pane packet analysis: Frame Table, Protocol Tree Dissector, Hex & ASCII payload dump.
 */

import React, { useState } from 'react';
import { PacketFrame } from '../types/security';
import { MOCK_PCAP_FRAMES_S1 } from '../engine/sample-data';
import { 
  FileSearch, 
  Terminal, 
  Search, 
  Layers, 
  Download, 
  Filter, 
  ChevronRight, 
  ChevronDown, 
  ShieldAlert, 
  Copy, 
  Activity 
} from 'lucide-react';

interface PacketInspectorProps {
  initialFrames?: PacketFrame[];
}

export const PacketInspector: React.FC<PacketInspectorProps> = ({ 
  initialFrames = MOCK_PCAP_FRAMES_S1 
}) => {
  const [frames] = useState<PacketFrame[]>(initialFrames);
  const [selectedFrameNumber, setSelectedFrameNumber] = useState<number>(1425);
  const [filterQuery, setFilterQuery] = useState<string>('ip.addr == 194.26.29.112');
  const [copiedPayload, setCopiedPayload] = useState<boolean>(false);

  const selectedFrame = frames.find(f => f.frameNumber === selectedFrameNumber) || frames[0];

  const filteredFrames = frames.filter(f => {
    if (!filterQuery.trim()) return true;
    const q = filterQuery.toLowerCase();
    return (
      f.srcIp.includes(q) ||
      f.destIp.includes(q) ||
      f.protocol.toLowerCase().includes(q) ||
      f.info.toLowerCase().includes(q) ||
      f.asciiPayload.toLowerCase().includes(q)
    );
  });

  const handleCopyAscii = () => {
    if (selectedFrame) {
      navigator.clipboard.writeText(selectedFrame.asciiPayload);
      setCopiedPayload(true);
      setTimeout(() => setCopiedPayload(false), 2000);
    }
  };

  return (
    <div className="p-4 sm:p-6 space-y-4 max-w-7xl mx-auto font-sans">
      {/* Title & Display Filter Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <div className="flex items-center gap-2">
            <FileSearch className="w-5 h-5 text-sky-400" />
            <h1 className="text-xl font-bold text-white tracking-tight">
              Deep Packet Forensics & Stream Inspector
            </h1>
          </div>
          <p className="text-xs text-slate-400 mt-0.5">
            TShark / Wireshark frame dissection with synchronized hex dump and threat offset highlighting.
          </p>
        </div>

        <div className="flex items-center gap-2 text-xs font-mono">
          <span className="px-2.5 py-1 bg-sky-950/80 text-sky-300 border border-sky-800 rounded font-semibold">
            PCAP Ring-Buffer: ACTIVE (4 Frames Captured)
          </span>
        </div>
      </div>

      {/* Wireshark Display Filter Input */}
      <div className="flex items-center gap-2 bg-slate-900 border border-slate-800 rounded-lg px-3 py-2 text-xs font-mono">
        <Filter className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
        <span className="text-slate-500 text-[11px] uppercase">Filter:</span>
        <input
          type="text"
          value={filterQuery}
          onChange={(e) => setFilterQuery(e.target.value)}
          placeholder="Apply display filter (e.g. ip.addr == 194.26.29.112 or tcp.port == 8443)..."
          className="bg-transparent text-cyan-300 placeholder-slate-600 focus:outline-none flex-1 text-xs"
        />
        {filterQuery && (
          <button 
            onClick={() => setFilterQuery('')}
            className="text-slate-500 hover:text-slate-300 text-xs px-1 cursor-pointer"
          >
            Clear
          </button>
        )}
      </div>

      {/* Pane 1: Packet Frame Table */}
      <div className="bg-slate-950 border border-slate-800 rounded-xl overflow-hidden shadow-lg">
        <div className="bg-slate-900/90 px-4 py-2 border-b border-slate-800 flex items-center justify-between text-xs font-semibold text-slate-300">
          <span>Packet Frame List ({filteredFrames.length} Frames)</span>
          <span className="text-[11px] text-slate-500 font-mono">Click any frame to inspect protocol tree & payload</span>
        </div>

        <div className="overflow-x-auto max-h-56 overflow-y-auto">
          <table className="w-full text-left font-mono text-xs">
            <thead className="bg-slate-900/60 text-slate-400 text-[11px] sticky top-0 border-b border-slate-800">
              <tr>
                <th className="py-2 px-3">No.</th>
                <th className="py-2 px-3">Time (UTC)</th>
                <th className="py-2 px-3">Source</th>
                <th className="py-2 px-3">Destination</th>
                <th className="py-2 px-3">Protocol</th>
                <th className="py-2 px-3">Len</th>
                <th className="py-2 px-4">Info</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-900 text-slate-300">
              {filteredFrames.map(frame => {
                const isSelected = frame.frameNumber === selectedFrameNumber;
                const hasThreat = frame.suspiciousOffsets && frame.suspiciousOffsets.length > 0;

                return (
                  <tr
                    key={frame.frameNumber}
                    onClick={() => setSelectedFrameNumber(frame.frameNumber)}
                    className={`cursor-pointer transition hover:bg-slate-900/70 ${
                      isSelected ? 'bg-cyan-950/70 text-cyan-200 font-semibold' : ''
                    } ${hasThreat ? 'bg-rose-950/20' : ''}`}
                  >
                    <td className="py-2 px-3 text-cyan-400 font-bold">{frame.frameNumber}</td>
                    <td className="py-2 px-3 text-slate-400">{frame.timestamp.split('T')[1].replace('Z', '')}</td>
                    <td className="py-2 px-3">{frame.srcIp}:{frame.srcPort}</td>
                    <td className="py-2 px-3">{frame.destIp}:{frame.destPort}</td>
                    <td className="py-2 px-3">
                      <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                        frame.protocol === 'HTTP' ? 'bg-indigo-950 text-indigo-300 border border-indigo-800' :
                        frame.protocol === 'LDAP' ? 'bg-purple-950 text-purple-300 border border-purple-800' :
                        'bg-slate-800 text-slate-300'
                      }`}>
                        {frame.protocol}
                      </span>
                    </td>
                    <td className="py-2 px-3 text-slate-400">{frame.length}</td>
                    <td className="py-2 px-4 flex items-center justify-between gap-2">
                      <span className="truncate max-w-lg">{frame.info}</span>
                      {hasThreat && (
                        <span className="px-1.5 py-0.2 bg-rose-900/80 text-rose-300 text-[10px] rounded font-sans shrink-0 font-bold">
                          THREAT PAYLOAD
                        </span>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

      {/* Pane 2 & 3 Split: Protocol Tree Dissector & Hex/ASCII Dump */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Pane 2: Protocol Tree Dissector */}
        <div className="bg-slate-950 border border-slate-800 rounded-xl p-4 shadow-lg space-y-3 font-mono text-xs">
          <div className="flex items-center justify-between pb-2 border-b border-slate-800">
            <div className="flex items-center gap-2">
              <Layers className="w-4 h-4 text-cyan-400" />
              <span className="text-sm font-bold text-slate-200">
                Frame #{selectedFrame?.frameNumber} Dissection Tree
              </span>
            </div>
            <span className="text-[11px] text-slate-500">{selectedFrame?.length} bytes on wire</span>
          </div>

          <div className="space-y-2 text-slate-300 text-xs">
            <details open className="group">
              <summary className="cursor-pointer select-none py-1 px-2 rounded hover:bg-slate-900 flex items-center gap-2 text-slate-200 font-semibold">
                <ChevronRight className="w-3.5 h-3.5 text-cyan-400 group-open:rotate-90 transition-transform" />
                <span>Frame {selectedFrame?.frameNumber}: {selectedFrame?.length} bytes on wire ({selectedFrame?.length * 8} bits)</span>
              </summary>
              <div className="pl-6 pt-1 text-[11px] text-slate-400 space-y-0.5">
                <div>Arrival Time: {selectedFrame?.timestamp}</div>
                <div>Epoch Time: 1791888842.185 seconds</div>
                <div>Capture Length: {selectedFrame?.length} bytes</div>
              </div>
            </details>

            <details open className="group">
              <summary className="cursor-pointer select-none py-1 px-2 rounded hover:bg-slate-900 flex items-center gap-2 text-slate-200 font-semibold">
                <ChevronRight className="w-3.5 h-3.5 text-cyan-400 group-open:rotate-90 transition-transform" />
                <span>Internet Protocol Version 4 (IPv4), Src: {selectedFrame?.srcIp}, Dst: {selectedFrame?.destIp}</span>
              </summary>
              <div className="pl-6 pt-1 text-[11px] text-slate-400 space-y-0.5">
                <div>Version: 4, Header Length: 20 bytes</div>
                <div>Source Address: {selectedFrame?.srcIp}</div>
                <div>Destination Address: {selectedFrame?.destIp}</div>
                <div>Protocol: {selectedFrame?.protocol} (0x06)</div>
              </div>
            </details>

            <details open className="group">
              <summary className="cursor-pointer select-none py-1 px-2 rounded hover:bg-slate-900 flex items-center gap-2 text-slate-200 font-semibold">
                <ChevronRight className="w-3.5 h-3.5 text-cyan-400 group-open:rotate-90 transition-transform" />
                <span>Transmission Control Protocol (TCP), Src Port: {selectedFrame?.srcPort}, Dst Port: {selectedFrame?.destPort}</span>
              </summary>
              <div className="pl-6 pt-1 text-[11px] text-slate-400 space-y-0.5">
                <div>Source Port: {selectedFrame?.srcPort}</div>
                <div>Destination Port: {selectedFrame?.destPort}</div>
                <div>TCP Flags: {selectedFrame?.tcpFlags || '[PSH, ACK]'}</div>
                <div>Stream Index: 42</div>
              </div>
            </details>

            {selectedFrame?.suspiciousOffsets && selectedFrame.suspiciousOffsets.length > 0 && (
              <div className="p-3 bg-rose-950/40 border border-rose-800/80 rounded-lg space-y-1">
                <div className="flex items-center gap-2 text-rose-300 font-bold">
                  <ShieldAlert className="w-4 h-4 text-rose-400" />
                  <span>Extracted Threat Payload Pattern:</span>
                </div>
                {selectedFrame.suspiciousOffsets.map((so, idx) => (
                  <div key={idx} className="text-[11px]">
                    <div className="text-rose-200 font-semibold font-mono">{so.label}</div>
                    <div className="text-slate-400">Threat Class: {so.threatClass}</div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* Pane 3: Hex Dump & ASCII Payload Viewer */}
        <div className="bg-slate-950 border border-slate-800 rounded-xl p-4 shadow-lg space-y-3 font-mono text-xs">
          <div className="flex items-center justify-between pb-2 border-b border-slate-800">
            <div className="flex items-center gap-2">
              <Terminal className="w-4 h-4 text-cyan-400" />
              <span className="text-sm font-bold text-slate-200">
                Hex & ASCII Payload View
              </span>
            </div>

            <button
              onClick={handleCopyAscii}
              className="flex items-center gap-1 text-[11px] px-2 py-1 bg-slate-900 hover:bg-slate-800 border border-slate-700 rounded text-slate-300 transition cursor-pointer"
            >
              <Copy className="w-3 h-3 text-cyan-400" />
              <span>{copiedPayload ? 'Copied!' : 'Copy Decoded Text'}</span>
            </button>
          </div>

          {/* Hex display */}
          <div className="space-y-1">
            <div className="text-[10px] text-slate-500 uppercase tracking-wider">Hex Byte Stream:</div>
            <div className="p-2.5 bg-slate-900/90 rounded border border-slate-800 text-[11px] text-cyan-300 leading-relaxed break-all max-h-32 overflow-y-auto font-mono">
              {selectedFrame?.hexPayload}
            </div>
          </div>

          {/* ASCII display */}
          <div className="space-y-1">
            <div className="text-[10px] text-slate-500 uppercase tracking-wider">Decoded ASCII Stream:</div>
            <div className="p-2.5 bg-slate-900/90 rounded border border-slate-800 text-[11px] text-slate-200 leading-relaxed whitespace-pre-wrap max-h-40 overflow-y-auto font-mono">
              {selectedFrame?.asciiPayload}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
