/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 * 
 * SENTINEL FUSION - Wireshark PCAP File & Image Object Carving Studio
 * Reconstructs carved files, images, executables, scripts, and documents from packet streams.
 */

import React, { useState } from 'react';
import { CarvedFileObject } from '../types/security';
import { MOCK_CARVED_FILES } from '../engine/sample-data';
import { 
  FileCode, 
  Image as ImageIcon, 
  Download, 
  ShieldAlert, 
  FileText, 
  Layers, 
  Hash, 
  Eye, 
  CheckCircle2, 
  Binary, 
  Activity, 
  Copy,
  ExternalLink,
  Lock
} from 'lucide-react';

export const PcapFileCarver: React.FC = () => {
  const [files] = useState<CarvedFileObject[]>(MOCK_CARVED_FILES);
  const [selectedFileId, setSelectedFileId] = useState<string>('CARVED-001');
  const [copiedHash, setCopiedHash] = useState<string | null>(null);

  const selectedFile = files.find(f => f.id === selectedFileId) || files[0];

  const handleCopyHash = (hash: string) => {
    navigator.clipboard.writeText(hash);
    setCopiedHash(hash);
    setTimeout(() => setCopiedHash(null), 2000);
  };

  const handleDownloadFile = (file: CarvedFileObject) => {
    let content = file.previewContent || file.hexDumpPreview;
    let mime = file.mimeType;
    let blob = new Blob([content], { type: mime });
    let url = URL.createObjectURL(blob);
    let a = document.createElement('a');
    a.href = url;
    a.download = file.fileName;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="p-4 sm:p-6 space-y-6 max-w-7xl mx-auto font-sans">
      {/* Top Banner */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <div className="flex items-center gap-2">
            <Binary className="w-5 h-5 text-indigo-600" />
            <h1 className="text-xl font-bold text-slate-900 tracking-tight">
              Wireshark Object Carving & Reconstructed File Forensics
            </h1>
          </div>
          <p className="text-xs text-slate-500 mt-1">
            Reconstructed images, shell scripts, Java bytecode, and exfiltrated documents extracted from TCP/UDP payload streams.
          </p>
        </div>

        <div className="flex items-center gap-2 text-xs font-mono">
          <span className="px-3 py-1 bg-indigo-50 text-indigo-700 border border-indigo-200 rounded-lg font-semibold flex items-center gap-1.5 shadow-sm">
            <Lock className="w-3.5 h-3.5 text-indigo-600" />
            PCAP File Carving Engine: {files.length} Reconstructed Artifacts
          </span>
        </div>
      </div>

      {/* Main 2-Column Split: Carved Object Grid & Detail Inspection Panel */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Column: List of Extracted Files & Images */}
        <div className="space-y-3">
          <h2 className="text-xs font-bold uppercase tracking-wider text-slate-500 flex items-center justify-between">
            <span>Carved Stream Objects</span>
            <span className="font-mono text-indigo-600">{files.length} Extracted</span>
          </h2>

          <div className="space-y-2.5">
            {files.map(file => {
              const isSelected = file.id === selectedFileId;
              const isMalicious = file.threatVerdict === 'MALICIOUS';
              const isExfil = file.threatVerdict === 'CONFIDENTIAL_EXFIL';
              const isImage = file.fileType === 'IMAGE';

              return (
                <div
                  key={file.id}
                  onClick={() => setSelectedFileId(file.id)}
                  className={`p-3.5 rounded-xl border transition-all cursor-pointer ${
                    isSelected 
                      ? 'bg-white border-indigo-500 shadow-md ring-2 ring-indigo-500/10' 
                      : 'bg-white border-slate-200 hover:border-slate-300 hover:shadow-sm'
                  }`}
                >
                  <div className="flex items-start justify-between gap-2">
                    <div className="flex items-center gap-2">
                      <div className={`w-8 h-8 rounded-lg flex items-center justify-center shrink-0 ${
                        isImage ? 'bg-sky-50 text-sky-600' :
                        file.fileType === 'SCRIPT' ? 'bg-emerald-50 text-emerald-600' :
                        file.fileType === 'DOCUMENT' ? 'bg-purple-50 text-purple-600' :
                        'bg-amber-50 text-amber-600'
                      }`}>
                        {isImage ? <ImageIcon className="w-4 h-4" /> : <FileCode className="w-4 h-4" />}
                      </div>
                      <div className="min-w-0">
                        <div className="text-xs font-bold text-slate-900 truncate">
                          {file.fileName}
                        </div>
                        <div className="text-[10px] font-mono text-slate-500">
                          {(file.sizeBytes / 1024).toFixed(1)} KB • Frame #{file.extractedFromFrame}
                        </div>
                      </div>
                    </div>

                    <span className={`text-[10px] font-mono px-2 py-0.5 rounded-full font-bold shrink-0 ${
                      isMalicious ? 'bg-rose-50 text-rose-700 border border-rose-200' :
                      isExfil ? 'bg-amber-50 text-amber-700 border border-amber-200' :
                      'bg-sky-50 text-sky-700 border border-sky-200'
                    }`}>
                      {file.threatVerdict.replace('_', ' ')}
                    </span>
                  </div>

                  <div className="mt-2.5 pt-2 border-t border-slate-100 flex items-center justify-between text-[11px] text-slate-500 font-mono">
                    <span>Proto: {file.sourceProtocol}</span>
                    <span>Entropy: <strong className={file.entropy > 7.0 ? 'text-rose-600' : 'text-slate-700'}>{file.entropy}</strong></span>
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Right 2 Columns: Full Forensic File Inspector & Image Preview */}
        <div className="lg:col-span-2 bg-white border border-slate-200 rounded-2xl p-6 shadow-sm space-y-6">
          {/* File Header */}
          <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-4 pb-4 border-b border-slate-200">
            <div className="space-y-1">
              <div className="flex items-center gap-2">
                <span className="font-mono text-xs font-bold text-indigo-600">{selectedFile.id}</span>
                <span className="px-2 py-0.5 rounded-full text-[10px] font-mono font-bold bg-slate-100 text-slate-700 border border-slate-200">
                  {selectedFile.mimeType}
                </span>
                <span className={`px-2 py-0.5 rounded-full text-[10px] font-bold ${
                  selectedFile.threatVerdict === 'MALICIOUS' ? 'bg-rose-100 text-rose-700' : 'bg-amber-100 text-amber-800'
                }`}>
                  {selectedFile.threatVerdict}
                </span>
              </div>
              <h2 className="text-lg font-bold text-slate-900 tracking-tight">
                {selectedFile.fileName}
              </h2>
              <div className="text-xs text-slate-500 font-mono">
                Carved from Stream: {selectedFile.sourceHost} → {selectedFile.destinationHost}
              </div>
            </div>

            <button
              onClick={() => handleDownloadFile(selectedFile)}
              className="px-4 py-2 bg-indigo-600 hover:bg-indigo-700 text-white font-semibold rounded-xl text-xs flex items-center gap-2 shadow-sm transition cursor-pointer shrink-0"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Download Carved File</span>
            </button>
          </div>

          {/* Cryptographic Hashes & VirusTotal Score */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs font-mono">
            <div className="p-3 bg-slate-50 border border-slate-200 rounded-xl space-y-1">
              <div className="text-[10px] text-slate-500 uppercase tracking-wider flex items-center justify-between">
                <span>SHA-256 Provenance Signature:</span>
                <button
                  onClick={() => handleCopyHash(selectedFile.sha256)}
                  className="text-indigo-600 hover:text-indigo-700 text-[10px] font-sans font-medium flex items-center gap-1 cursor-pointer"
                >
                  <Copy className="w-3 h-3" />
                  {copiedHash === selectedFile.sha256 ? 'Copied' : 'Copy'}
                </button>
              </div>
              <div className="text-slate-800 text-[11px] truncate font-bold">
                {selectedFile.sha256}
              </div>
            </div>

            <div className="p-3 bg-slate-50 border border-slate-200 rounded-xl space-y-1">
              <div className="text-[10px] text-slate-500 uppercase tracking-wider">
                Threat Intelligence & VirusTotal:
              </div>
              <div className="text-rose-600 font-bold text-xs flex items-center gap-1.5">
                <ShieldAlert className="w-3.5 h-3.5" />
                <span>{selectedFile.virusTotalScore}</span>
              </div>
            </div>
          </div>

          {/* If Image: Render Extracted Visual Image directly! */}
          {selectedFile.fileType === 'IMAGE' && selectedFile.previewUrl && (
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold uppercase tracking-wider text-slate-700 flex items-center gap-2">
                  <ImageIcon className="w-4 h-4 text-sky-600" />
                  <span>Visual Image Reconstruction Preview:</span>
                </span>
                <span className="text-[11px] text-slate-500 font-mono">PNG RGBA 480x320</span>
              </div>
              <div className="p-4 bg-slate-100 border border-slate-200 rounded-xl flex items-center justify-center">
                <img
                  src={selectedFile.previewUrl}
                  alt={selectedFile.fileName}
                  className="max-h-60 rounded-lg shadow-md border border-slate-300"
                />
              </div>
            </div>
          )}

          {/* Text/Script/Bytecode Preview */}
          {selectedFile.previewContent && (
            <div className="space-y-2">
              <span className="text-xs font-bold uppercase tracking-wider text-slate-700 flex items-center gap-2">
                <FileCode className="w-4 h-4 text-indigo-600" />
                <span>Reconstructed Content Dissection:</span>
              </span>
              <div className="p-4 bg-slate-900 rounded-xl text-slate-200 font-mono text-xs overflow-x-auto max-h-56 leading-relaxed">
                <pre className="whitespace-pre-wrap">{selectedFile.previewContent}</pre>
              </div>
            </div>
          )}

          {/* Hex Dump Section */}
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-xs font-bold uppercase tracking-wider text-slate-700 flex items-center gap-2">
                <Binary className="w-4 h-4 text-slate-600" />
                <span>Header Hex Signature & Entropy ({selectedFile.entropy} / 8.0):</span>
              </span>
              {selectedFile.entropy > 7.0 && (
                <span className="text-[10px] font-bold text-rose-600 font-mono bg-rose-50 px-2 py-0.5 rounded border border-rose-200">
                  HIGH ENTROPY: PACKED/ENCRYPTED
                </span>
              )}
            </div>
            <div className="p-3 bg-slate-50 border border-slate-200 rounded-xl font-mono text-xs text-slate-700 leading-relaxed break-all">
              {selectedFile.hexDumpPreview}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
