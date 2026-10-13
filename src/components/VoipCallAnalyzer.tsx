/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 * 
 * SENTINEL FUSION - Wireshark VoIP & Audio RTP Forensics Studio
 * Real audio synthesizer, playable Web Audio waveform, downloadable .WAV file,
 * interactive SIP ladder diagram, and RTP jitter buffer telemetry.
 */

import React, { useState, useEffect, useRef } from 'react';
import { VoipCallSession } from '../types/security';
import { MOCK_VOIP_CALLS } from '../engine/sample-data';
import { 
  PhoneCall, 
  Volume2, 
  VolumeX, 
  Play, 
  Pause, 
  Activity, 
  ShieldAlert, 
  Clock, 
  Radio, 
  Layers, 
  CheckCircle2, 
  BarChart3, 
  Sparkles,
  ArrowRight,
  Download,
  Sliders,
  FileAudio,
  MessageSquare,
  RefreshCw,
  Terminal
} from 'lucide-react';

export const VoipCallAnalyzer: React.FC = () => {
  const [sessions] = useState<VoipCallSession[]>(MOCK_VOIP_CALLS);
  const [selectedCallId, setSelectedCallId] = useState<string>('SIP-CALL-2026-89410-EXT');
  const [isPlaying, setIsPlaying] = useState<boolean>(false);
  const [playbackTime, setPlaybackTime] = useState<number>(0); // 0 to 48 seconds
  const [selectedSipMessageIdx, setSelectedSipMessageIdx] = useState<number>(0);
  
  // Interactive Jitter Buffer Simulator
  const [jitterBufferSizeMs, setJitterBufferSizeMs] = useState<number>(40);
  const [simulatedLossPct, setSimulatedLossPct] = useState<number>(0.25);
  const [downloadSuccess, setDownloadSuccess] = useState<string | null>(null);

  const audioContextRef = useRef<AudioContext | null>(null);
  const oscillatorNodeRef = useRef<OscillatorNode | null>(null);
  const gainNodeRef = useRef<GainNode | null>(null);
  const animationFrameRef = useRef<number | null>(null);

  const activeCall = sessions.find(s => s.callId === selectedCallId) || sessions[0];

  // Dynamic MOS calculation based on jitter and loss
  const calculatedMos = Math.max(
    1.0, 
    Math.min(
      4.5, 
      +(4.4 - (jitterBufferSizeMs / 120) * 0.4 - (simulatedLossPct * 0.15)).toFixed(2)
    )
  );

  // Playback timer ticker
  useEffect(() => {
    let interval: any;
    if (isPlaying) {
      interval = setInterval(() => {
        setPlaybackTime(prev => {
          if (prev >= activeCall.durationSeconds) {
            handleStopAudio();
            return 0;
          }
          return prev + 1;
        });
      }, 1000);
    }
    return () => clearInterval(interval);
  }, [isPlaying, activeCall.durationSeconds]);

  const handleTogglePlayAudio = () => {
    if (isPlaying) {
      handleStopAudio();
    } else {
      handleStartAudio();
    }
  };

  const handleStartAudio = () => {
    try {
      // 1. Spoken intercepted voice communication via SpeechSynthesis
      if (typeof window !== 'undefined' && 'speechSynthesis' in window) {
        window.speechSynthesis.cancel();
        const text = "Attention: Intercepted voice communication on SIP trunk 1042. External caller from IP 194.26.29.112 attempted spoofed connection to corporate financial desk. Reconnaissance confirmed.";
        const utterance = new SpeechSynthesisUtterance(text);
        utterance.rate = 1.0;
        utterance.pitch = 0.95;
        utterance.onend = () => {
          handleStopAudio();
        };
        utterance.onerror = () => {
          handleStopAudio();
        };
        window.speechSynthesis.speak(utterance);
      }

      // 2. Drive Web Audio API for telephone carrier modulation (440Hz + 350Hz dial/ring tone modulated)
      const ctx = new (window.AudioContext || (window as any).webkitAudioContext)();
      audioContextRef.current = ctx;

      const osc = ctx.createOscillator();
      const gain = ctx.createGain();

      osc.type = 'sawtooth';
      osc.frequency.setValueAtTime(440, ctx.currentTime);
      gain.gain.setValueAtTime(0.03, ctx.currentTime);

      osc.connect(gain);
      gain.connect(ctx.destination);
      osc.start();

      oscillatorNodeRef.current = osc;
      gainNodeRef.current = gain;
      setIsPlaying(true);
    } catch (e) {
      setIsPlaying(true);
    }
  };

  const handleStopAudio = () => {
    if (typeof window !== 'undefined' && 'speechSynthesis' in window) {
      window.speechSynthesis.cancel();
    }
    if (oscillatorNodeRef.current) {
      try {
        oscillatorNodeRef.current.stop();
        oscillatorNodeRef.current.disconnect();
      } catch (e) {}
      oscillatorNodeRef.current = null;
    }
    if (audioContextRef.current && audioContextRef.current.state !== 'closed') {
      try {
        audioContextRef.current.close();
      } catch (e) {}
      audioContextRef.current = null;
    }
    setIsPlaying(false);
  };

  // Real .WAV Audio Generator: writes standard RIFF/WAVE header and PCM sine wave samples
  const handleDownloadRealWavFile = () => {
    const sampleRate = 8000;
    const durationSec = 4; // 4 seconds sample
    const numSamples = sampleRate * durationSec;
    const buffer = new ArrayBuffer(44 + numSamples * 2);
    const view = new DataView(buffer);

    // RIFF chunk descriptor
    writeString(view, 0, 'RIFF');
    view.setUint32(4, 36 + numSamples * 2, true);
    writeString(view, 8, 'WAVE');

    // fmt sub-chunk
    writeString(view, 12, 'fmt ');
    view.setUint32(16, 16, true); // Subchunk1Size (16 for PCM)
    view.setUint16(20, 1, true);  // AudioFormat (1 for PCM)
    view.setUint16(22, 1, true);  // NumChannels (1 mono)
    view.setUint32(24, sampleRate, true); // SampleRate (8000 Hz)
    view.setUint32(28, sampleRate * 2, true); // ByteRate
    view.setUint16(32, 2, true);  // BlockAlign
    view.setUint16(34, 16, true); // BitsPerSample (16 bits)

    // data sub-chunk
    writeString(view, 36, 'data');
    view.setUint32(40, numSamples * 2, true);

    // Write synthesized G.711 PCM telephony audio tones (440Hz dial tone + 800Hz jitter)
    for (let i = 0; i < numSamples; i++) {
      const t = i / sampleRate;
      const sample = Math.sin(2 * Math.PI * 440 * t) * 0.4 + Math.sin(2 * Math.PI * 350 * t) * 0.3;
      const intSample = Math.max(-32768, Math.min(32767, sample * 32767));
      view.setInt16(44 + i * 2, intSample, true);
    }

    const blob = new Blob([buffer], { type: 'audio/wav' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `intercepted_voip_call_${activeCall.callId}.wav`;
    a.click();
    URL.revokeObjectURL(url);

    setDownloadSuccess(`Downloaded intercepted audio stream: ${a.download}`);
    setTimeout(() => setDownloadSuccess(null), 3500);
  };

  const writeString = (view: DataView, offset: number, string: string) => {
    for (let i = 0; i < string.length; i++) {
      view.setUint8(offset + i, string.charCodeAt(i));
    }
  };

  const selectedSipMsg = activeCall.sipMessages[selectedSipMessageIdx] || activeCall.sipMessages[0];

  const getRawSipPayload = (msg: typeof selectedSipMsg) => {
    return `${msg.method} ${msg.to} SIP/2.0\r
Via: SIP/2.0/UDP 194.26.29.112:5060;branch=z9hG4bK89104271;rport\r
Max-Forwards: 70\r
From: <${msg.from}>;tag=as39108a7\r
To: <${msg.to}>\r
Call-ID: ${activeCall.callId}\r
CSeq: ${msg.frameNumber} ${msg.method.split(' ')[0]}\r
User-Agent: Asterisk PBX 18.12.0\r
Content-Type: application/sdp\r
Content-Length: 214\r
\r
v=0\r
o=external_spoof 2890844526 2890842807 IN IP4 194.26.29.112\r
s=VoIP Intercepted Session\r
c=IN IP4 194.26.29.112\r
t=0 0\r
m=audio 16402 RTP/AVP 0 101\r
a=rtpmap:0 PCMU/8000\r
a=rtpmap:101 telephone-event/8000\r
a=fmtp:101 0-16\r
a=ptime:20`;
  };

  return (
    <div className="p-4 sm:p-6 space-y-6 max-w-7xl mx-auto font-sans bg-slate-50 min-h-screen">
      {/* Top Banner */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 bg-white p-5 rounded-2xl border border-slate-200 shadow-sm">
        <div>
          <div className="flex items-center gap-2">
            <PhoneCall className="w-5 h-5 text-indigo-600" />
            <h1 className="text-xl font-bold text-slate-900 tracking-tight">
              Wireshark VoIP Call & Voice RTP Forensics Studio
            </h1>
          </div>
          <p className="text-xs text-slate-500 mt-1">
            Reconstructed voice communications, real interactive SIP signaling ladder, Web Audio player, and G.711 / Opus payload extraction.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={handleDownloadRealWavFile}
            className="px-3.5 py-2 bg-indigo-600 hover:bg-indigo-700 text-white font-semibold rounded-xl text-xs flex items-center gap-2 shadow-sm transition cursor-pointer"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Download .WAV Audio</span>
          </button>
        </div>
      </div>

      {downloadSuccess && (
        <div className="p-3 bg-emerald-50 border border-emerald-200 text-emerald-900 text-xs font-mono rounded-xl flex items-center gap-2 animate-fade-in shadow-2xs">
          <CheckCircle2 className="w-4 h-4 text-emerald-600 shrink-0" />
          <span>{downloadSuccess}</span>
        </div>
      )}

      {/* Main Grid: Audio Player, Jitter Telemetry, and SIP Ladder */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Column: Voice Audio Player & Waveform */}
        <div className="space-y-4">
          <div className="bg-white border border-slate-200 rounded-2xl p-5 shadow-sm space-y-4">
            <div className="flex items-center justify-between">
              <span className="text-xs font-bold uppercase tracking-wider text-slate-500 flex items-center gap-1.5">
                <FileAudio className="w-4 h-4 text-indigo-600" />
                <span>Intercepted Stream Player</span>
              </span>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-emerald-50 text-emerald-700 border border-emerald-200 font-bold">
                CODEC: G.711 u-law
              </span>
            </div>

            {/* Audio Waveform Equalizer */}
            <div className="p-4 bg-slate-900 rounded-xl space-y-3">
              <div className="flex items-center justify-between text-slate-400 text-[11px] font-mono">
                <span>00:{playbackTime.toString().padStart(2, '0')}</span>
                <span className="text-indigo-400">G.711 PCMU (8000 Hz)</span>
                <span>00:{activeCall.durationSeconds.toString().padStart(2, '0')}</span>
              </div>

              {/* Animated Waveform Visualizer */}
              <div className="flex items-center justify-between gap-1 h-16 px-1">
                {Array.from({ length: 32 }).map((_, idx) => {
                  const baseHeight = 15 + Math.sin(idx * 0.4) * 35;
                  const dynamicHeight = isPlaying 
                    ? Math.max(10, Math.min(100, (baseHeight + (Math.sin(playbackTime * 4 + idx) * 30))))
                    : baseHeight * 0.5;

                  return (
                    <div
                      key={idx}
                      className={`w-1.5 rounded-full transition-all duration-150 ${
                        isPlaying ? 'bg-indigo-400' : 'bg-slate-700'
                      }`}
                      style={{ height: `${dynamicHeight}%` }}
                    />
                  );
                })}
              </div>

              {/* Play / Pause / Seek */}
              <div className="flex items-center justify-between pt-2 border-t border-slate-800">
                <button
                  onClick={handleTogglePlayAudio}
                  className={`px-4 py-2 rounded-xl text-xs font-bold flex items-center gap-2 transition cursor-pointer shadow-sm ${
                    isPlaying 
                      ? 'bg-rose-600 hover:bg-rose-700 text-white' 
                      : 'bg-indigo-600 hover:bg-indigo-700 text-white'
                  }`}
                >
                  {isPlaying ? <Pause className="w-4 h-4" /> : <Play className="w-4 h-4" />}
                  <span>{isPlaying ? 'Pause Audio' : 'Play Intercepted Audio'}</span>
                </button>

                <div className="flex items-center gap-2 text-slate-400 text-xs font-mono">
                  <Volume2 className="w-4 h-4 text-indigo-400" />
                  <span>RTP Payload Active</span>
                </div>
              </div>
            </div>

            {/* Call Metadata Details */}
            <div className="p-3.5 bg-slate-50 border border-slate-200 rounded-xl space-y-2 text-xs">
              <div className="flex items-center justify-between text-slate-600">
                <span className="font-semibold">Caller (From):</span>
                <span className="font-mono text-slate-900 font-bold">{activeCall.fromCaller}</span>
              </div>
              <div className="flex items-center justify-between text-slate-600">
                <span className="font-semibold">Recipient (To):</span>
                <span className="font-mono text-slate-900 font-bold">{activeCall.toCallee}</span>
              </div>
              <div className="flex items-center justify-between text-slate-600">
                <span className="font-semibold">Session ID:</span>
                <span className="font-mono text-indigo-600">{activeCall.callId}</span>
              </div>
              <div className="flex items-center justify-between text-slate-600">
                <span className="font-semibold">Total RTP Packets:</span>
                <span className="font-mono text-slate-900 font-bold">{activeCall.rtpStream.totalPackets} frames</span>
              </div>
            </div>

            {/* Threat Indicators */}
            <div className="space-y-1.5 pt-1">
              <span className="text-[11px] font-bold text-slate-700 uppercase tracking-wider">
                Voice Security Indicators:
              </span>
              <div className="space-y-1">
                {activeCall.threatIndicators.map((indicator, idx) => (
                  <div key={idx} className="p-2 bg-rose-50 border border-rose-200 text-rose-800 rounded-lg text-xs flex items-start gap-1.5">
                    <ShieldAlert className="w-3.5 h-3.5 text-rose-600 shrink-0 mt-0.5" />
                    <span>{indicator}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Interactive RTP Jitter Buffer Simulator */}
          <div className="bg-white border border-slate-200 rounded-2xl p-5 shadow-sm space-y-3.5">
            <div className="flex items-center justify-between">
              <span className="text-xs font-bold uppercase tracking-wider text-slate-500 flex items-center gap-1.5">
                <Sliders className="w-4 h-4 text-indigo-600" />
                <span>RTP Jitter Buffer & MOS Telemetry</span>
              </span>
              <span className="text-xs font-bold text-slate-900 font-mono">
                MOS: <strong className={calculatedMos > 4.0 ? 'text-emerald-600' : 'text-amber-600'}>{calculatedMos} / 5.0</strong>
              </span>
            </div>

            <div className="space-y-2">
              <div className="flex items-center justify-between text-xs text-slate-600">
                <span>Jitter Buffer Size:</span>
                <span className="font-mono font-bold text-slate-900">{jitterBufferSizeMs} ms</span>
              </div>
              <input
                type="range"
                min="10"
                max="120"
                value={jitterBufferSizeMs}
                onChange={(e) => setJitterBufferSizeMs(Number(e.target.value))}
                className="w-full accent-indigo-600"
              />
            </div>

            <div className="space-y-2">
              <div className="flex items-center justify-between text-xs text-slate-600">
                <span>Simulated Packet Loss:</span>
                <span className="font-mono font-bold text-slate-900">{simulatedLossPct.toFixed(2)} %</span>
              </div>
              <input
                type="range"
                min="0"
                max="5"
                step="0.05"
                value={simulatedLossPct}
                onChange={(e) => setSimulatedLossPct(Number(e.target.value))}
                className="w-full accent-indigo-600"
              />
            </div>

            <div className="p-3 bg-slate-50 rounded-xl border border-slate-200 text-[11px] text-slate-600 flex items-center justify-between">
              <span>VoIP Call Quality Rating:</span>
              <span className="font-bold text-emerald-700 bg-emerald-50 px-2 py-0.5 rounded border border-emerald-200">
                {calculatedMos > 4.2 ? 'EXCELLENT (HIGH FIDELITY)' : 'FAIR (ACCEPTABLE)'}
              </span>
            </div>
          </div>
        </div>

        {/* Right 2 Columns: Interactive SIP Ladder Diagram & Dissection */}
        <div className="lg:col-span-2 space-y-4">
          <div className="bg-white border border-slate-200 rounded-2xl p-5 shadow-sm space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-slate-100">
              <div>
                <h2 className="text-sm font-bold text-slate-900 tracking-tight">
                  SIP Flow Sequence & Signaling Ladder Diagram
                </h2>
                <p className="text-xs text-slate-500">
                  Wireshark Telephony VoIP call flow. Click any message to inspect raw SIP headers and SDP media descriptions.
                </p>
              </div>

              <span className="text-xs font-mono text-indigo-600 font-bold bg-indigo-50 px-2.5 py-1 rounded-lg border border-indigo-200">
                6 Signaling Frames
              </span>
            </div>

            {/* SIP Ladder Visualization */}
            <div className="space-y-2">
              <div className="grid grid-cols-2 text-center text-xs font-bold text-slate-600 pb-2 border-b border-slate-200">
                <div className="border-r border-slate-200">Caller (Attacker: 194.26.29.112)</div>
                <div>Corporate PBX (Target: 10.0.1.5)</div>
              </div>

              <div className="space-y-2 pt-2">
                {activeCall.sipMessages.map((msg, idx) => {
                  const isSelected = selectedSipMessageIdx === idx;
                  const isOutgoing = msg.from.includes('external');

                  return (
                    <div
                      key={idx}
                      onClick={() => setSelectedSipMessageIdx(idx)}
                      className={`p-3 rounded-xl border transition-all cursor-pointer flex items-center justify-between text-xs ${
                        isSelected 
                          ? 'bg-indigo-50/70 border-indigo-500 shadow-sm ring-2 ring-indigo-500/10' 
                          : 'bg-slate-50 border-slate-200 hover:border-slate-300'
                      }`}
                    >
                      <div className="flex items-center gap-3">
                        <span className="font-mono text-[11px] font-bold text-slate-500">
                          #{msg.frameNumber}
                        </span>
                        <div className="flex items-center gap-2">
                          <span className={`px-2 py-0.5 rounded font-mono font-bold text-[11px] ${
                            msg.method === 'INVITE' ? 'bg-amber-100 text-amber-800' :
                            msg.method === '200 OK' ? 'bg-emerald-100 text-emerald-800' :
                            msg.method === 'BYE' ? 'bg-slate-200 text-slate-700' :
                            'bg-sky-100 text-sky-800'
                          }`}>
                            {msg.method}
                          </span>
                          <span className="text-slate-700 font-medium">
                            {isOutgoing ? '→ Sent to PBX Core' : '← Response from PBX Core'}
                          </span>
                        </div>
                      </div>

                      <div className="text-[11px] font-mono text-slate-500">
                        {msg.timestamp}
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>

            {/* Selected SIP Message Raw Dissector */}
            <div className="pt-3 border-t border-slate-200 space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold uppercase tracking-wider text-slate-700 flex items-center gap-1.5">
                  <Terminal className="w-4 h-4 text-indigo-600" />
                  <span>Wireshark SIP / SDP Protocol Dissection (Frame #{selectedSipMsg.frameNumber}):</span>
                </span>
                <span className="text-[11px] font-mono text-slate-500">
                  {selectedSipMsg.method}
                </span>
              </div>

              <div className="p-4 bg-slate-900 rounded-xl text-slate-200 font-mono text-xs overflow-x-auto max-h-60 leading-relaxed border border-slate-800">
                <pre>{getRawSipPayload(selectedSipMsg)}</pre>
              </div>
            </div>
          </div>

          {/* Intercepted Speech Transcript Box */}
          <div className="bg-white border border-slate-200 rounded-2xl p-5 shadow-sm space-y-3">
            <div className="flex items-center gap-2">
              <MessageSquare className="w-4 h-4 text-indigo-600" />
              <h3 className="text-xs font-bold text-slate-900 uppercase tracking-wider">
                Reconstructed Speech Transcript (Acoustic Forensics)
              </h3>
            </div>

            <div className="p-3.5 bg-slate-50 rounded-xl border border-slate-200 space-y-2 text-xs">
              <div className="flex items-start gap-2">
                <span className="font-bold text-rose-700 shrink-0 font-mono">[08:11:42] Caller:</span>
                <span className="text-slate-800">
                  "Hello, this is Corporate IT Support calling regarding urgent maintenance on database cluster Corp-DB01. Please confirm administrative credentials immediately."
                </span>
              </div>
              <div className="flex items-start gap-2">
                <span className="font-bold text-indigo-700 shrink-0 font-mono">[08:11:58] Callee:</span>
                <span className="text-slate-800">
                  "Which ticketing system change request is this attached to? I don't see an approved maintenance window on today's calendar."
                </span>
              </div>
              <div className="flex items-start gap-2">
                <span className="font-bold text-rose-700 shrink-0 font-mono">[08:12:28] Caller:</span>
                <span className="text-slate-800 italic">
                  [Call terminated abruptly by caller after challenge — Session ended with SIP BYE]
                </span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
