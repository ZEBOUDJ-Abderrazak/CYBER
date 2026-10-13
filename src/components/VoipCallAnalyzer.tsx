/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 * 
 * SENTINEL FUSION - Wireshark VoIP & Audio RTP Forensics Analyzer
 * Inspects SIP signaling ladder diagrams, RTP jitter, and audio waveform playback.
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
  ArrowRight
} from 'lucide-react';

export const VoipCallAnalyzer: React.FC = () => {
  const [sessions] = useState<VoipCallSession[]>(MOCK_VOIP_CALLS);
  const [selectedCallId, setSelectedCallId] = useState<string>('SIP-CALL-2026-89410-EXT');
  const [isPlaying, setIsPlaying] = useState<boolean>(false);
  const [playbackProgress, setPlaybackProgress] = useState<number>(0);
  const audioContextRef = useRef<AudioContext | null>(null);
  const oscillatorRef = useRef<OscillatorNode | null>(null);

  const activeCall = sessions.find(s => s.callId === selectedCallId) || sessions[0];

  useEffect(() => {
    let timer: any;
    if (isPlaying) {
      timer = setInterval(() => {
        setPlaybackProgress(prev => {
          if (prev >= 100) {
            handleStopAudio();
            return 0;
          }
          return prev + 2;
        });
      }, 200);
    }
    return () => clearInterval(timer);
  }, [isPlaying]);

  const handleTogglePlayAudio = () => {
    if (isPlaying) {
      handleStopAudio();
    } else {
      handleStartAudio();
    }
  };

  const handleStartAudio = () => {
    try {
      const ctx = new (window.AudioContext || (window as any).webkitAudioContext)();
      audioContextRef.current = ctx;

      // Create a modulated audio synthesizer simulating telephone voice frequencies
      const osc = ctx.createOscillator();
      const gain = ctx.createGain();

      osc.type = 'sine';
      osc.frequency.setValueAtTime(440, ctx.currentTime);
      
      // Phone call frequency modulation
      osc.frequency.exponentialRampToValueAtTime(880, ctx.currentTime + 0.3);
      osc.frequency.exponentialRampToValueAtTime(554, ctx.currentTime + 0.6);

      gain.gain.setValueAtTime(0.08, ctx.currentTime);

      osc.connect(gain);
      gain.connect(ctx.destination);
      osc.start();

      oscillatorRef.current = osc;
      setIsPlaying(true);
    } catch (e) {
      setIsPlaying(true);
    }
  };

  const handleStopAudio = () => {
    if (oscillatorRef.current) {
      try {
        oscillatorRef.current.stop();
        oscillatorRef.current.disconnect();
      } catch (e) {}
      oscillatorRef.current = null;
    }
    if (audioContextRef.current) {
      try {
        audioContextRef.current.close();
      } catch (e) {}
      audioContextRef.current = null;
    }
    setIsPlaying(false);
  };

  return (
    <div className="p-4 sm:p-6 space-y-6 max-w-7xl mx-auto font-sans">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <div className="flex items-center gap-2">
            <PhoneCall className="w-5 h-5 text-emerald-600" />
            <h1 className="text-xl font-bold text-slate-900 tracking-tight">
              Wireshark VoIP & Audio RTP Forensics Studio
            </h1>
          </div>
          <p className="text-xs text-slate-500 mt-1">
            SIP call signaling sequence reconstruction, RTP jitter buffer metrics, and decrypted audio stream playback.
          </p>
        </div>

        <div className="flex items-center gap-2 text-xs font-mono">
          <span className="px-3 py-1 bg-emerald-50 text-emerald-700 border border-emerald-200 rounded-lg font-semibold flex items-center gap-1.5 shadow-sm">
            <Radio className="w-3.5 h-3.5 text-emerald-600 animate-pulse" />
            Active VoIP Streams Monitored: 1 Intercepted Call
          </span>
        </div>
      </div>

      {/* Main 2-Column Grid: SIP Ladder Diagram & Audio RTP Waveform Player */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Left Column: SIP Signaling Flow Ladder */}
        <div className="bg-white border border-slate-200 rounded-2xl p-6 shadow-sm space-y-5">
          <div className="flex items-center justify-between pb-3 border-b border-slate-100">
            <div>
              <span className="text-xs font-mono font-bold text-indigo-600">{activeCall.callId}</span>
              <h2 className="text-sm font-bold text-slate-900 mt-0.5">
                SIP Call Flow Ladder (Signaling Sequence)
              </h2>
            </div>
            <span className="text-[11px] font-mono text-slate-500">
              Duration: {activeCall.durationSeconds}s
            </span>
          </div>

          {/* Caller & Callee Endpoints */}
          <div className="grid grid-cols-2 gap-3 text-xs font-mono">
            <div className="p-3 bg-slate-50 border border-slate-200 rounded-xl space-y-0.5">
              <div className="text-[10px] text-slate-500 uppercase tracking-wider">From (Caller):</div>
              <div className="text-slate-900 font-bold truncate">{activeCall.fromCaller}</div>
              <div className="text-rose-600 text-[10px] font-semibold">SPOOFED IDENTITY DETECTED</div>
            </div>

            <div className="p-3 bg-slate-50 border border-slate-200 rounded-xl space-y-0.5">
              <div className="text-[10px] text-slate-500 uppercase tracking-wider">To (Callee):</div>
              <div className="text-slate-900 font-bold truncate">{activeCall.toCallee}</div>
              <div className="text-slate-500 text-[10px]">Internal Executive PBX</div>
            </div>
          </div>

          {/* Ladder Messages Diagram */}
          <div className="space-y-2.5 relative before:absolute before:inset-0 before:left-1/2 before:w-0.5 before:bg-slate-200 py-1">
            {activeCall.sipMessages.map((msg, idx) => {
              const isInvite = msg.method === 'INVITE';
              const is200 = msg.method === '200 OK';
              const isBye = msg.method === 'BYE';
              const isClientToServer = isInvite || msg.method === 'ACK' || isBye;

              return (
                <div key={idx} className="relative z-10 flex items-center justify-between text-xs font-mono">
                  <div className={`w-[45%] text-right ${isClientToServer ? 'font-bold text-indigo-600' : 'text-slate-400'}`}>
                    {isClientToServer && (
                      <span className="bg-indigo-50 border border-indigo-200 px-2 py-1 rounded-md text-[11px] inline-block shadow-2xs">
                        {msg.method} →
                      </span>
                    )}
                  </div>

                  <div className="w-5 h-5 rounded-full bg-white border-2 border-indigo-500 flex items-center justify-center text-[9px] font-bold text-indigo-700 shadow-xs">
                    {idx + 1}
                  </div>

                  <div className={`w-[45%] text-left ${!isClientToServer ? 'font-bold text-emerald-600' : 'text-slate-400'}`}>
                    {!isClientToServer && (
                      <span className="bg-emerald-50 border border-emerald-200 px-2 py-1 rounded-md text-[11px] inline-block shadow-2xs">
                        ← {msg.method} {msg.statusCode && `(${msg.statusCode})`}
                      </span>
                    )}
                  </div>
                </div>
              );
            })}
          </div>

          {/* Vishing / Threat Indicators */}
          <div className="p-3 bg-amber-50 border border-amber-200 rounded-xl space-y-1.5 text-xs">
            <div className="flex items-center gap-2 text-amber-900 font-bold">
              <ShieldAlert className="w-4 h-4 text-amber-600" />
              <span>Voice / Vishing Telemetry Warnings:</span>
            </div>
            {activeCall.threatIndicators.map((ind, i) => (
              <div key={i} className="text-amber-800 text-[11px] flex items-center gap-1.5">
                <span className="w-1.5 h-1.5 rounded-full bg-amber-500 shrink-0" />
                <span>{ind}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Right Column: Audio RTP Waveform & Interactive Playback Engine */}
        <div className="bg-white border border-slate-200 rounded-2xl p-6 shadow-sm space-y-6 flex flex-col justify-between">
          <div className="space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-slate-100">
              <div>
                <span className="text-xs font-bold uppercase tracking-wider text-slate-500">
                  RTP Stream Forensics & Quality Metrics
                </span>
                <h2 className="text-base font-bold text-slate-900 mt-0.5">
                  Audio Quality & MOS Score Analysis
                </h2>
              </div>
              <span className="px-2.5 py-1 bg-emerald-100 text-emerald-800 rounded-full font-bold text-xs font-mono">
                MOS: {activeCall.rtpStream.mosScore} / 5.0 ({activeCall.rtpStream.audioQualityRating})
              </span>
            </div>

            {/* RTP Metric Cards */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs font-mono">
              <div className="p-3 bg-slate-50 border border-slate-200 rounded-xl">
                <div className="text-[10px] text-slate-500 uppercase">Codec:</div>
                <div className="text-slate-900 font-bold mt-1">G.711 u-law</div>
              </div>
              <div className="p-3 bg-slate-50 border border-slate-200 rounded-xl">
                <div className="text-[10px] text-slate-500 uppercase">Avg Jitter:</div>
                <div className="text-slate-900 font-bold mt-1">{activeCall.rtpStream.avgJitterMs} ms</div>
              </div>
              <div className="p-3 bg-slate-50 border border-slate-200 rounded-xl">
                <div className="text-[10px] text-slate-500 uppercase">Packet Loss:</div>
                <div className="text-emerald-600 font-bold mt-1">{activeCall.rtpStream.packetLossPct}%</div>
              </div>
              <div className="p-3 bg-slate-50 border border-slate-200 rounded-xl">
                <div className="text-[10px] text-slate-500 uppercase">SSRC Stream:</div>
                <div className="text-indigo-600 font-bold mt-1">{activeCall.rtpStream.ssrc}</div>
              </div>
            </div>

            {/* Audio Waveform Equalizer Display */}
            <div className="p-5 bg-slate-900 rounded-2xl space-y-4">
              <div className="flex items-center justify-between text-xs font-mono text-slate-400">
                <span className="flex items-center gap-1.5 text-cyan-300 font-bold">
                  <Activity className="w-4 h-4 text-cyan-400" />
                  <span>Intercepted Audio Waveform Spectrum</span>
                </span>
                <span>{isPlaying ? 'PLAYING (LIVE SYNTHESIS)' : 'READY'}</span>
              </div>

              {/* Animated Waveform Bars */}
              <div className="h-24 flex items-end justify-between gap-1 px-2">
                {[40, 65, 30, 85, 95, 45, 70, 80, 55, 90, 60, 75, 40, 85, 95, 60, 45, 80, 70, 50, 65, 85, 40, 95].map((h, i) => {
                  const animatedH = isPlaying 
                    ? Math.min(100, Math.max(15, (h + Math.sin(Date.now() / 200 + i) * 35))) 
                    : h * 0.4;

                  return (
                    <div
                      key={i}
                      className="flex-1 bg-gradient-to-t from-cyan-500 to-indigo-400 rounded-t transition-all duration-150"
                      style={{ height: `${animatedH}%` }}
                    />
                  );
                })}
              </div>

              {/* Playback Progress Slider */}
              <div className="space-y-1">
                <div className="h-1.5 bg-slate-800 rounded-full overflow-hidden">
                  <div
                    className="h-full bg-cyan-400 transition-all duration-200"
                    style={{ width: `${playbackProgress}%` }}
                  />
                </div>
                <div className="flex justify-between text-[10px] font-mono text-slate-500">
                  <span>00:00</span>
                  <span>00:{activeCall.durationSeconds}</span>
                </div>
              </div>
            </div>
          </div>

          {/* Player Controls */}
          <div className="pt-4 border-t border-slate-100 flex items-center justify-between">
            <button
              onClick={handleTogglePlayAudio}
              className={`px-5 py-2.5 rounded-xl font-bold text-xs flex items-center gap-2 transition cursor-pointer shadow-sm ${
                isPlaying 
                  ? 'bg-rose-600 hover:bg-rose-700 text-white' 
                  : 'bg-emerald-600 hover:bg-emerald-700 text-white'
              }`}
            >
              {isPlaying ? <Pause className="w-4 h-4" /> : <Play className="w-4 h-4" />}
              <span>{isPlaying ? 'Pause Audio Stream' : 'Play Intercepted Voice Stream'}</span>
            </button>

            <span className="text-xs text-slate-500 font-mono">
              Web Audio Synthesizer • PCM Decoded
            </span>
          </div>
        </div>
      </div>
    </div>
  );
};
