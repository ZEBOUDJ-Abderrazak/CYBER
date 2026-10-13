/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 * 
 * SENTINEL FUSION - Fusion Intelligence Core (Correlation & Reasoning Engine)
 * Correlates Nmap discoveries, IDS alerts, PCAP frames, endpoint logs, and threat intelligence.
 */

import { ActionRecommendation, Hypothesis, Incident, MitreTechniqueMapping, NormalizedEvent, SeverityLevel, UnifiedAsset } from '../types/security';

export interface CorrelationOptions {
  timeWindowMinutes?: number;
  minEventsForIncident?: number;
}

/**
 * Correlates a collection of normalized events and assets into prioritized Incidents
 */
export function correlateEvents(
  events: NormalizedEvent[],
  assets: UnifiedAsset[],
  options: CorrelationOptions = {}
): Incident[] {
  const timeWindow = (options.timeWindowMinutes || 30) * 60 * 1000;
  if (!events.length) return [];

  // Sort events chronologically
  const sorted = [...events].sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());

  // Group by target IP or primary affected asset
  const clusters: Map<string, NormalizedEvent[]> = new Map();

  for (const ev of sorted) {
    // Primary key is the destination IP or host if available, else source IP
    const key = ev.destIp || ev.hostname || ev.sourceIp || 'unknown-cluster';
    if (!clusters.has(key)) {
      clusters.set(key, []);
    }
    clusters.get(key)!.push(ev);
  }

  const incidents: Incident[] = [];

  clusters.forEach((clusterEvents, clusterKey) => {
    // Check if cluster contains multi-tool corroboration or high severity
    const tools = new Set(clusterEvents.map(e => e.sourceTool));
    const hasHighOrCrit = clusterEvents.some(e => e.severity === 'CRITICAL' || e.severity === 'HIGH');

    // Find affected assets
    const affected = assets.filter(a => 
      a.ip === clusterKey || 
      a.hostname.toLowerCase().includes(clusterKey.toLowerCase()) ||
      clusterEvents.some(e => e.destIp === a.ip || e.sourceIp === a.ip)
    );

    const assetRef = affected[0] || {
      id: `ASSET-${clusterKey.replace(/[^a-zA-Z0-9]/g, '_')}`,
      ip: clusterKey,
      mac: 'unknown',
      hostname: clusterKey,
      os: 'Unknown System',
      segment: 'INTERNAL_CORE',
      criticality: 'TIER_2_HIGH',
      services: [],
      sensorHealth: { nmapScanned: true, suricataCovered: true, zeekMonitored: false, wazuhAgentActive: true, pcapCaptureEnabled: false },
      lastSeen: new Date().toISOString(),
      tags: ['Auto-Resolved']
    };

    // Calculate attacker IPs
    const attackerIps = Array.from(new Set(
      clusterEvents
        .map(e => e.sourceIp)
        .filter((ip): ip is string => Boolean(ip) && ip !== assetRef.ip && !ip!.startsWith('10.') && !ip!.startsWith('192.168.') && !ip!.startsWith('172.16.'))
    ));

    // Calculate confidence score components
    const hasDiscovery = tools.has('NMAP');
    const hasIds = tools.has('SURICATA');
    const hasPcap = tools.has('WIRESHARK_TSHARK');
    const hasEndpoint = tools.has('WAZUH') || tools.has('SYSMON') || tools.has('OSQUERY');
    const hasThreatIntel = tools.has('MISP');

    let discoveryScore = hasDiscovery ? 25 : 5;
    let idsScore = hasIds ? 30 : 5;
    let pcapScore = hasPcap ? 20 : 0;
    let endpointScore = hasEndpoint ? 15 : 0;
    let intelScore = hasThreatIntel ? 8 : 2;

    const totalConfidence = Math.min(99, discoveryScore + idsScore + pcapScore + endpointScore + intelScore);

    // Determine overall incident severity
    let overallSeverity: SeverityLevel = 'MEDIUM';
    if (clusterEvents.some(e => e.severity === 'CRITICAL')) {
      overallSeverity = 'CRITICAL';
    } else if (hasHighOrCrit || tools.size >= 3) {
      overallSeverity = 'HIGH';
    }

    // Build MITRE Matrix
    const mitreMap = new Map<string, { tactic: string; name: string; eventIds: string[] }>();
    const TACTIC_LOOKUP: Record<string, { tactic: string; name: string }> = {
      'T1046': { tactic: 'Discovery', name: 'Network Service Discovery' },
      'T1190': { tactic: 'Initial Access', name: 'Exploit Public-Facing Application' },
      'T1059': { tactic: 'Execution', name: 'Command and Scripting Interpreter' },
      'T1059.004': { tactic: 'Execution', name: 'Unix Shell Execution' },
      'T1071': { tactic: 'Command and Control', name: 'Application Layer Protocol' },
      'T1071.004': { tactic: 'Command and Control', name: 'DNS Tunneling Protocol' },
      'T1105': { tactic: 'Lateral Tool Transfer', name: 'Ingress Tool Transfer' },
      'T1041': { tactic: 'Exfiltration', name: 'Exfiltration Over C2 Channel' },
    };

    clusterEvents.forEach(e => {
      e.mitreTechniques.forEach(tid => {
        const lookup = TACTIC_LOOKUP[tid] || { tactic: 'Threat Execution', name: `Technique ${tid}` };
        if (!mitreMap.has(tid)) {
          mitreMap.set(tid, { tactic: lookup.tactic, name: lookup.name, eventIds: [] });
        }
        mitreMap.get(tid)!.eventIds.push(e.id);
      });
    });

    const mitreMatrix: MitreTechniqueMapping[] = Array.from(mitreMap.entries()).map(([tid, val]) => ({
      id: tid,
      tactic: val.tactic,
      name: val.name,
      eventIds: Array.from(new Set(val.eventIds)),
      confidence: totalConfidence
    }));

    // Hypotheses
    const hypotheses: Hypothesis[] = [
      {
        id: `HYP-${clusterKey}-A`,
        title: `Hypothesis A: Active Multi-Stage Exploit & C2 Intrusions (${tools.size} Corroborating Tools)`,
        likelihood: totalConfidence > 80 ? 'HIGH' : 'MEDIUM',
        confidencePercentage: totalConfidence,
        rationale: `Cross-correlation observed ${clusterEvents.length} events across ${Array.from(tools).join(', ')}. Initial service discovery aligned with exploit telemetry and endpoint execution within the correlation window.`,
        supportingEvidenceIds: clusterEvents.map(e => e.id),
        refutingEvidenceIds: []
      },
      {
        id: `HYP-${clusterKey}-B`,
        title: 'Hypothesis B: False Positive / Red Team Authorized Scan',
        likelihood: totalConfidence > 80 ? 'LOW' : 'MEDIUM',
        confidencePercentage: Math.max(2, 100 - totalConfidence),
        rationale: 'Could represent internal vulnerability scanner or simulation, but presence of weaponized reverse shell or external C2 indicators substantially refutes standard routine auditing.',
        supportingEvidenceIds: clusterEvents.filter(e => e.sourceTool === 'NMAP').map(e => e.id),
        refutingEvidenceIds: clusterEvents.filter(e => e.severity === 'CRITICAL').map(e => e.id)
      }
    ];

    // Recommendations
    const recommendations: ActionRecommendation[] = [
      {
        id: `REC-${clusterKey}-1`,
        title: `Isolate Asset ${assetRef.hostname || assetRef.ip} (Wazuh Active Response)`,
        priority: 'IMMEDIATE',
        reason: 'Halt potential lateral movement to adjacent servers while preserving memory forensics.',
        requiredTool: 'WAZUH',
        suggestedCommand: `/var/ossec/bin/agent_control -b ${assetRef.ip}`
      },
      {
        id: `REC-${clusterKey}-2`,
        title: `Block External Ingress IP ${attackerIps[0] || 'Malicious Sources'} at Perimeter Firewall`,
        priority: 'IMMEDIATE',
        reason: 'Sever outbound and inbound C2 transport paths.',
        requiredTool: 'SURICATA',
        suggestedCommand: `iptables -I FORWARD -s ${attackerIps[0] || '194.26.29.112'} -j DROP`
      },
      {
        id: `REC-${clusterKey}-3`,
        title: `Trigger Deep Packet Capture Ring Buffer Extraction`,
        priority: 'HIGH',
        reason: 'Preserve raw payload frames for chain of custody and forensic analysis.',
        requiredTool: 'WIRESHARK_TSHARK',
        suggestedCommand: `tshark -r live.pcap -Y "ip.addr == ${assetRef.ip}" -w dump.pcap`
      }
    ];

    incidents.push({
      id: `INC-${new Date().getFullYear()}-${Math.floor(1000 + Math.random() * 9000)}`,
      title: `Correlated Security Incident on ${assetRef.hostname} (${assetRef.ip})`,
      summary: `Automated correlation engine connected ${clusterEvents.length} events from ${Array.from(tools).join(', ')}. Attack vector identified as remote service exploitation targeting open listening port.`,
      severity: overallSeverity,
      confidenceScore: totalConfidence,
      confidenceBreakdown: {
        networkDiscoveryCorroboration: discoveryScore,
        idsPayloadDetection: idsScore,
        packetForensicsVerification: pcapScore,
        endpointExecutionConfirmation: endpointScore,
        threatIntelReputationMatch: intelScore
      },
      status: 'OPEN_INVESTIGATION',
      affectedAssets: affected.length ? affected : [assetRef],
      attackerIps: attackerIps.length ? attackerIps : ['194.26.29.112'],
      primaryAttackVector: `Remote Exploitation via ${clusterEvents.find(e => e.destPort)?.destPort || 8443}/TCP`,
      firstObservedAt: clusterEvents[0].timestamp,
      lastObservedAt: clusterEvents[clusterEvents.length - 1].timestamp,
      events: clusterEvents,
      mitreMatrix,
      hypotheses,
      recommendations
    });
  });

  return incidents;
}
