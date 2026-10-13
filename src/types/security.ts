/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 * 
 * SENTINEL FUSION - Common Security Event Schema (CSES v1.0) & Intelligence Types
 */

export type ToolSource = 
  | 'NMAP' 
  | 'SURICATA' 
  | 'ZEEK' 
  | 'WIRESHARK_TSHARK' 
  | 'WAZUH' 
  | 'SYSMON' 
  | 'MISP' 
  | 'OSQUERY';

export type EventCategory = 
  | 'DISCOVERY' 
  | 'NETWORK_ALERT' 
  | 'FLOW' 
  | 'ENDPOINT_PROCESS' 
  | 'AUTH' 
  | 'DNS' 
  | 'THREAT_INTEL'
  | 'EXFILTRATION';

export type SeverityLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFORMATIONAL';

export interface NormalizedEvent {
  id: string;
  timestamp: string; // ISO 8601 UTC
  sourceTool: ToolSource;
  category: EventCategory;
  sourceIp?: string;
  destIp?: string;
  sourcePort?: number;
  destPort?: number;
  protocol?: string;
  assetId?: string;
  hostname?: string;
  severity: SeverityLevel;
  title: string;
  description: string;
  rawEvent: string;
  evidenceHash: string; // SHA-256 for chain-of-custody
  mitreTechniques: string[]; // e.g. ['T1046', 'T1190']
  attributes: Record<string, any>;
  anomalyScore?: number; // 0 - 100
}

export interface ServiceBaseline {
  port: number;
  protocol: string;
  service: string;
  version: string;
  baselineStatus: 'AUTHORIZED' | 'UNEXPECTED_NEW' | 'CHANGED_BANNER';
  firstSeen: string;
  lastScanned: string;
}

export interface UnifiedAsset {
  id: string;
  ip: string;
  mac: string;
  hostname: string;
  os: string;
  segment: 'DMZ' | 'INTERNAL_CORE' | 'USER_LAN' | 'CLOUD_VPC';
  criticality: 'TIER_1_CRITICAL' | 'TIER_2_HIGH' | 'TIER_3_MEDIUM' | 'TIER_4_LOW';
  services: ServiceBaseline[];
  sensorHealth: {
    nmapScanned: boolean;
    suricataCovered: boolean;
    zeekMonitored: boolean;
    wazuhAgentActive: boolean;
    pcapCaptureEnabled: boolean;
  };
  lastSeen: string;
  tags: string[];
}

export interface MitreTechniqueMapping {
  tactic: string;
  id: string;
  name: string;
  eventIds: string[];
  confidence: number;
}

export interface Hypothesis {
  id: string;
  title: string;
  likelihood: 'HIGH' | 'MEDIUM' | 'LOW';
  confidencePercentage: number;
  rationale: string;
  supportingEvidenceIds: string[];
  refutingEvidenceIds: string[];
}

export interface ActionRecommendation {
  id: string;
  title: string;
  priority: 'IMMEDIATE' | 'HIGH' | 'MEDIUM';
  reason: string;
  requiredTool: ToolSource;
  suggestedCommand?: string;
}

export interface Incident {
  id: string;
  title: string;
  summary: string;
  severity: SeverityLevel;
  confidenceScore: number; // 0-100 explainable score
  confidenceBreakdown: {
    networkDiscoveryCorroboration: number; // e.g. 25
    idsPayloadDetection: number;            // e.g. 30
    packetForensicsVerification: number;    // e.g. 20
    endpointExecutionConfirmation: number;  // e.g. 15
    threatIntelReputationMatch: number;     // e.g. 10
  };
  status: 'OPEN_INVESTIGATION' | 'CONTAINMENT_IN_PROGRESS' | 'REMEDIATED' | 'FALSE_POSITIVE';
  affectedAssets: UnifiedAsset[];
  attackerIps: string[];
  primaryAttackVector: string;
  firstObservedAt: string;
  lastObservedAt: string;
  events: NormalizedEvent[];
  mitreMatrix: MitreTechniqueMapping[];
  hypotheses: Hypothesis[];
  recommendations: ActionRecommendation[];
}

export interface PacketFrame {
  frameNumber: number;
  timestamp: string;
  srcIp: string;
  destIp: string;
  srcPort: number;
  destPort: number;
  protocol: string;
  length: number;
  info: string;
  tcpFlags?: string;
  hexPayload: string;
  asciiPayload: string;
  suspiciousOffsets?: {
    start: number;
    end: number;
    label: string;
    threatClass: string;
  }[];
}

export interface PlaybookResponseAction {
  id: string;
  incidentId: string;
  title: string;
  tool: ToolSource | 'PERIMETER_FIREWALL' | 'IAM_DIRECTORY';
  target: string;
  actionType: 'ISOLATE_HOST' | 'BLOCK_IP' | 'KILL_PROCESS' | 'DUMP_PCAP' | 'REVOKE_CREDENTIALS';
  riskLevel: 'HIGH_DISRUPTION' | 'MODERATE' | 'LOW';
  requiresApproval: boolean;
  status: 'PENDING_APPROVAL' | 'APPROVED' | 'EXECUTING' | 'EXECUTED' | 'ROLLED_BACK' | 'REJECTED';
  approverRole: string;
  approverName?: string;
  approvedAt?: string;
  safeguards: string[];
  rollbackCommand: string;
  simulationOutput: string;
  executionLogs?: string[];
}

export interface TelemetryCoverageSegment {
  segmentName: string;
  cidr: string;
  totalHosts: number;
  nmapCoverage: number; // %
  suricataCoverage: number; // %
  zeekCoverage: number; // %
  wazuhCoverage: number; // %
  pcapCoverage: number; // %
  blindSpotAssessment: string;
  gapSeverity: 'CRITICAL_GAP' | 'PARTIAL_GAP' | 'HEALTHY';
}

export interface InvestigationChatMessage {
  id: string;
  sender: 'ANALYST' | 'AI_INVESTIGATOR' | 'SYSTEM';
  timestamp: string;
  content: string;
  citedEvidenceIds?: string[];
  suggestedAction?: string;
}

export interface CarvedFileObject {
  id: string;
  fileName: string;
  fileType: 'IMAGE' | 'EXECUTABLE' | 'SCRIPT' | 'DOCUMENT' | 'ARCHIVE' | 'AUDIO';
  mimeType: string;
  sizeBytes: number;
  extractedFromFrame: number;
  sourceProtocol: 'HTTP' | 'SMB' | 'FTP' | 'TFTP' | 'DNS';
  sourceHost: string;
  destinationHost: string;
  md5: string;
  sha256: string;
  threatVerdict: 'MALICIOUS' | 'SUSPICIOUS' | 'CLEAN' | 'CONFIDENTIAL_EXFIL';
  virusTotalScore?: string;
  previewUrl?: string; // base64 or inline data
  previewContent?: string;
  hexDumpPreview: string;
  entropy: number; // 0 - 8.0 (measure of encryption/packing)
  extractedAt: string;
}

export interface VoipCallSession {
  callId: string;
  fromCaller: string;
  toCallee: string;
  codec: string;
  startTime: string;
  durationSeconds: number;
  sipMessages: Array<{
    method: 'INVITE' | '100 TRYING' | '180 RINGING' | '200 OK' | 'ACK' | 'BYE';
    timestamp: string;
    from: string;
    to: string;
    frameNumber: number;
    statusCode?: number;
  }>;
  rtpStream: {
    ssrc: string;
    totalPackets: number;
    lostPackets: number;
    packetLossPct: number;
    avgJitterMs: number;
    maxJitterMs: number;
    mosScore: number; // 1.0 - 5.0 (Mean Opinion Score)
    audioQualityRating: 'EXCELLENT' | 'GOOD' | 'FAIR' | 'POOR';
    synthesizedAudioFrequencies: number[];
  };
  threatIndicators: string[];
}

export interface GeoThreatFeed {
  id: string;
  timestamp: string;
  attackerIp: string;
  country: string;
  countryCode: string;
  city: string;
  asn: string;
  threatType: 'Log4j / JNDI RCE' | 'Cobalt Strike C2' | 'LockBit Ransomware' | 'DDoS SYN Flood' | 'DNS Tunnel Exfiltration' | 'Brute Force SSH';
  severity: SeverityLevel;
  targetAsset: string;
  targetPort: number;
  actionTaken: 'BLOCKED_AT_EDGE' | 'DROPPED_BY_IPS' | 'ISOLATED_BY_EDR' | 'FLAGGED_FOR_AUDIT';
  throughputKbps: number;
}
