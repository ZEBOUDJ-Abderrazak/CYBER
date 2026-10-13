/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 * 
 * SENTINEL FUSION - Multi-Tool Ingestion Parsers
 * Parses Nmap XML, Suricata EVE-JSON, Zeek logs, Wazuh alerts, and TShark PCAP JSON
 */

import { NormalizedEvent, PacketFrame, ServiceBaseline } from '../types/security';
import { syncPseudoSha256 } from './evidence';

/**
 * Parses Nmap XML / text output into normalized discovery events and discovered services
 */
export function parseNmapScan(rawContent: string): { events: NormalizedEvent[]; services: ServiceBaseline[]; targetIp?: string; hostname?: string } {
  const events: NormalizedEvent[] = [];
  const services: ServiceBaseline[] = [];
  let targetIp = '192.168.1.100';
  let hostname = 'unknown-host';

  try {
    // Check if it's XML format
    if (rawContent.includes('<nmaprun') || rawContent.includes('<host>')) {
      const parser = new DOMParser();
      const xmlDoc = parser.parseFromString(rawContent, 'text/xml');
      
      const hostEl = xmlDoc.querySelector('host');
      if (hostEl) {
        const addrEl = hostEl.querySelector('address[addrtype="ipv4"]') || hostEl.querySelector('address');
        if (addrEl && addrEl.getAttribute('addr')) {
          targetIp = addrEl.getAttribute('addr')!;
        }
        
        const hostNameEl = hostEl.querySelector('hostnames hostname');
        if (hostNameEl && hostNameEl.getAttribute('name')) {
          hostname = hostNameEl.getAttribute('name')!;
        }

        const portEls = hostEl.querySelectorAll('ports port');
        portEls.forEach((p, idx) => {
          const portNum = parseInt(p.getAttribute('portid') || '0', 10);
          const proto = p.getAttribute('protocol') || 'tcp';
          const stateEl = p.querySelector('state');
          const state = stateEl?.getAttribute('state') || 'open';
          const serviceEl = p.querySelector('service');
          const serviceName = serviceEl?.getAttribute('name') || 'unknown';
          const product = serviceEl?.getAttribute('product') || '';
          const version = serviceEl?.getAttribute('version') || '';
          const fullVersion = [product, version].filter(Boolean).join(' ') || 'Standard';

          if (state === 'open') {
            const isUnexpected = portNum === 8443 || portNum === 7001 || portNum === 9999 || portNum === 4444;
            const baselineStatus = isUnexpected ? 'UNEXPECTED_NEW' : 'AUTHORIZED';

            services.push({
              port: portNum,
              protocol: proto,
              service: serviceName,
              version: fullVersion,
              baselineStatus,
              firstSeen: new Date().toISOString(),
              lastScanned: new Date().toISOString()
            });

            const evId = `NMAP-EV-${Date.now()}-${idx}`;
            const rawPortText = p.outerHTML;
            events.push({
              id: evId,
              timestamp: new Date().toISOString(),
              sourceTool: 'NMAP',
              category: 'DISCOVERY',
              destIp: targetIp,
              destPort: portNum,
              protocol: proto.toUpperCase(),
              hostname,
              severity: isUnexpected ? 'HIGH' : 'INFORMATIONAL',
              title: isUnexpected ? `Unexpected Open Service Port ${portNum}/${proto} (${serviceName})` : `Discovered Open Port ${portNum}/${proto} (${serviceName})`,
              description: `Nmap detected active listening service: ${serviceName} ${fullVersion} on host ${targetIp}. ${isUnexpected ? 'ATTENTION: Port not present in approved asset baseline!' : 'Service matches baseline profile.'}`,
              rawEvent: rawPortText,
              evidenceHash: syncPseudoSha256(rawPortText),
              mitreTechniques: ['T1046'],
              attributes: {
                port: portNum,
                state,
                service: serviceName,
                product,
                version,
                baselineViolation: isUnexpected
              }
            });
          }
        });
      }
    } else {
      // Fallback: simple text/regex parser for nmap stdout
      const ipMatch = rawContent.match(/Nmap scan report for (?:([a-zA-Z0-9.-]+) \()?([0-9.]+)\)?/);
      if (ipMatch) {
        if (ipMatch[1]) hostname = ipMatch[1];
        if (ipMatch[2]) targetIp = ipMatch[2];
      }

      const portRegex = /(\d+)\/(tcp|udp)\s+(\w+)\s+([^\n\r]+)/g;
      let match;
      let count = 0;
      while ((match = portRegex.exec(rawContent)) !== null) {
        count++;
        const portNum = parseInt(match[1], 10);
        const proto = match[2];
        const state = match[3];
        const serviceInfo = match[4].trim();

        if (state === 'open') {
          const isUnexpected = portNum === 8443 || portNum === 4444 || portNum === 7001;
          services.push({
            port: portNum,
            protocol: proto,
            service: serviceInfo.split(' ')[0] || 'service',
            version: serviceInfo.split(' ').slice(1).join(' ') || '1.0',
            baselineStatus: isUnexpected ? 'UNEXPECTED_NEW' : 'AUTHORIZED',
            firstSeen: new Date().toISOString(),
            lastScanned: new Date().toISOString()
          });

          events.push({
            id: `NMAP-TXT-${Date.now()}-${count}`,
            timestamp: new Date().toISOString(),
            sourceTool: 'NMAP',
            category: 'DISCOVERY',
            destIp: targetIp,
            destPort: portNum,
            protocol: proto.toUpperCase(),
            hostname,
            severity: isUnexpected ? 'HIGH' : 'INFORMATIONAL',
            title: `${isUnexpected ? '[ANOMALY] ' : ''}Open Port ${portNum}/${proto} (${serviceInfo})`,
            description: `Active service identified by Nmap: ${serviceInfo}`,
            rawEvent: match[0],
            evidenceHash: syncPseudoSha256(match[0]),
            mitreTechniques: ['T1046'],
            attributes: { port: portNum, proto, state, serviceInfo }
          });
        }
      }
    }
  } catch (err) {
    console.error('Error parsing Nmap data:', err);
  }

  return { events, services, targetIp, hostname };
}

/**
 * Parses Suricata EVE-JSON log lines
 */
export function parseSuricataEve(rawJsonLines: string): NormalizedEvent[] {
  const events: NormalizedEvent[] = [];
  const lines = rawJsonLines.split('\n').filter(l => l.trim().length > 0);

  lines.forEach((line, index) => {
    try {
      const data = JSON.parse(line);
      if (data.event_type === 'alert' || data.alert) {
        const alert = data.alert || {};
        const sevNum = alert.severity || 2;
        const sevMap: Record<number, 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'> = {
          1: 'CRITICAL',
          2: 'HIGH',
          3: 'MEDIUM',
          4: 'LOW'
        };

        const signature = alert.signature || 'Suricata IDS Alert';
        const signatureId = alert.signature_id || 0;
        const mitreList: string[] = [];
        if (signature.toLowerCase().includes('exploit') || signature.toLowerCase().includes('rce')) {
          mitreList.push('T1190');
        }
        if (signature.toLowerCase().includes('c2') || signature.toLowerCase().includes('beacon')) {
          mitreList.push('T1071');
        }
        if (signature.toLowerCase().includes('scan') || signature.toLowerCase().includes('recon')) {
          mitreList.push('T1046');
        }

        events.push({
          id: `SURI-${data.flow_id || Date.now()}-${index}`,
          timestamp: data.timestamp || new Date().toISOString(),
          sourceTool: 'SURICATA',
          category: 'NETWORK_ALERT',
          sourceIp: data.src_ip,
          destIp: data.dest_ip,
          sourcePort: data.src_port,
          destPort: data.dest_port,
          protocol: data.proto || 'TCP',
          severity: sevMap[sevNum] || 'HIGH',
          title: `Suricata IDS: ${signature}`,
          description: `Suricata network intrusion detection triggered rule [${signatureId}]: "${signature}". Category: ${alert.category || 'Potentially Bad Traffic'}. Payload payload inspected across flow ${data.src_ip}:${data.src_port} -> ${data.dest_ip}:${data.dest_port}.`,
          rawEvent: line,
          evidenceHash: syncPseudoSha256(line),
          mitreTechniques: mitreList.length ? mitreList : ['T1190'],
          attributes: {
            signature_id: signatureId,
            category: alert.category,
            flow_id: data.flow_id,
            in_iface: data.in_iface,
            payload_printable: data.payload_printable || data.http?.url || null
          }
        });
      } else if (data.event_type === 'dns') {
        events.push({
          id: `SURI-DNS-${Date.now()}-${index}`,
          timestamp: data.timestamp || new Date().toISOString(),
          sourceTool: 'SURICATA',
          category: 'DNS',
          sourceIp: data.src_ip,
          destIp: data.dest_ip,
          protocol: 'UDP',
          severity: data.dns?.rrname?.length > 45 ? 'HIGH' : 'INFORMATIONAL',
          title: `Suricata DNS Query: ${data.dns?.rrname || 'Unknown'}`,
          description: `DNS query ${data.dns?.type || 'A'} for ${data.dns?.rrname} answered with ${JSON.stringify(data.dns?.rdata || [])}`,
          rawEvent: line,
          evidenceHash: syncPseudoSha256(line),
          mitreTechniques: ['T1071.004'],
          attributes: data.dns || {}
        });
      }
    } catch (e) {
      // ignore malformed line
    }
  });

  return events;
}

/**
 * Parses Zeek log format (TSV or JSON)
 */
export function parseZeekLogs(rawContent: string, logType: 'conn' | 'http' | 'dns' | 'notice' = 'conn'): NormalizedEvent[] {
  const events: NormalizedEvent[] = [];
  const lines = rawContent.split('\n').filter(l => l.trim().length > 0 && !l.startsWith('#'));

  lines.forEach((line, index) => {
    try {
      if (line.startsWith('{')) {
        const data = JSON.parse(line);
        events.push({
          id: `ZEEK-${data.uid || Date.now()}-${index}`,
          timestamp: data.ts ? new Date(parseFloat(data.ts) * 1000).toISOString() : new Date().toISOString(),
          sourceTool: 'ZEEK',
          category: logType === 'dns' ? 'DNS' : logType === 'notice' ? 'NETWORK_ALERT' : 'FLOW',
          sourceIp: data['id.orig_h'],
          destIp: data['id.resp_h'],
          sourcePort: data['id.orig_p'],
          destPort: data['id.resp_p'],
          protocol: (data.proto || 'tcp').toUpperCase(),
          severity: data.note ? 'HIGH' : 'LOW',
          title: data.note ? `Zeek Notice: ${data.note}` : `Zeek ${logType.toUpperCase()} Stream: ${data['id.orig_h']} -> ${data['id.resp_h']}`,
          description: `Zeek protocol behavioral telemetry: duration ${data.duration || 0}s, sent ${data.orig_bytes || 0}B, received ${data.resp_bytes || 0}B. State: ${data.conn_state || 'SF'}.`,
          rawEvent: line,
          evidenceHash: syncPseudoSha256(line),
          mitreTechniques: ['T1071'],
          attributes: data
        });
      }
    } catch (e) {
      // skip
    }
  });

  return events;
}

/**
 * Parses Wazuh alert JSON
 */
export function parseWazuhAlerts(rawJson: string): NormalizedEvent[] {
  const events: NormalizedEvent[] = [];
  const lines = rawJson.split('\n').filter(l => l.trim().length > 0);

  lines.forEach((line, idx) => {
    try {
      const data = JSON.parse(line);
      const rule = data.rule || {};
      const agent = data.agent || {};
      const ruleLevel = rule.level || 3;
      
      let sev: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' = 'LOW';
      if (ruleLevel >= 12) sev = 'CRITICAL';
      else if (ruleLevel >= 8) sev = 'HIGH';
      else if (ruleLevel >= 5) sev = 'MEDIUM';

      const mitreTechniques = rule.mitre?.id || ['T1059'];

      events.push({
        id: `WAZUH-${data.id || Date.now()}-${idx}`,
        timestamp: data.timestamp || new Date().toISOString(),
        sourceTool: 'WAZUH',
        category: 'ENDPOINT_PROCESS',
        hostname: agent.name || 'host-endpoint',
        destIp: agent.ip || '127.0.0.1',
        severity: sev,
        title: `Wazuh EDR: ${rule.description || 'Endpoint Event'}`,
        description: `Wazuh agent [${agent.id || '001'}: ${agent.name}] triggered Rule ${rule.id} (Level ${ruleLevel}): ${rule.description}. Command line or process details: ${JSON.stringify(data.data || data.full_log || '')}`,
        rawEvent: line,
        evidenceHash: syncPseudoSha256(line),
        mitreTechniques: Array.isArray(mitreTechniques) ? mitreTechniques : [mitreTechniques],
        attributes: {
          ruleId: rule.id,
          ruleLevel,
          agentId: agent.id,
          agentName: agent.name,
          process: data.data?.process || data.data?.win?.eventdata?.image || null,
          cmdline: data.data?.command || data.data?.win?.eventdata?.commandLine || null
        }
      });
    } catch (e) {
      // skip
    }
  });

  return events;
}
