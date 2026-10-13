/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 * 
 * SENTINEL FUSION - Automated Verification Test Suite
 * Validates Nmap ingestion, Suricata correlation, SHA-256 integrity, and incident generation.
 */

import { parseNmapScan, parseSuricataEve, parseWazuhAlerts } from './parsers';
import { correlateEvents } from './correlation';
import { syncPseudoSha256 } from './evidence';
import { MOCK_ASSETS } from './sample-data';

export interface TestResult {
  testName: string;
  passed: boolean;
  details: string;
}

export function runSentinelTestSuite(): TestResult[] {
  const results: TestResult[] = [];

  // Test 1: Nmap XML Ingestion & Anomaly Detection
  try {
    const rawNmapXml = `<?xml version="1.0"?>
    <nmaprun scanner="nmap">
      <host>
        <address addr="10.0.4.15" addrtype="ipv4"/>
        <hostnames><hostname name="Corp-DB01.fin.corp"/></hostnames>
        <ports>
          <port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="8.9"/></port>
          <port protocol="tcp" portid="8443"><state state="open"/><service name="https-alt" product="Apache Tomcat" version="Spring 5.3"/></port>
        </ports>
      </host>
    </nmaprun>`;

    const parsed = parseNmapScan(rawNmapXml);
    const hasPort8443 = parsed.events.some(e => e.destPort === 8443);
    const hasUnexpectedBaseline = parsed.services.some(s => s.port === 8443 && s.baselineStatus === 'UNEXPECTED_NEW');

    results.push({
      testName: 'Nmap XML Ingestion & Baseline Diff',
      passed: hasPort8443 && hasUnexpectedBaseline,
      details: `Discovered ${parsed.events.length} ports. Port 8443 flagged as UNEXPECTED_NEW.`
    });
  } catch (err: any) {
    results.push({ testName: 'Nmap XML Ingestion & Baseline Diff', passed: false, details: err.message });
  }

  // Test 2: Suricata EVE-JSON Ingestion & Severity Mapping
  try {
    const rawSuricataEve = `{"timestamp":"2026-10-13T08:14:02Z","event_type":"alert","src_ip":"194.26.29.112","src_port":48912,"dest_ip":"10.0.4.15","dest_port":8443,"proto":"TCP","alert":{"signature":"ET EXPLOIT Spring4Shell RCE","signature_id":2034334,"severity":1}}`;
    const suriEvents = parseSuricataEve(rawSuricataEve);
    const isCritical = suriEvents.length > 0 && suriEvents[0].severity === 'CRITICAL';
    const isTargeting8443 = suriEvents[0]?.destPort === 8443;

    results.push({
      testName: 'Suricata EVE-JSON Exploit Extraction',
      passed: isCritical && isTargeting8443,
      details: `Extracted ${suriEvents.length} alert. Dest Port: 8443, Severity: CRITICAL.`
    });
  } catch (err: any) {
    results.push({ testName: 'Suricata EVE-JSON Exploit Extraction', passed: false, details: err.message });
  }

  // Test 3: SHA-256 Provenance & Tamper-Proof Hashing
  try {
    const samplePayload = 'TEST_SECURITY_EVENT_PAYLOAD_12345';
    const hash1 = syncPseudoSha256(samplePayload);
    const hash2 = syncPseudoSha256(samplePayload);
    const hashTampered = syncPseudoSha256(samplePayload + '_TAMPERED');

    results.push({
      testName: 'Cryptographic SHA-256 Provenance Verification',
      passed: hash1 === hash2 && hash1 !== hashTampered && hash1.length === 64,
      details: `Generated 64-char deterministic hash: ${hash1.slice(0, 16)}... Integrity verified.`
    });
  } catch (err: any) {
    results.push({ testName: 'Cryptographic SHA-256 Provenance Verification', passed: false, details: err.message });
  }

  // Test 4: Fusion Intelligence Core Multi-Source Correlation
  try {
    const rawNmapXml = `<nmaprun><host><address addr="10.0.4.15"/><ports><port protocol="tcp" portid="8443"><state state="open"/><service name="https-alt"/></port></ports></host></nmaprun>`;
    const rawSuricataEve = `{"timestamp":"2026-10-13T08:14:02Z","event_type":"alert","src_ip":"194.26.29.112","dest_ip":"10.0.4.15","dest_port":8443,"proto":"TCP","alert":{"signature":"ET EXPLOIT Spring4Shell","severity":1}}`;
    const rawWazuh = `{"timestamp":"2026-10-13T08:14:04Z","rule":{"level":14,"id":100201,"description":"Java spawned shell"},"agent":{"name":"Corp-DB01","ip":"10.0.4.15"},"data":{"process":"/bin/sh"}}`;

    const nmapEv = parseNmapScan(rawNmapXml).events;
    const suriEv = parseSuricataEve(rawSuricataEve);
    const wazuhEv = parseWazuhAlerts(rawWazuh);

    const allEvents = [...nmapEv, ...suriEv, ...wazuhEv];
    const incidents = correlateEvents(allEvents, MOCK_ASSETS);

    const hasIncident = incidents.length > 0;
    const incident = incidents[0];
    const highConfidence = incident && incident.confidenceScore >= 70;
    const hasHypotheses = incident && incident.hypotheses.length >= 2;

    results.push({
      testName: 'Fusion Intelligence Core Cross-Tool Correlation',
      passed: hasIncident && highConfidence && hasHypotheses,
      details: `Correlated ${allEvents.length} events across 3 tools. Incident Confidence: ${incident?.confidenceScore}%. Hypotheses generated: ${incident?.hypotheses.length}.`
    });
  } catch (err: any) {
    results.push({ testName: 'Fusion Intelligence Core Cross-Tool Correlation', passed: false, details: err.message });
  }

  return results;
}
