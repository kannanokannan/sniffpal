// ── SniffPal Parser Web Worker ────────────────────────
// Runs entirely off the main UI thread
// Handles 500MB+ files without freezing the browser

import { lookupCountry } from '../utils/geoip.js';

const TRACKER_DOMAINS = [
  "google-analytics.com", "doubleclick.net",
  "googleadservices.com", "googletagmanager.com",
  "facebook.com", "pixel.facebook.com",
  "graph.instagram.com", "criteo.com",
  "appsflyer.com", "mixpanel.com",
  "segment.io", "segment.com",
  "branch.io", "scorecardresearch.com",
  "tiktokv.com", "flurry.com",
  "amplitude.com", "hotjar.com",
  "clarity.ms", "newrelic.com",
  "datadog-browser-agent.com", "sentry.io",
  "intercom.io", "hubspot.com",
  "firebase.googleapis.com",
];

// Max packets to process — prevents memory crash on huge files
const MAX_PACKETS = 25000;

// ── Streaming JSON packet parser ─────────────────────
// Phase 1: byte-level scan for packet boundaries — zero string allocation,
//          works on files of any size without hitting V8 string limits.
// Phase 2: read each sampled packet individually and parse.
async function streamParsePackets(file, onProgress) {
  const CHUNK = 16 * 1024 * 1024; // 16 MB scan chunks
  const totalBytes = file.size;

  // ── Phase 1: scan raw bytes, reservoir-sample byte offsets ──
  const offsets = []; // [[byteStart, byteEnd], ...]  max MAX_PACKETS entries
  let totalPacketCount = 0;
  let depth = 0, inStr = false, esc = false;
  let pktByteStart = -1;

  for (let base = 0; base < totalBytes; base += CHUNK) {
    const end = Math.min(base + CHUNK, totalBytes);
    const bytes = new Uint8Array(await file.slice(base, end).arrayBuffer());

    for (let i = 0; i < bytes.length; i++) {
      const b = bytes[i];
      if (esc)                    { esc = false;       continue; }
      if (b === 0x5C && inStr)    { esc = true;        continue; } // backslash
      if (b === 0x22)             { inStr = !inStr;    continue; } // "
      if (inStr)                  { continue; }

      if (b === 0x7B || b === 0x5B) {               // { [
        depth++;
        if (b === 0x7B && depth === 2 && pktByteStart < 0) pktByteStart = base + i;
      } else if (b === 0x7D || b === 0x5D) {        // } ]
        if (b === 0x7D && depth === 2 && pktByteStart >= 0) {
          totalPacketCount++;
          if (offsets.length < MAX_PACKETS) {
            offsets.push([pktByteStart, base + i]);
          } else {
            const j = Math.floor(Math.random() * totalPacketCount);
            if (j < MAX_PACKETS) offsets[j] = [pktByteStart, base + i];
          }
          pktByteStart = -1;
        }
        depth--;
      }
    }

    onProgress(
      5 + Math.round((end / totalBytes) * 13),
      `Scanning… ${totalPacketCount.toLocaleString()} packets found`
    );
  }

  if (totalPacketCount === 0) return { packets: [], totalPacketCount: 0 };

  // Sort by start offset so Phase 2 reads are sequential (faster on disk)
  offsets.sort((a, b) => a[0] - b[0]);

  // ── Phase 2: read and parse each sampled packet individually ──
  onProgress(18, `Parsing ${offsets.length.toLocaleString()} sampled packets…`);
  const decoder = new TextDecoder('utf-8', { fatal: false });
  const packets = [];

  for (let i = 0; i < offsets.length; i++) {
    const [start, end] = offsets[i];
    const buf = await file.slice(start, end + 1).arrayBuffer();
    try { packets.push(JSON.parse(decoder.decode(buf))); } catch { /* skip malformed */ }

    if (i % 500 === 0 && i > 0) {
      onProgress(
        18 + Math.round((i / offsets.length) * 4),
        `Parsing ${i.toLocaleString()} / ${offsets.length.toLocaleString()} packets…`
      );
    }
  }

  return { packets, totalPacketCount };
}

self.onmessage = async function (e) {
  const { file, fileSize } = e.data;

  try {
    // ── Step 1: Stream-parse the file ──────────────
    self.postMessage({ type: "progress", value: 5, label: "Scanning file…" });

    let totalPacketCount, packets;
    try {
      ({ totalPacketCount, packets } = await streamParsePackets(
        file,
        (pct, label) => self.postMessage({ type: "progress", value: pct, label })
      ));
    } catch (err) {
      self.postMessage({ type: "error", message: "Could not read file: " + err.message });
      return;
    }

    if (totalPacketCount === 0) {
      self.postMessage({ type: "error", message: "No packets found. Please export from Wireshark as JSON (File → Export Packet Dissections → As JSON)." });
      return;
    }

    const sampled = totalPacketCount > MAX_PACKETS;

    self.postMessage({ type: "progress", value: 22, label: `Analysing ${packets.length.toLocaleString()} packets…` });

    // ── Step 3: Process packets in chunks ───────────
    const devices = Object.create(null);
    const protocols = {};
    const trafficTypes = {};
    const dnsQueries = {};
    const sniSites = {};
    const securityAlerts = [];
    const arpReplies = {};
    const dhcpServers = new Set();
    const icmpRedirectSources = new Set();
    const trackers = {};
    let totalBytes = 0;
    let retransmissions = 0;
    let nxdomainCount = 0;
    let icmpRedirects = 0;
    const rttValues = [];

    // ── v2.1 IoT + GeoIP tracking ──────────────────
    const mqttUnencryptedDevices = new Set();
    const upnpDevices = new Set();
    const oddHoursDevices = new Set();
    const foreignConnections = Object.create(null); // mac → { countryCode: { count, flag } }
    const ipGeoCache = Object.create(null);          // dstIp → lookupCountry result (cache)
    const SUSPICIOUS_COUNTRIES = new Set(['CN', 'RU', 'KP', 'IR']);
    let captureStart = null;
    let captureEnd = null;

    const CHUNK = 1000;
    const total = packets.length;
    const MAC_RE = /^([0-9a-f]{2}:){5}[0-9a-f]{2}$/i;

    for (let i = 0; i < total; i++) {
      const pkt = packets[i];
      const layers = pkt?._source?.layers || {};
      const frameLen = parseInt(layers?.frame?.["frame.len"] || 0);
      totalBytes += frameLen;

      // ── DNS ────────────────────────────────────────
      if (layers?.dns) {
        const query = layers.dns?.["dns.qry.name"];
        const rcode = layers.dns?.["dns.flags.rcode"];
        const isResponse = layers.dns?.["dns.flags.response"];
        if (query) {
          const domain = cleanDomain(query);
          if (!dnsQueries[domain]) {
            dnsQueries[domain] = {
              domain, count: 0, failed: 0,
              icon: getSiteIcon(domain),
              category: getSiteCategory(domain),
            };
          }
          dnsQueries[domain].count++;
          if (isResponse === "1" && rcode === "3") {
            dnsQueries[domain].failed++;
            nxdomainCount++;
          }
        }
      }

      // ── SNI ────────────────────────────────────────
      const sni =
        layers?.tls?.["tls.handshake.extensions_server_name"] ||
        layers?.ssl?.["ssl.handshake.extensions_server_name"];
      if (sni) {
        const domain = cleanDomain(sni);
        if (!sniSites[domain]) {
          sniSites[domain] = {
            domain, count: 0, encrypted: true,
            icon: getSiteIcon(domain),
            category: getSiteCategory(domain),
          };
        }
        sniSites[domain].count++;
      }

      // ── Tracker Detection ──────────────────────────
      const domainToCheck = sni || layers?.dns?.["dns.qry.name"] || "";
      if (domainToCheck) {
        const matched = TRACKER_DOMAINS.find(t => domainToCheck.includes(t));
        if (matched) {
          if (!trackers[matched]) {
            trackers[matched] = {
              domain: matched, count: 0,
              icon: getTrackerIcon(matched),
              type: getTrackerType(matched),
            };
          }
          trackers[matched].count++;
        }
      }

      // ── HTTP ───────────────────────────────────────
      if (layers?.http) {
        const host = layers.http?.["http.host"];
        const method = layers.http?.["http.request.method"];
        const authHeader = layers.http?.["http.authorization"];
        const uri = layers.http?.["http.request.uri"];

        if (host) {
          const domain = cleanDomain(host);
          if (!sniSites[domain]) {
            sniSites[domain] = {
              domain, count: 0, encrypted: false,
              icon: getSiteIcon(domain),
              category: getSiteCategory(domain),
            };
          }
          sniSites[domain].count++;
        }

        if (authHeader) {
          securityAlerts.push({
            severity: "critical", icon: "🔴",
            title: "Cleartext Credentials Detected",
            detail: `HTTP Authorization header exposed on ${host || "unknown host"}`,
            type: "credential",
          });
        }

        if (method === "POST" && !sni) {
          securityAlerts.push({
            severity: "warning", icon: "🟡",
            title: "Unencrypted Form Submission",
            detail: `HTTP POST to ${host || "unknown"} — data sent in cleartext`,
            type: "cleartext",
          });
        }

        if (uri && (
          uri.includes("cmd.exe") || uri.includes("eval(") ||
          uri.includes("../") || uri.includes("select%20") ||
          uri.includes("<script")
        )) {
          securityAlerts.push({
            severity: "critical", icon: "🔴",
            title: "Suspicious Request Detected",
            detail: `Possible exploit attempt: ${uri.substring(0, 60)}`,
            type: "exploit",
          });
        }
      }

      // ── FTP ────────────────────────────────────────
      if (layers?.ftp) {
        const cmd = layers.ftp?.["ftp.request.command"];
        if (cmd === "PASS" || cmd === "USER") {
          securityAlerts.push({
            severity: "critical", icon: "🔴",
            title: "FTP Cleartext Password",
            detail: "FTP credentials transmitted without encryption",
            type: "credential",
          });
        }
      }

      // ── ARP Spoofing ───────────────────────────────
      if (layers?.arp) {
        const arpOpcode = layers.arp?.["arp.opcode"];
        const arpSrcMac = layers.arp?.["arp.src.hw_mac"];
        const arpSrcIp = layers.arp?.["arp.src.proto_ipv4"];
        if (arpOpcode === "2") {
          if (!arpReplies[arpSrcMac]) {
            arpReplies[arpSrcMac] = { count: 0, ips: new Set() };
          }
          arpReplies[arpSrcMac].count++;
          if (arpSrcIp) arpReplies[arpSrcMac].ips.add(arpSrcIp);
        }
      }

      // ── Rogue DHCP ─────────────────────────────────
      if (layers?.bootp || layers?.dhcp) {
        const msgType =
          layers?.bootp?.["bootp.option.dhcp"] ||
          layers?.dhcp?.["dhcp.option.dhcp"];
        const srcIpDhcp = layers?.ip?.["ip.src"] || null;
        const srcMacDhcp = layers?.eth?.["eth.src"] || null;
        if ((msgType === "2" || msgType === "5") && srcIpDhcp && srcMacDhcp) {
          dhcpServers.add(`${srcIpDhcp}|${srcMacDhcp}`);
        }
      }

      // ── ICMP Redirect ──────────────────────────────
      if (layers?.icmp) {
        const icmpType = layers.icmp?.["icmp.type"];
        if (icmpType === "5") {
          icmpRedirects++;
          icmpRedirectSources.add(layers?.ip?.["ip.src"] || "unknown");
        }
      }

      // ── TCP Health ─────────────────────────────────
      if (layers?.tcp) {
        if (layers.tcp?.["tcp.analysis.retransmission"] ||
            layers.tcp?.["tcp.analysis.fast_retransmission"]) {
          retransmissions++;
        }
        const rtt = parseFloat(layers.tcp?.["tcp.analysis.ack_rtt"] || 0);
        if (rtt > 0) rttValues.push(rtt);
      }

      // ── Protocol ───────────────────────────────────
      const proto =
        layers?.http  ? "HTTP"  :
        layers?.tls   ? "TLS"   :
        layers?.dns   ? "DNS"   :
        layers?.bootp ? "DHCP"  :
        layers?.icmp  ? "ICMP"  :
        layers?.tcp   ? "TCP"   :
        layers?.udp   ? "UDP"   :
        layers?.arp   ? "ARP"   : "Other";
      protocols[proto] = (protocols[proto] || 0) + 1;

      // ── Traffic Type ───────────────────────────────
      const srcPort = parseInt(layers?.tcp?.["tcp.srcport"] || layers?.udp?.["udp.srcport"] || 0);
      const dstPort = parseInt(layers?.tcp?.["tcp.dstport"] || layers?.udp?.["udp.dstport"] || 0);
      const trafficType = detectTrafficType(layers, srcPort, dstPort, frameLen);
      if (trafficType) {
        trafficTypes[trafficType] = (trafficTypes[trafficType] || 0) + 1;
      }

      // ── Devices ────────────────────────────────────
      const srcMac = layers?.eth?.["eth.src"] || null;
      const dstMac = layers?.eth?.["eth.dst"] || null;
      const srcIp = layers?.ip?.["ip.src"] || layers?.ipv6?.["ipv6.src"] || null;
      const dstIp = layers?.ip?.["ip.dst"] || layers?.ipv6?.["ipv6.dst"] || null;
      const hostname = layers?.bootp?.["bootp.option.hostname"] || layers?.dhcp?.["dhcp.option.hostname"] || null;

      [srcMac, dstMac].forEach((mac, idx) => {
        if (!mac || !MAC_RE.test(mac)) return;
        if (mac.startsWith("ff:ff") || mac.startsWith("33:33") || mac.startsWith("01:00")) return;
        if (!devices[mac]) {
          const vendor = lookupVendor(mac);
          devices[mac] = {
            mac, packets: 0, bytes: 0, vendor,
            icon: getDeviceIcon(vendor),
            nickname: getNickname(vendor),
            ip: null, hostname: null, trafficTypes: {},
          };
        }
        devices[mac].packets++;
        devices[mac].bytes += frameLen;
        if (idx === 0 && srcIp && !devices[mac].ip) devices[mac].ip = srcIp;
        if (idx === 1 && dstIp && !devices[mac].ip) devices[mac].ip = dstIp;
        if (hostname && !devices[mac].hostname) devices[mac].hostname = hostname;
        if (trafficType) {
          devices[mac].trafficTypes[trafficType] = (devices[mac].trafficTypes[trafficType] || 0) + 1;
        }
      });

      // ── v2.1: Capture timestamp ────────────────────
      const timeEpoch = parseFloat(layers?.frame?.["frame.time_epoch"] || 0);
      if (timeEpoch > 0) {
        if (!captureStart || timeEpoch < captureStart) captureStart = timeEpoch;
        if (!captureEnd   || timeEpoch > captureEnd)   captureEnd   = timeEpoch;
      }

      // ── v2.1: mDNS device naming (port 5353) ──────
      if (layers?.dns) {
        const mdnsName = layers.dns?.["dns.qry.name"];
        if (mdnsName && mdnsName.endsWith('.local')) {
          // Instance queries: "Living Room TV._airplay._tcp.local" → "Living Room TV"
          const m = mdnsName.match(/^([^_][^.]+)\._/);
          if (m && srcMac && devices[srcMac] && !devices[srcMac].hostname) {
            devices[srcMac].hostname = m[1].trim();
          }
        }
        // NetBIOS / NBNS machine names
        const nbnsName = layers?.nbns?.["nbns.name"];
        if (nbnsName && srcMac && devices[srcMac] && !devices[srcMac].hostname) {
          devices[srcMac].hostname = nbnsName.replace(/\s*<\d+>\s*$/, '').trim();
        }
      }

      // ── v2.1: IoT protocol detection ──────────────
      if (dstPort === 1883 || srcPort === 1883) {
        // Unencrypted MQTT — cleartext IoT messaging
        const key = srcMac || srcIp || 'unknown';
        mqttUnencryptedDevices.add(key);
      }
      if (dstPort === 1900 || srcPort === 1900) {
        // UPnP/SSDP — devices advertising port-opening
        const key = srcMac || srcIp || 'unknown';
        upnpDevices.add(key);
      }

      // ── v2.1: Odd-hours traffic (2am–5am local) ───
      if (timeEpoch > 0 && srcMac) {
        const hr = new Date(timeEpoch * 1000).getHours();
        if (hr >= 2 && hr < 5) oddHoursDevices.add(srcMac);
      }

      // ── v2.1: Foreign IP detection ────────────────
      if (dstIp && srcMac) {
        let geo = ipGeoCache[dstIp];
        if (geo === undefined) geo = ipGeoCache[dstIp] = lookupCountry(dstIp);
        if (geo && geo.code && SUSPICIOUS_COUNTRIES.has(geo.code)) {
          if (!foreignConnections[srcMac]) foreignConnections[srcMac] = Object.create(null);
          if (!foreignConnections[srcMac][geo.code]) {
            foreignConnections[srcMac][geo.code] = { count: 0, flag: geo.flag };
          }
          foreignConnections[srcMac][geo.code].count++;
        }
      }

      // ── Progress updates every chunk ───────────────
      if (i % CHUNK === 0 && i > 0) {
        const pct = 22 + Math.floor((i / total) * 68);
        self.postMessage({
          type: "progress",
          value: pct,
          label: `Analysing packet ${i.toLocaleString()} of ${total.toLocaleString()}...`
        });
      }
    }

    // ── ARP Alerts ─────────────────────────────────
    self.postMessage({ type: "progress", value: 90, label: "Running security checks..." });

    Object.entries(arpReplies).forEach(([mac, data]) => {
      if (data.count > 50) {
        securityAlerts.push({
          severity: "critical", icon: "🔴",
          title: `ARP Flood — ${data.count} replies`,
          detail: `MAC ${mac} sent ${data.count} ARP replies. Possible MitM attack.`,
          type: "arp_spoof",
        });
      }
      if (data.ips.size > 1) {
        securityAlerts.push({
          severity: "critical", icon: "🔴",
          title: "ARP Spoofing Confirmed",
          detail: `MAC ${mac} claiming IPs: ${[...data.ips].join(", ")}. Possible router impersonation!`,
          type: "arp_spoof",
        });
      }
    });

    if (dhcpServers.size > 1) {
      securityAlerts.push({
        severity: "critical", icon: "🔴",
        title: "Rogue DHCP Server Detected!",
        detail: `${dhcpServers.size} DHCP servers found — only one should exist. Possible network hijack!`,
        type: "rogue_dhcp",
      });
    }

    if (icmpRedirects > 0) {
      securityAlerts.push({
        severity: "critical", icon: "🔴",
        title: "ICMP Redirect Attack Detected",
        detail: `${icmpRedirects} ICMP Type 5 packets from: ${[...icmpRedirectSources].join(", ")}`,
        type: "icmp_redirect",
      });
    }

    const nxdomainRate = nxdomainCount / Math.max(Object.keys(dnsQueries).length, 1);
    if (nxdomainCount > 5) {
      securityAlerts.unshift({
        severity: nxdomainRate > 0.3 ? "critical" : "warning",
        icon: nxdomainRate > 0.3 ? "🔴" : "🟡",
        title: `${nxdomainCount} Failed DNS Lookups`,
        detail: nxdomainRate > 0.3
          ? "High NXDOMAIN rate — possible malware / DGA activity"
          : "Some DNS failures — could be misconfiguration",
        type: "dns",
      });
    }

    if (retransmissions > 50) {
      securityAlerts.push({
        severity: "warning", icon: "🟡",
        title: `${retransmissions} TCP Retransmissions`,
        detail: "High retransmissions — congestion or poor link quality",
        type: "tcp",
      });
    }

    const avgRtt = rttValues.length
      ? (rttValues.reduce((a, b) => a + b, 0) / rttValues.length * 1000).toFixed(1)
      : null;

    if (avgRtt && parseFloat(avgRtt) > 150) {
      securityAlerts.push({
        severity: "warning", icon: "🟡",
        title: `High Latency: ${avgRtt}ms average RTT`,
        detail: "Network delay detected — may affect streaming or calls",
        type: "latency",
      });
    }

    // ── v2.1: IoT alerts ──────────────────────────
    if (mqttUnencryptedDevices.size > 0) {
      securityAlerts.push({
        severity: 'critical', icon: '🔴',
        title: `Unencrypted MQTT on ${mqttUnencryptedDevices.size} device${mqttUnencryptedDevices.size > 1 ? 's' : ''}`,
        detail: 'Port 1883 (cleartext MQTT) detected. Smart home messages are visible to anyone on the network. Switch to TLS on port 8883.',
        type: 'mqtt_unencrypted',
      });
    }

    if (upnpDevices.size > 0) {
      securityAlerts.push({
        severity: 'warning', icon: '🟡',
        title: `UPnP/SSDP active — ${upnpDevices.size} device${upnpDevices.size > 1 ? 's' : ''}`,
        detail: 'UPnP lets devices automatically open router ports without your knowledge. Disable UPnP on your router unless required.',
        type: 'upnp',
      });
    }

    if (oddHoursDevices.size > 0) {
      securityAlerts.push({
        severity: 'warning', icon: '🟡',
        title: `${oddHoursDevices.size} device${oddHoursDevices.size > 1 ? 's' : ''} active at odd hours (2am–5am)`,
        detail: 'Unusual network activity detected while you were likely asleep. Verify these devices are supposed to be communicating at night.',
        type: 'odd_hours',
      });
    }

    // ── v2.1: Foreign IP alerts (one per country) ──
    const COUNTRY_NAMES = { CN: 'China', RU: 'Russia', KP: 'North Korea', IR: 'Iran' };
    const countrySummary = Object.create(null);
    for (const countryMap of Object.values(foreignConnections)) {
      for (const [code, info] of Object.entries(countryMap)) {
        if (!countrySummary[code]) countrySummary[code] = { flag: info.flag, totalCount: 0, deviceCount: 0 };
        countrySummary[code].totalCount += info.count;
        countrySummary[code].deviceCount++;
      }
    }
    for (const [code, info] of Object.entries(countrySummary)) {
      const name = COUNTRY_NAMES[code] || code;
      securityAlerts.push({
        severity: 'critical', icon: '🔴',
        title: `${info.flag} ${info.totalCount} connection${info.totalCount > 1 ? 's' : ''} to ${name}`,
        detail: `${info.deviceCount} device${info.deviceCount > 1 ? 's' : ''} on your network called ${name} servers ${info.totalCount} time${info.totalCount > 1 ? 's' : ''}. Possible IoT phone-home activity.`,
        type: 'foreign_ip',
      });
    }

    const uniqueAlerts = securityAlerts.filter(
      (a, i, arr) => arr.findIndex(b => b.title === a.title) === i
    );

    if (uniqueAlerts.length === 0) {
      uniqueAlerts.push({
        severity: "good", icon: "🟢",
        title: "No Security Issues Detected",
        detail: "Traffic looks clean based on available packet data",
        type: "clean",
      });
    }

    // ── Final assembly ──────────────────────────────
    const deviceList = Object.values(devices).map(d => ({
      ...d,
      topTraffic: getTopTraffic(d.trafficTypes),
      bandwidthMB: (d.bytes / 1024 / 1024).toFixed(2),
    })).sort((a, b) => b.packets - a.packets);

    const allSites = { ...sniSites };
    Object.values(dnsQueries).forEach(dns => {
      if (!allSites[dns.domain]) {
        allSites[dns.domain] = {
          domain: dns.domain, count: dns.count,
          failed: dns.failed, encrypted: false,
          icon: dns.icon, category: dns.category,
        };
      } else {
        allSites[dns.domain].dnsCount = dns.count;
        allSites[dns.domain].failed = dns.failed || 0;
      }
    });

    const websiteList = Object.values(allSites)
      .filter(s => s.domain.length > 3 && !s.domain.match(/^\d/))
      .sort((a, b) => b.count - a.count)
      .slice(0, 50);

    self.postMessage({ type: "progress", value: 100, label: "Done!" });

    self.postMessage({
      type: "result",
      data: {
        totalPackets: totalPacketCount,
        processedPackets: packets.length,
        sampled,
        totalMB: (totalBytes / 1024 / 1024).toFixed(2),
        fileSizeMB: (fileSize / 1024 / 1024).toFixed(1),
        avgRtt,
        retransmissions,
        devices: deviceList,
        protocols: Object.entries(protocols)
          .map(([name, value]) => ({ name, value }))
          .sort((a, b) => b.value - a.value),
        trafficTypes: Object.entries(trafficTypes)
          .map(([name, value]) => ({ name, value }))
          .sort((a, b) => b.value - a.value),
        websites: websiteList,
        security: uniqueAlerts,
        nxdomainCount,
        trackers: Object.values(trackers).sort((a, b) => b.count - a.count),
        captureStart: captureStart ? new Date(captureStart * 1000).toISOString() : null,
        captureEnd:   captureEnd   ? new Date(captureEnd   * 1000).toISOString() : null,
      }
    });

  } catch (err) {
    self.postMessage({ type: "error", message: err.message });
  }
};

// ── All helper functions ──────────────────────────────

function cleanDomain(domain) {
  return domain.replace(/^www\./, "").replace(/\.$/, "").toLowerCase().trim();
}

function getSiteIcon(domain) {
  if (domain.includes("netflix") || domain.includes("youtube")) return "📺";
  if (domain.includes("spotify"))   return "🎵";
  if (domain.includes("gmail") || domain.includes("mail")) return "📧";
  if (domain.includes("github"))    return "💻";
  if (domain.includes("google"))    return "🔍";
  if (domain.includes("facebook") || domain.includes("instagram")) return "📱";
  if (domain.includes("amazon"))    return "📦";
  if (domain.includes("apple") || domain.includes("icloud")) return "🍎";
  if (domain.includes("microsoft") || domain.includes("windows")) return "🪟";
  if (domain.includes("zoom") || domain.includes("meet") || domain.includes("teams")) return "📹";
  if (domain.includes("twitch"))    return "🎮";
  if (domain.includes("discord") || domain.includes("whatsapp") || domain.includes("telegram")) return "💬";
  return "🌐";
}

function getSiteCategory(domain) {
  if (domain.includes("netflix") || domain.includes("youtube") ||
      domain.includes("twitch") || domain.includes("spotify")) return "🎬 Entertainment";
  if (domain.includes("gmail") || domain.includes("outlook") ||
      domain.includes("mail")) return "📧 Email";
  if (domain.includes("github") || domain.includes("stackoverflow")) return "💻 Dev Tools";
  if (domain.includes("zoom") || domain.includes("meet") ||
      domain.includes("teams")) return "📹 Video Call";
  if (domain.includes("facebook") || domain.includes("instagram") ||
      domain.includes("twitter") || domain.includes("tiktok")) return "📱 Social";
  if (domain.includes("amazon") || domain.includes("flipkart")) return "🛒 Shopping";
  if (domain.includes("google") || domain.includes("bing")) return "🔍 Search";
  return "🌐 Web";
}

function getTrackerIcon(domain) {
  if (domain.includes("google"))    return "🔍";
  if (domain.includes("facebook") || domain.includes("instagram")) return "👁️";
  if (domain.includes("tiktok"))    return "🎵";
  if (domain.includes("hotjar"))    return "🔥";
  if (domain.includes("mixpanel") || domain.includes("amplitude")) return "📊";
  if (domain.includes("sentry") || domain.includes("newrelic") || domain.includes("datadog")) return "🐛";
  if (domain.includes("hubspot") || domain.includes("intercom")) return "💼";
  return "📡";
}

function getTrackerType(domain) {
  if (domain.includes("analytics") || domain.includes("mixpanel") ||
      domain.includes("amplitude") || domain.includes("segment")) return "📊 Analytics";
  if (domain.includes("doubleclick") || domain.includes("criteo") ||
      domain.includes("adservice")) return "🎯 Advertising";
  if (domain.includes("facebook") || domain.includes("instagram") ||
      domain.includes("tiktok"))    return "👁️ Social Tracking";
  if (domain.includes("sentry") || domain.includes("newrelic") ||
      domain.includes("datadog") || domain.includes("hotjar")) return "🐛 Error/Session";
  if (domain.includes("appsflyer") || domain.includes("branch") ||
      domain.includes("flurry"))    return "📱 App Tracking";
  return "📡 Telemetry";
}

function detectTrafficType(layers, srcPort, dstPort, frameLen) {
  const ports = [srcPort, dstPort];
  if (ports.some(p => [1935, 8554, 554].includes(p))) return "🎬 Streaming";
  if (layers?.tls && frameLen > 800) return "🎬 Streaming";
  if (ports.some(p => [3478, 3479, 5004, 19302].includes(p))) return "📹 Video Call";
  if (ports.some(p => [3074, 27015, 7777, 25565].includes(p))) return "🎮 Gaming";
  if (ports.some(p => [25, 587, 465, 993, 995].includes(p))) return "📧 Email";
  if (ports.some(p => [21, 22, 445, 139, 2049].includes(p))) return "📁 File Transfer";
  if (ports.some(p => [1883, 8883, 5683].includes(p))) return "🏠 Smart Home";
  if (layers?.dns)   return "🌐 Browsing";
  if (layers?.http)  return "🌐 Browsing";
  if (layers?.tls && frameLen < 200) return "💬 Chat / API";
  if (layers?.bootp) return "🔧 Network Setup";
  if (layers?.arp)   return "🔍 Discovery";
  return null;
}

function getTopTraffic(trafficTypes) {
  if (!trafficTypes || !Object.keys(trafficTypes).length) return "🔀 Mixed";
  return Object.entries(trafficTypes).sort((a, b) => b[1] - a[1])[0][0];
}

function lookupVendor(mac) {
  const prefix = mac.substring(0, 8).toUpperCase();
  const vendors = {
    "00:50:56": "VMware",    "00:0C:29": "VMware",
    "AC:DE:48": "Apple",     "00:1A:2B": "Cisco",
    "B8:27:EB": "Raspberry", "DC:A6:32": "Raspberry Pi",
    "00:E0:4C": "Realtek",   "FC:F8:AE": "Apple",
    "00:1B:63": "Apple",     "F8:0C:58": "Huawei",
    "9C:B6:D0": "Netgear",   "60:01:94": "Amazon",
    "CC:8C:BF": "Samsung",   "68:57:2D": "Apple",
    "74:58:F3": "Google",    "00:17:88": "Philips Hue",
    "18:B4:30": "Nest",      "F4:F5:D8": "Google",
    "D8:6C:63": "Amazon",    "8C:79:F0": "Samsung",
    "F0:70:4F": "Huawei",    "44:38:39": "Cumulus",
  };
  return vendors[prefix] || "Unknown Device";
}

function getDeviceIcon(vendor) {
  if (vendor.includes("Apple"))     return "🍎";
  if (vendor.includes("Samsung"))   return "📱";
  if (vendor.includes("Google"))    return "🔍";
  if (vendor.includes("Amazon"))    return "📦";
  if (vendor.includes("Cisco"))     return "🔌";
  if (vendor.includes("Netgear"))   return "📡";
  if (vendor.includes("Huawei"))    return "📶";
  if (vendor.includes("Raspberry")) return "🍓";
  if (vendor.includes("VMware"))    return "💻";
  if (vendor.includes("Philips"))   return "💡";
  if (vendor.includes("Nest"))      return "🏠";
  return "🖥️";
}

function getNickname(vendor) {
  if (vendor.includes("Apple"))     return "Apple Device";
  if (vendor.includes("Samsung"))   return "Samsung Device";
  if (vendor.includes("Google"))    return "Google Device";
  if (vendor.includes("Amazon"))    return "Amazon Device";
  if (vendor.includes("Cisco"))     return "Cisco Router";
  if (vendor.includes("Netgear"))   return "Netgear Router";
  if (vendor.includes("Huawei"))    return "Huawei Device";
  if (vendor.includes("Raspberry")) return "Raspberry Pi";
  if (vendor.includes("Nest"))      return "Smart Home Hub";
  if (vendor.includes("Philips"))   return "Smart Light";
  return "Unknown Device";
}
