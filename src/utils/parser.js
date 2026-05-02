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

export function parseWiresharkJSON(jsonData) {
  const packets = Array.isArray(jsonData) ? jsonData : [];
  const devices = {};
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

  packets.forEach((pkt) => {
    const layers = pkt?._source?.layers || {};
    const frameLen = parseInt(layers?.frame?.["frame.len"] || 0);
    totalBytes += frameLen;

    // ── DNS Analysis ─────────────────────────────────
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

    // ── SNI (HTTPS Websites) ──────────────────────────
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

    // ── Tracker / Advertiser Detection ───────────────
    const domainToCheck = sni || layers?.dns?.["dns.qry.name"] || "";
    if (domainToCheck) {
      const matched = TRACKER_DOMAINS.find(t => domainToCheck.includes(t));
      if (matched) {
        if (!trackers[matched]) {
          trackers[matched] = {
            domain: matched,
            count: 0,
            icon: getTrackerIcon(matched),
            type: getTrackerType(matched),
          };
        }
        trackers[matched].count++;
      }
    }

    // ── HTTP (Cleartext) ──────────────────────────────
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
        uri.includes("cmd.exe") ||
        uri.includes("eval(") ||
        uri.includes("../") ||
        uri.includes("select%20") ||
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

    // ── FTP Cleartext ─────────────────────────────────
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

    // ── ARP Spoofing Detection ────────────────────────
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

    // ── Rogue DHCP Detection ──────────────────────────
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

    // ── ICMP Redirect Detection ───────────────────────
    if (layers?.icmp) {
      const icmpType = layers.icmp?.["icmp.type"];
      if (icmpType === "5") {
        icmpRedirects++;
        const fromIp = layers?.ip?.["ip.src"] || "unknown";
        icmpRedirectSources.add(fromIp);
      }
    }

    // ── TCP Health ────────────────────────────────────
    if (layers?.tcp) {
      if (layers.tcp?.["tcp.analysis.retransmission"] ||
          layers.tcp?.["tcp.analysis.fast_retransmission"]) {
        retransmissions++;
      }
      const rtt = parseFloat(layers.tcp?.["tcp.analysis.ack_rtt"] || 0);
      if (rtt > 0) rttValues.push(rtt);
    }

    // ── Protocol detection ────────────────────────────
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

    // ── Traffic type ──────────────────────────────────
    const srcPort = parseInt(layers?.tcp?.["tcp.srcport"] || layers?.udp?.["udp.srcport"] || 0);
    const dstPort = parseInt(layers?.tcp?.["tcp.dstport"] || layers?.udp?.["udp.dstport"] || 0);
    const trafficType = detectTrafficType(layers, srcPort, dstPort, frameLen);
    if (trafficType) {
      trafficTypes[trafficType] = (trafficTypes[trafficType] || 0) + 1;
    }

    // ── Device tracking ───────────────────────────────
    const srcMac = layers?.eth?.["eth.src"] || null;
    const dstMac = layers?.eth?.["eth.dst"] || null;
    const srcIp = layers?.ip?.["ip.src"] || layers?.ipv6?.["ipv6.src"] || null;
    const dstIp = layers?.ip?.["ip.dst"] || layers?.ipv6?.["ipv6.dst"] || null;
    const hostname = layers?.bootp?.["bootp.option.hostname"] || layers?.dhcp?.["dhcp.option.hostname"] || null;

    [srcMac, dstMac].forEach((mac, idx) => {
      if (!mac || mac.startsWith("ff:ff") || mac.startsWith("33:33") || mac.startsWith("01:00")) return;
      if (!devices[mac]) {
        const vendor = lookupVendor(mac);
        devices[mac] = {
          mac, packets: 0, bytes: 0,
          vendor,
          icon: getDeviceIcon(vendor),
          nickname: getNickname(vendor),
          ip: null, hostname: null,
          trafficTypes: {},
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
  });

  // ── ARP Spoofing Alerts ───────────────────────────
  Object.entries(arpReplies).forEach(([mac, data]) => {
    if (data.count > 50) {
      securityAlerts.push({
        severity: "critical", icon: "🔴",
        title: `ARP Flood — ${data.count} replies from one device`,
        detail: `MAC ${mac} sent ${data.count} ARP replies. Possible ARP spoofing / MitM attack.`,
        type: "arp_spoof",
      });
    }
    if (data.ips.size > 1) {
      securityAlerts.push({
        severity: "critical", icon: "🔴",
        title: "ARP Spoofing Confirmed",
        detail: `MAC ${mac} claiming ${data.ips.size} IPs: ${[...data.ips].join(", ")}. Attacker may be impersonating your router!`,
        type: "arp_spoof",
      });
    }
  });

  // ── Rogue DHCP Alert ─────────────────────────────
  if (dhcpServers.size > 1) {
    const servers = [...dhcpServers].map(s => s.split("|")[0]).join(", ");
    securityAlerts.push({
      severity: "critical", icon: "🔴",
      title: "Rogue DHCP Server Detected!",
      detail: `${dhcpServers.size} DHCP servers: ${servers}. Only one should exist — possible network hijack!`,
      type: "rogue_dhcp",
    });
  }

  // ── ICMP Redirect Alert ───────────────────────────
  if (icmpRedirects > 0) {
    securityAlerts.push({
      severity: "critical", icon: "🔴",
      title: "ICMP Redirect Attack Detected",
      detail: `${icmpRedirects} ICMP Type 5 packets from: ${[...icmpRedirectSources].join(", ")}. Someone is rerouting your traffic!`,
      type: "icmp_redirect",
    });
  }

  // ── DNS Aggregate Alerts ──────────────────────────
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
      detail: "High retransmissions indicate congestion or poor link quality",
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

  // ── Deduplicate alerts ────────────────────────────
  const uniqueAlerts = securityAlerts.filter(
    (alert, idx, arr) => arr.findIndex(a => a.title === alert.title) === idx
  );

  if (uniqueAlerts.length === 0) {
    uniqueAlerts.push({
      severity: "good", icon: "🟢",
      title: "No Security Issues Detected",
      detail: "Traffic looks clean based on available packet data",
      type: "clean",
    });
  }

  // ── Final device list ─────────────────────────────
  const deviceList = Object.values(devices).map((d) => ({
    ...d,
    topTraffic: getTopTraffic(d.trafficTypes),
    bandwidthMB: (d.bytes / 1024 / 1024).toFixed(2),
  })).sort((a, b) => b.packets - a.packets);

  // ── Merge websites ────────────────────────────────
  const allSites = { ...sniSites };
  Object.values(dnsQueries).forEach((dns) => {
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

  return {
    totalPackets: packets.length,
    totalMB: (totalBytes / 1024 / 1024).toFixed(2),
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
  };
}

// ── Helpers ───────────────────────────────────────────
function cleanDomain(domain) {
  return domain.replace(/^www\./, "").replace(/\.$/, "").toLowerCase().trim();
}

function getSiteIcon(domain) {
  if (domain.includes("netflix"))   return "📺";
  if (domain.includes("youtube"))   return "📺";
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
  if (domain.includes("discord"))   return "💬";
  if (domain.includes("whatsapp") || domain.includes("telegram")) return "💬";
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
  if (domain.includes("sentry") || domain.includes("newrelic") ||
      domain.includes("datadog"))   return "🐛";
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
