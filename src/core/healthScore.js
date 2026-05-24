// healthScore.js — Network Health Score Calculator
// Returns 0-100 score + grade + recommendations

export function calculateHealthScore(data) {
  let score = 100;
  const issues = [];
  const recommendations = [];

  // ── Security deductions ──────────────────────────
  const criticals = data.security.filter(
    a => a.severity === 'critical' && a.type !== 'clean'
  );
  const warnings = data.security.filter(
    a => a.severity === 'warning'
  );

  score -= criticals.length * 15;
  score -= warnings.length * 5;

  if (criticals.length > 0) {
    issues.push(`${criticals.length} critical security threat${criticals.length > 1 ? 's' : ''}`);
    recommendations.push('Address critical security alerts immediately');
  }

  // ── Encryption check ─────────────────────────────
  const httpSites = data.websites?.filter(w => !w.encrypted).length || 0;
  const totalSites = data.websites?.length || 1;
  const encryptionRate = 1 - (httpSites / totalSites);

  if (encryptionRate < 0.7) {
    score -= 10;
    issues.push(`${httpSites} unencrypted HTTP sites visited`);
    recommendations.push('Avoid HTTP sites — use HTTPS everywhere');
  }

  // ── Tracker load ─────────────────────────────────
  const trackerCount = data.trackers?.length || 0;
  if (trackerCount > 10) {
    score -= 8;
    issues.push(`${trackerCount} ad trackers detected`);
    recommendations.push('Consider a DNS-level ad blocker like Pi-hole');
  } else if (trackerCount > 5) {
    score -= 4;
  }

  // ── TCP health ───────────────────────────────────
  if (data.retransmissions > 100) {
    score -= 8;
    issues.push('High TCP retransmissions — poor connection quality');
    recommendations.push('Check ethernet cables or WiFi interference');
  } else if (data.retransmissions > 50) {
    score -= 4;
  }

  // ── Latency ──────────────────────────────────────
  if (data.avgRtt && parseFloat(data.avgRtt) > 150) {
    score -= 6;
    issues.push(`High latency: ${data.avgRtt}ms average`);
    recommendations.push('Move router closer or upgrade to WiFi 6');
  }

  // ── Unknown devices ──────────────────────────────
  const unknownDevices = data.devices?.filter(
    d => d.vendor === 'Unknown Device'
  ).length || 0;
  const totalDevices = data.devices?.length || 1;
  const unknownRate = unknownDevices / totalDevices;

  if (unknownRate > 0.5) {
    score -= 8;
    issues.push(`${unknownDevices} unidentified devices`);
    recommendations.push('Audit unknown devices — consider MAC filtering');
  } else if (unknownRate > 0.3) {
    score -= 4;
  }

  // ── DNS health ───────────────────────────────────
  if (data.nxdomainCount > 10) {
    score -= 6;
    issues.push('High DNS failure rate — possible malware');
    recommendations.push('Run malware scan on devices with high NXDOMAIN rate');
  }

  // ── IoT unencrypted MQTT ─────────────────────────
  const mqttAlert = data.security?.find(a => a.type === 'mqtt_unencrypted');
  if (mqttAlert) {
    score -= 10;
    issues.push('IoT devices using unencrypted MQTT');
    recommendations.push('Enable TLS on your MQTT broker (port 8883)');
  }

  // ── Foreign IPs ──────────────────────────────────
  const foreignAlert = data.security?.find(a => a.type === 'foreign_ip');
  if (foreignAlert) {
    score -= 8;
    issues.push('Devices connecting to foreign/unusual IPs');
    recommendations.push('Review which devices are calling foreign servers');
  }

  // ── Cap score ────────────────────────────────────
  score = Math.max(0, Math.min(100, score));

  // ── Default recommendations ──────────────────────
  if (recommendations.length === 0) {
    recommendations.push('Network looks healthy — keep monitoring regularly');
    recommendations.push('Consider putting IoT devices on a guest network');
  }

  return {
    score: Math.round(score),
    grade: getGrade(score),
    color: getColor(score),
    issues,
    recommendations,
    summary: getSummary(score),
  };
}

function getGrade(score) {
  if (score >= 90) return 'A';
  if (score >= 80) return 'B';
  if (score >= 70) return 'C';
  if (score >= 60) return 'D';
  return 'F';
}

function getColor(score) {
  if (score >= 80) return 'text-green-400';
  if (score >= 60) return 'text-yellow-400';
  return 'text-red-400';
}

function getSummary(score) {
  if (score >= 90) return 'Excellent — Network is well secured';
  if (score >= 80) return 'Good — Minor issues to address';
  if (score >= 70) return 'Fair — Some attention needed';
  if (score >= 60) return 'Poor — Several issues detected';
  return 'Critical — Immediate action required';
}
