export default function PrintReport({ data, healthScore, fileName }) {
  if (!data) return null;

  const generated = new Date().toLocaleString();
  const capStart = data.captureStart
    ? new Date(data.captureStart).toLocaleString() : null;
  const capEnd = data.captureEnd
    ? new Date(data.captureEnd).toLocaleString() : null;

  const criticals = data.security?.filter(a => a.severity === 'critical' && a.type !== 'clean') || [];
  const warnings  = data.security?.filter(a => a.severity === 'warning') || [];

  const s = {
    page:       { fontFamily: 'Arial, sans-serif', fontSize: 12, color: '#111', background: '#fff', padding: '32px 40px', maxWidth: 900, margin: '0 auto' },
    header:     { borderBottom: '3px solid #0ea5e9', paddingBottom: 16, marginBottom: 24 },
    title:      { fontSize: 26, fontWeight: 700, color: '#0369a1', margin: 0 },
    sub:        { fontSize: 12, color: '#64748b', margin: '4px 0 0' },
    section:    { marginBottom: 28 },
    h2:         { fontSize: 15, fontWeight: 700, color: '#0f172a', borderBottom: '1px solid #e2e8f0', paddingBottom: 6, marginBottom: 12 },
    grid2:      { display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 },
    grid3:      { display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 12 },
    card:       { background: '#f8fafc', border: '1px solid #e2e8f0', borderRadius: 6, padding: '10px 14px' },
    cardVal:    { fontSize: 22, fontWeight: 700, color: '#0369a1' },
    cardLbl:    { fontSize: 11, color: '#64748b', marginTop: 2 },
    alertC:     { background: '#fff1f2', border: '1px solid #fecaca', borderRadius: 6, padding: '8px 12px', marginBottom: 6 },
    alertW:     { background: '#fffbeb', border: '1px solid #fde68a', borderRadius: 6, padding: '8px 12px', marginBottom: 6 },
    alertG:     { background: '#f0fdf4', border: '1px solid #bbf7d0', borderRadius: 6, padding: '8px 12px', marginBottom: 6 },
    alertTitle: { fontWeight: 600, fontSize: 12 },
    alertDetail:{ fontSize: 11, color: '#475569', marginTop: 2 },
    alertId:    { fontSize: 10, fontFamily: 'monospace', color: '#7c3aed', marginRight: 6 },
    table:      { width: '100%', borderCollapse: 'collapse', fontSize: 11 },
    th:         { background: '#f1f5f9', padding: '6px 8px', textAlign: 'left', fontWeight: 600, borderBottom: '1px solid #cbd5e1' },
    td:         { padding: '5px 8px', borderBottom: '1px solid #f1f5f9', verticalAlign: 'top' },
    rec:        { fontSize: 12, padding: '4px 0', borderBottom: '1px solid #f1f5f9' },
    badge:      { display: 'inline-block', fontSize: 9, padding: '1px 5px', borderRadius: 9999, background: '#ede9fe', color: '#6d28d9', marginRight: 3, marginBottom: 2 },
    footer:     { marginTop: 32, paddingTop: 12, borderTop: '1px solid #e2e8f0', fontSize: 10, color: '#94a3b8', textAlign: 'center' },
    aiBox:      { background: '#f8fafc', border: '1px solid #e2e8f0', borderRadius: 6, padding: '16px 20px', textAlign: 'center', color: '#94a3b8' },
    trafficBar: { display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 },
    trafficLbl: { fontSize: 11, width: 160, flexShrink: 0 },
    trafficTrack: { flex: 1, background: '#e2e8f0', borderRadius: 9999, height: 10 },
    trafficFill: { background: '#0ea5e9', borderRadius: 9999, height: 10 },
    trafficVal: { fontSize: 11, color: '#64748b', width: 40, textAlign: 'right' },
  };

  const scoreColor = healthScore
    ? (healthScore.score >= 80 ? '#16a34a' : healthScore.score >= 60 ? '#d97706' : '#dc2626')
    : '#64748b';

  // Traffic type totals for bar chart
  const trafficTotal = (data.trafficTypes || []).reduce((sum, t) => sum + t.value, 0) || 1;

  return (
    <div style={s.page}>

      {/* ── Header ──────────────────────────────────────────────────────── */}
      <div style={s.header}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
          <div>
            <h1 style={s.title}>📡 SniffPal Network Security Report</h1>
            <p style={s.sub}>
              {fileName && <><strong>File:</strong> {fileName} · </>}
              {capStart && <><strong>Capture:</strong> {capStart}{capEnd && capEnd !== capStart ? ` → ${capEnd}` : ''} · </>}
              <strong>Generated:</strong> {generated}
            </p>
          </div>
          {healthScore && (
            <div style={{ textAlign: 'right' }}>
              <div style={{ fontSize: 36, fontWeight: 800, color: scoreColor, lineHeight: 1 }}>{healthScore.grade}</div>
              <div style={{ fontSize: 12, color: scoreColor, fontWeight: 600 }}>{healthScore.score}/100</div>
              <div style={{ fontSize: 10, color: '#64748b' }}>Health Score</div>
            </div>
          )}
        </div>
      </div>

      {/* ── Network Summary ──────────────────────────────────────────────── */}
      <div style={s.section}>
        <h2 style={s.h2}>Network Summary</h2>
        <div style={s.grid3}>
          <div style={s.card}>
            <div style={s.cardVal}>{data.devices?.length ?? 0}</div>
            <div style={s.cardLbl}>Devices Detected</div>
          </div>
          <div style={s.card}>
            <div style={s.cardVal}>{data.totalPackets?.toLocaleString() ?? 0}</div>
            <div style={s.cardLbl}>Total Packets{data.sampled ? ' (sampled)' : ''}</div>
          </div>
          <div style={s.card}>
            <div style={s.cardVal}>{data.totalMB} MB</div>
            <div style={s.cardLbl}>Total Traffic</div>
          </div>
          <div style={s.card}>
            <div style={s.cardVal}>{criticals.length}</div>
            <div style={{ ...s.cardLbl, color: criticals.length > 0 ? '#dc2626' : '#16a34a' }}>Critical Alerts</div>
          </div>
          <div style={s.card}>
            <div style={s.cardVal}>{data.trackers?.length ?? 0}</div>
            <div style={s.cardLbl}>Ad Trackers Found</div>
          </div>
          <div style={s.card}>
            <div style={s.cardVal}>{data.avgRtt ? `${data.avgRtt}ms` : 'N/A'}</div>
            <div style={s.cardLbl}>Avg Latency (RTT)</div>
          </div>
        </div>
        {healthScore && (
          <div style={{ marginTop: 12, padding: '10px 14px', background: '#f0f9ff', border: '1px solid #bae6fd', borderRadius: 6 }}>
            <strong>Assessment:</strong> {healthScore.summary}
          </div>
        )}
      </div>

      {/* ── Traffic Breakdown ────────────────────────────────────────────── */}
      {data.trafficTypes && data.trafficTypes.length > 0 && (
        <div style={s.section}>
          <h2 style={s.h2}>Traffic Breakdown</h2>
          {data.trafficTypes.slice(0, 8).map((t, i) => (
            <div key={i} style={s.trafficBar}>
              <span style={s.trafficLbl}>{t.name}</span>
              <div style={s.trafficTrack}>
                <div style={{ ...s.trafficFill, width: `${Math.round((t.value / trafficTotal) * 100)}%` }} />
              </div>
              <span style={s.trafficVal}>{t.value.toLocaleString()}</span>
            </div>
          ))}
          {data.protocols && data.protocols.length > 0 && (
            <div style={{ marginTop: 12 }}>
              <div style={{ fontSize: 11, color: '#64748b', marginBottom: 6, fontWeight: 600 }}>Protocol Distribution</div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                {data.protocols.map((p, i) => (
                  <span key={i} style={{ ...s.badge, background: '#e0f2fe', color: '#0369a1', fontSize: 11 }}>
                    {p.name}: {p.value.toLocaleString()}
                  </span>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* ── Security Findings (legacy alerts) ───────────────────────────── */}
      <div style={s.section}>
        <h2 style={s.h2}>Security Findings ({data.security?.length ?? 0})</h2>
        {data.security?.map((alert, i) => (
          <div key={i} style={alert.severity === 'critical' ? s.alertC : alert.severity === 'warning' ? s.alertW : s.alertG}>
            <div style={s.alertTitle}>
              {alert.icon} {alert.title}
            </div>
            <div style={s.alertDetail}>{alert.detail}</div>
          </div>
        ))}
      </div>

      {/* ── Privacy & IoT Findings (structured, with IDs) ────────────────── */}
      {data.findings && data.findings.length > 0 && (
        <div style={s.section}>
          <h2 style={s.h2}>Privacy & IoT Findings ({data.findings.length})</h2>
          {data.findings.map((f, i) => (
            <div key={i} style={f.severity === 'critical' ? s.alertC : f.severity === 'warning' ? s.alertW : s.alertG}>
              <div style={s.alertTitle}>
                <span style={s.alertId}>{f.id}</span>
                {f.title}
              </div>
              <div style={s.alertDetail}>{f.description}</div>
              {f.fix && (
                <div style={{ fontSize: 10, color: '#0369a1', marginTop: 3 }}>
                  ✓ Fix: {f.fix}
                </div>
              )}
            </div>
          ))}
        </div>
      )}

      {/* ── Device Inventory — ALL devices, no cap ───────────────────────── */}
      <div style={s.section}>
        <h2 style={s.h2}>Device Inventory ({data.devices?.length ?? 0} devices)</h2>
        <table style={s.table}>
          <thead>
            <tr>
              <th style={s.th}>#</th>
              <th style={s.th}>MAC Address</th>
              <th style={s.th}>IP Address</th>
              <th style={s.th}>Vendor / Name</th>
              <th style={s.th}>Hostname</th>
              <th style={s.th}>Protocols</th>
              <th style={s.th}>Packets</th>
              <th style={s.th}>Traffic (MB)</th>
              <th style={s.th}>Top Activity</th>
            </tr>
          </thead>
          <tbody>
            {data.devices?.map((d, i) => (
              <tr key={d.mac} style={{ background: i % 2 === 0 ? '#fff' : '#f8fafc' }}>
                <td style={s.td}>{i + 1}</td>
                <td style={{ ...s.td, fontFamily: 'monospace', fontSize: 10 }}>{d.mac}</td>
                <td style={s.td}>{d.ip || '—'}</td>
                <td style={s.td}>
                  {d.enriched?.deviceName || d.hostname || d.vendor}
                  {d.enriched?.manufacturer && d.enriched.manufacturer !== d.vendor && (
                    <div style={{ fontSize: 10, color: '#64748b' }}>{d.enriched.manufacturer}{d.enriched.model ? ` · ${d.enriched.model}` : ''}</div>
                  )}
                </td>
                <td style={s.td}>{d.hostname || '—'}</td>
                <td style={s.td}>
                  {d.enriched?.enrichmentSource?.map(src => (
                    <span key={src} style={s.badge}>{src}</span>
                  ))}
                </td>
                <td style={s.td}>{d.packets?.toLocaleString()}</td>
                <td style={s.td}>{d.bandwidthMB}</td>
                <td style={s.td}>{d.topTraffic}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* ── Recommendations ──────────────────────────────────────────────── */}
      {healthScore?.recommendations?.length > 0 && (
        <div style={s.section}>
          <h2 style={s.h2}>Recommendations</h2>
          {healthScore.recommendations.map((rec, i) => (
            <div key={i} style={s.rec}>• {rec}</div>
          ))}
        </div>
      )}

      {/* ── AI Insights placeholder ──────────────────────────────────────── */}
      <div style={s.section}>
        <h2 style={s.h2}>AI Insights</h2>
        <div style={s.aiBox}>
          <div style={{ fontSize: 20, marginBottom: 6 }}>🤖</div>
          <div style={{ fontWeight: 600, fontSize: 13, marginBottom: 4 }}>AI Insights — available in the web app</div>
          <div style={{ fontSize: 11 }}>
            Plain-English explanations of every finding, powered by Gemini Nano (Chrome) or SmolLM2.<br />
            Visit{' '}
            <span style={{ color: '#0369a1' }}>kannanokannan.github.io/sniffpal</span>
            {' '}to view AI-generated insights for this capture.
          </div>
        </div>
      </div>

      {/* ── Footer ──────────────────────────────────────────────────────── */}
      <div style={s.footer}>
        SniffPal v2.1 — Local Network Intelligence · No data ever leaves your browser ·
        github.com/kannanokannan/sniffpal
      </div>

    </div>
  );
}
