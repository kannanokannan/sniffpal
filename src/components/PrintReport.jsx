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
    page:    { fontFamily: 'Arial, sans-serif', fontSize: 12, color: '#111', background: '#fff', padding: '32px 40px', maxWidth: 900, margin: '0 auto' },
    header:  { borderBottom: '3px solid #0ea5e9', paddingBottom: 16, marginBottom: 24 },
    title:   { fontSize: 26, fontWeight: 700, color: '#0369a1', margin: 0 },
    sub:     { fontSize: 12, color: '#64748b', margin: '4px 0 0' },
    section: { marginBottom: 28 },
    h2:      { fontSize: 15, fontWeight: 700, color: '#0f172a', borderBottom: '1px solid #e2e8f0', paddingBottom: 6, marginBottom: 12 },
    grid2:   { display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 },
    grid3:   { display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 12 },
    card:    { background: '#f8fafc', border: '1px solid #e2e8f0', borderRadius: 6, padding: '10px 14px' },
    cardVal: { fontSize: 22, fontWeight: 700, color: '#0369a1' },
    cardLbl: { fontSize: 11, color: '#64748b', marginTop: 2 },
    alertC:  { background: '#fff1f2', border: '1px solid #fecaca', borderRadius: 6, padding: '8px 12px', marginBottom: 6 },
    alertW:  { background: '#fffbeb', border: '1px solid #fde68a', borderRadius: 6, padding: '8px 12px', marginBottom: 6 },
    alertG:  { background: '#f0fdf4', border: '1px solid #bbf7d0', borderRadius: 6, padding: '8px 12px', marginBottom: 6 },
    alertTitle: { fontWeight: 600, fontSize: 12 },
    alertDetail: { fontSize: 11, color: '#475569', marginTop: 2 },
    table:   { width: '100%', borderCollapse: 'collapse', fontSize: 11 },
    th:      { background: '#f1f5f9', padding: '6px 8px', textAlign: 'left', fontWeight: 600, borderBottom: '1px solid #cbd5e1' },
    td:      { padding: '5px 8px', borderBottom: '1px solid #f1f5f9', verticalAlign: 'top' },
    rec:     { fontSize: 12, padding: '4px 0', borderBottom: '1px solid #f1f5f9' },
    footer:  { marginTop: 32, paddingTop: 12, borderTop: '1px solid #e2e8f0', fontSize: 10, color: '#94a3b8', textAlign: 'center' },
  };

  const scoreColor = healthScore
    ? (healthScore.score >= 80 ? '#16a34a' : healthScore.score >= 60 ? '#d97706' : '#dc2626')
    : '#64748b';

  return (
    <div style={s.page}>
      {/* Header */}
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

      {/* Network Summary */}
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

      {/* Security Findings */}
      <div style={s.section}>
        <h2 style={s.h2}>Security Findings ({data.security?.length ?? 0})</h2>
        {data.security?.map((alert, i) => (
          <div key={i} style={alert.severity === 'critical' ? s.alertC : alert.severity === 'warning' ? s.alertW : s.alertG}>
            <div style={s.alertTitle}>{alert.icon} {alert.title}</div>
            <div style={s.alertDetail}>{alert.detail}</div>
          </div>
        ))}
      </div>

      {/* Device Inventory */}
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
              <th style={s.th}>Packets</th>
              <th style={s.th}>Traffic (MB)</th>
              <th style={s.th}>Top Activity</th>
            </tr>
          </thead>
          <tbody>
            {data.devices?.slice(0, 50).map((d, i) => (
              <tr key={d.mac} style={{ background: i % 2 === 0 ? '#fff' : '#f8fafc' }}>
                <td style={s.td}>{i + 1}</td>
                <td style={{ ...s.td, fontFamily: 'monospace', fontSize: 10 }}>{d.mac}</td>
                <td style={s.td}>{d.ip || '—'}</td>
                <td style={s.td}>{d.vendor}</td>
                <td style={s.td}>{d.hostname || '—'}</td>
                <td style={s.td}>{d.packets?.toLocaleString()}</td>
                <td style={s.td}>{d.bandwidthMB}</td>
                <td style={s.td}>{d.topTraffic}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {data.devices?.length > 50 && (
          <p style={{ fontSize: 10, color: '#94a3b8', marginTop: 6 }}>
            Showing top 50 of {data.devices.length} devices.
          </p>
        )}
      </div>

      {/* Recommendations */}
      {healthScore?.recommendations?.length > 0 && (
        <div style={s.section}>
          <h2 style={s.h2}>Recommendations</h2>
          {healthScore.recommendations.map((rec, i) => (
            <div key={i} style={s.rec}>• {rec}</div>
          ))}
        </div>
      )}

      {/* Footer */}
      <div style={s.footer}>
        SniffPal v2.1 — Local Network Intelligence · No data ever leaves your browser ·
        github.com/kannanokannan/sniffpal
      </div>
    </div>
  );
}
