function RiskBadge({ level }) {
  const styles = {
    good: 'bg-green-900/40 text-green-300 border-green-800/50',
    caution: 'bg-yellow-900/40 text-yellow-300 border-yellow-800/50',
    high: 'bg-red-900/40 text-red-300 border-red-800/50',
  };
  const label = level === 'high' ? 'High Risk' : level === 'caution' ? 'Caution' : 'Good';
  return (
    <span className={`text-xs px-2.5 py-1 rounded-full border ${styles[level] || styles.good}`}>
      {label}
    </span>
  );
}

function Stat({ label, value, tone = 'slate' }) {
  const tones = {
    green: 'text-green-300',
    yellow: 'text-yellow-300',
    red: 'text-red-300',
    cyan: 'text-cyan-300',
    slate: 'text-white',
  };
  return (
    <div className="bg-slate-950/50 border border-white/5 rounded-xl p-4">
      <p className={`text-2xl font-bold ${tones[tone] || tones.slate}`}>{value}</p>
      <p className="text-slate-500 text-xs mt-1">{label}</p>
    </div>
  );
}

function Section({ title, children }) {
  return (
    <section className="space-y-3">
      <h3 className="text-white text-sm font-semibold">{title}</h3>
      {children}
    </section>
  );
}

export default function GuestWifiReport({ report, onClose }) {
  if (!report) return null;

  const hasSensitiveLeak = report.personalData?.status === 'risk';
  const visibleDomains = report.domains?.top || [];
  const vendors = report.captivePortal?.vendors || [];

  return (
    <div className="fixed inset-0 z-50 flex justify-end bg-slate-950/70 backdrop-blur-sm print:hidden">
      <button
        type="button"
        className="absolute inset-0 cursor-default"
        onClick={onClose}
        aria-label="Close guest WiFi report"
      />
      <aside className="relative w-full max-w-3xl h-full overflow-y-auto bg-slate-950 border-l border-white/10 shadow-2xl">
        <div className="sticky top-0 z-10 bg-slate-950/95 backdrop-blur border-b border-white/10 px-6 py-5">
          <div className="flex items-start justify-between gap-4">
            <div>
              <div className="flex items-center gap-3 mb-2">
                <h2 className="text-xl font-semibold text-white">Guest WiFi Privacy Report</h2>
                <RiskBadge level={report.riskLevel} />
              </div>
              <p className="text-slate-400 text-sm">
                A focused check for captive portals, visible domains, cleartext personal data, and shared-LAN exposure.
              </p>
            </div>
            <button
              type="button"
              onClick={onClose}
              className="text-slate-500 hover:text-white border border-white/10 rounded-lg px-3 py-1.5 text-sm"
            >
              Close
            </button>
          </div>
        </div>

        <div className="p-6 space-y-7">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            <Stat
              label="Personal data"
              value={hasSensitiveLeak ? 'Check' : 'Clean'}
              tone={hasSensitiveLeak ? 'red' : 'green'}
            />
            <Stat label="Visible domains" value={report.domains?.visibleCount || 0} tone="cyan" />
            <Stat label="Clear HTTP" value={report.http?.total || 0} tone={report.http?.total ? 'yellow' : 'green'} />
            <Stat label="Discovery packets" value={report.sharedLan?.total || 0} tone={report.sharedLan?.total ? 'yellow' : 'green'} />
          </div>

          <Section title="Summary">
            <div className="bg-slate-900/60 border border-white/5 rounded-xl p-4 space-y-2">
              {(report.reasons || []).map(reason => (
                <p key={reason} className="text-slate-300 text-sm">- {reason}</p>
              ))}
              {(!report.reasons || report.reasons.length === 0) && (
                <p className="text-slate-400 text-sm">No strong guest-network signals were detected.</p>
              )}
            </div>
          </Section>

          <Section title="Personal Data Check">
            <div className={`rounded-xl p-4 border ${hasSensitiveLeak ? 'bg-red-900/20 border-red-800/40' : 'bg-green-900/20 border-green-800/40'}`}>
              <p className={hasSensitiveLeak ? 'text-red-200 text-sm' : 'text-green-200 text-sm'}>
                {report.personalData?.summary}
              </p>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mt-4 text-xs">
                <div><p className="text-slate-500">POST forms</p><p className="text-white font-mono">{report.personalData?.cleartextPostCount || 0}</p></div>
                <div><p className="text-slate-500">Cookies</p><p className="text-white font-mono">{report.personalData?.cookieCount || 0}</p></div>
                <div><p className="text-slate-500">Auth headers</p><p className="text-white font-mono">{report.personalData?.authHeaderCount || 0}</p></div>
                <div><p className="text-slate-500">Sensitive hints</p><p className="text-white font-mono">{report.personalData?.sensitiveHintCount || 0}</p></div>
              </div>
            </div>
          </Section>

          <Section title="Captive Portal">
            {vendors.length > 0 ? (
              <div className="space-y-2">
                {vendors.map(v => (
                  <div key={v.vendor} className="bg-slate-900/60 border border-white/5 rounded-xl p-4">
                    <p className="text-white text-sm font-medium">{v.vendor}</p>
                    <p className="text-slate-500 text-xs mt-1">
                      Evidence seen {v.count} time{v.count === 1 ? '' : 's'} via {v.sources?.join(', ') || 'capture data'}.
                    </p>
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-slate-500 text-sm bg-slate-900/50 rounded-xl p-4 border border-white/5">
                No captive portal vendor string was identified.
              </p>
            )}
          </Section>

          <Section title="Domain Visibility">
            <p className="text-slate-400 text-sm">
              HTTPS protects page contents, but DNS and TLS metadata can still reveal which services were contacted.
            </p>
            <div className="bg-slate-900/60 border border-white/5 rounded-xl divide-y divide-white/5">
              {visibleDomains.slice(0, 12).map(d => (
                <div key={d.name} className="flex items-center justify-between px-4 py-2.5">
                  <span className="text-slate-300 text-sm truncate pr-3">{d.name}</span>
                  <span className="text-slate-500 text-xs font-mono">{d.count}</span>
                </div>
              ))}
              {visibleDomains.length === 0 && (
                <p className="text-slate-500 text-sm p-4">No domain metadata was collected.</p>
              )}
            </div>
          </Section>

          <Section title="Shared LAN Exposure">
            <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
              <Stat label="SSDP" value={report.sharedLan?.ssdp || 0} />
              <Stat label="mDNS" value={report.sharedLan?.mdns || 0} />
              <Stat label="LLMNR" value={report.sharedLan?.llmnr || 0} />
              <Stat label="NetBIOS" value={report.sharedLan?.netbios || 0} />
              <Stat label="WPAD" value={report.wpad?.count || 0} tone={report.wpad?.detected ? 'yellow' : 'green'} />
            </div>
            {report.wpad?.detected && (
              <p className="text-yellow-300 text-sm bg-yellow-900/20 border border-yellow-800/40 rounded-xl p-4">
                WPAD was visible. On guest networks this can help attackers steer devices toward a malicious proxy if other protections fail.
              </p>
            )}
          </Section>

          <Section title="Recommendations">
            <div className="space-y-2">
              {(report.recommendations || []).map(item => (
                <p key={item} className="text-slate-300 text-sm bg-slate-900/50 border border-white/5 rounded-xl px-4 py-3">
                  {item}
                </p>
              ))}
            </div>
          </Section>
        </div>
      </aside>
    </div>
  );
}
