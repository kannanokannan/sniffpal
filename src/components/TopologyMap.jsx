import { useState } from 'react';

// ── Band colour palette ───────────────────────────────────────────────────────
const BAND_COLORS = {
  '2.4 GHz': { ring: '#22c55e', line: '#22c55e', label: '2.4 GHz' },
  '5 GHz':   { ring: '#3b82f6', line: '#3b82f6', label: '5 GHz' },
  '6 GHz':   { ring: '#a855f7', line: '#a855f7', label: '6 GHz' },
  unknown:   { ring: '#64748b', line: '#64748b', label: 'Unknown', dashed: true },
};
const getBand = band => BAND_COLORS[band] || BAND_COLORS.unknown;

// ── Router detection — IP ending in .1, fallback: lowest IP numerically ──────
function detectRouter(devices) {
  const gw = devices.find(d => d.ip?.endsWith('.1'));
  if (gw) return gw;
  const toNum = ip => ip?.split('.').reduce((n, o) => n * 256 + +o, 0) ?? 999999;
  return [...devices].sort((a, b) => toNum(a.ip) - toNum(b.ip))[0] || devices[0];
}

// ── Device clustering ─────────────────────────────────────────────────────────
const CLUSTER_DEFS = [
  {
    name: 'IoT',
    match: d =>
      ['Amazon', 'Google Home', 'Philips', 'Nest', 'Sonos', 'Ring', 'Lifx', 'Tuya']
        .some(t => (d.vendor || '').includes(t)) ||
      ['smart_bulb', 'smart_speaker', 'smart_home', 'streaming_device', 'doorbell'].includes(d.type),
  },
  {
    name: 'Mobile',
    match: d =>
      ['Apple', 'Samsung', 'OnePlus', 'Xiaomi', 'Realme', 'OPPO', 'Vivo']
        .some(t => (d.vendor || '').includes(t)) ||
      ['phone', 'tablet'].includes(d.type),
  },
  {
    name: 'Network',
    match: d =>
      ['Cisco', 'Netgear', 'TP-Link', 'Huawei', 'D-Link', 'Ubiquiti', 'Asus', 'Linksys']
        .some(t => (d.vendor || '').includes(t)) ||
      ['router', 'switch', 'access_point'].includes(d.type),
  },
  {
    name: 'Computer',
    match: d =>
      ['VMware', 'Raspberry', 'Dell', 'HP', 'Lenovo', 'Realtek']
        .some(t => (d.vendor || '').includes(t)) ||
      ['nas', 'server', 'pc'].includes(d.type),
  },
  { name: 'Other', match: () => true },
];

function classify(d) {
  for (const c of CLUSTER_DEFS) if (c.match(d)) return c.name;
  return 'Other';
}

// ── Helpers ───────────────────────────────────────────────────────────────────
function shortLabel(d) {
  const s = d.enriched?.deviceName || d.hostname || d.nickname || d.vendor || d.mac;
  return s && s.length > 14 ? s.slice(0, 13) + '…' : (s || '?');
}

function connectorBadge(d) {
  const src = d.enriched?.enrichmentSource;
  if (src && src.length > 0) return src[0];
  return `${d.packets || 0}p`;
}

// ── Component ─────────────────────────────────────────────────────────────────
export default function TopologyMap({ devices }) {
  const [selected, setSelected] = useState(null);

  if (!devices || devices.length === 0) return null;

  const hasBandData = devices.some(d => d.band);
  const router      = detectRouter(devices);
  const others      = devices.filter(d => d.mac !== router.mac);

  // Build clusters (skip empty)
  const clusterMap = {};
  for (const d of others) {
    const name = classify(d);
    (clusterMap[name] = clusterMap[name] || []).push(d);
  }
  const activeClusters = CLUSTER_DEFS.map(c => c.name)
    .filter(n => clusterMap[n]?.length);

  // SVG geometry
  const CX = 450, CY = 325;
  const CLUSTER_DIST = 175;
  const nc = activeClusters.length;

  // Place cluster centres evenly around router
  const clusterMeta = activeClusters.map((name, i) => {
    const angle = (2 * Math.PI * i) / Math.max(nc, 1) - Math.PI / 2;
    return {
      name,
      cx: CX + CLUSTER_DIST * Math.cos(angle),
      cy: CY + CLUSTER_DIST * Math.sin(angle),
      devs: clusterMap[name],
    };
  });

  // Place devices in sub-ring around their cluster centre
  const nodes = [];
  for (const cl of clusterMeta) {
    const nd   = cl.devs.length;
    const subR = Math.max(60, Math.min(80, 40 + nd * 12));
    cl.devs.forEach((d, i) => {
      const angle = nd === 1
        ? -Math.PI / 2
        : (2 * Math.PI * i) / nd - Math.PI / 2;
      nodes.push({
        x: cl.cx + subR * Math.cos(angle),
        y: cl.cy + subR * Math.sin(angle),
        device: d,
      });
    });
  }

  const toggle = d => setSelected(p => p?.mac === d.mac ? null : d);

  return (
    <div className="bg-slate-800/40 backdrop-blur-md border
    border-white/5 rounded-2xl p-6">

      {/* CSS for hover scale */}
      <style>{`
        .topo-node {
          transform-box: fill-box;
          transform-origin: center;
          transition: transform 0.15s ease;
          cursor: pointer;
        }
        .topo-node:hover { transform: scale(1.15); }
      `}</style>

      {/* Header + band legend */}
      <div className="flex flex-wrap items-center justify-between gap-3 mb-4">
        <h2 className="text-lg font-semibold text-white flex items-center gap-2">
          <span className="w-2 h-2 rounded-full bg-purple-400
          shadow-[0_0_8px_rgba(168,85,247,0.8)]"/>
          Network Topology Map
          <span className="text-slate-500 text-sm font-normal ml-1">
            ({devices.length} device{devices.length !== 1 ? 's' : ''})
          </span>
        </h2>
        <div className="flex items-center gap-3 flex-wrap">
          {Object.entries(BAND_COLORS).map(([k, c]) => (
            <span key={k} className="flex items-center gap-1 text-xs text-slate-400">
              <svg width="10" height="10">
                <circle cx="5" cy="5" r="4" fill="none" stroke={c.ring} strokeWidth="2"/>
              </svg>
              {c.label}
            </span>
          ))}
        </div>
      </div>

      {/* No-band-data banner */}
      {!hasBandData && (
        <div className="bg-slate-700/40 border border-slate-600/50
        rounded-xl px-4 py-2 mb-4 text-xs text-slate-400">
          ℹ️ Band data unavailable — use{' '}
          <span className="font-mono text-slate-300">capture_monitor.py</span>{' '}
          for 2.4 / 5 GHz detection. All devices shown in grey.
        </div>
      )}

      {/* SVG map */}
      <div className="w-full overflow-hidden rounded-xl bg-slate-900/50">
        <svg viewBox="0 0 900 650" className="w-full" style={{ maxHeight: '520px' }}>

          {/* ── Connection lines with flowing animation + mid badge ── */}
          {nodes.map(({ x, y, device }, i) => {
            const c     = getBand(device.band);
            const speed = Math.max(0.4, 2 - (device.packets || 0) / 500);
            const mx    = (x + CX) / 2;
            const my    = (y + CY) / 2;
            return (
              <g key={`conn-${i}`}>
                <line
                  x1={x} y1={y} x2={CX} y2={CY}
                  stroke={c.line} strokeWidth="1.5"
                  strokeOpacity="0.35" strokeDasharray="6 4"
                >
                  <animate
                    attributeName="stroke-dashoffset"
                    from="20" to="0"
                    dur={`${speed}s`}
                    repeatCount="indefinite"
                  />
                </line>
                {/* Mid-line info badge */}
                <rect x={mx - 21} y={my - 9} width={42} height={17}
                  rx={4} fill="rgba(0,0,0,0.60)"/>
                <text x={mx} y={my + 4} textAnchor="middle"
                  fontSize="9" fill="#94a3b8">
                  {connectorBadge(device)}
                </text>
              </g>
            );
          })}

          {/* ── Router node (breathing glow) ── */}
          <g className="topo-node" onClick={() => toggle(router)}>
            {/* Outer glow pulse */}
            <circle cx={CX} cy={CY} r={46}
              fill="rgba(99,102,241,0.08)" stroke="none">
              <animate attributeName="r"
                values="42;50;42" dur="2s" repeatCount="indefinite"/>
              <animate attributeName="opacity"
                values="0.6;0.15;0.6" dur="2s" repeatCount="indefinite"/>
            </circle>
            <circle cx={CX} cy={CY} r={36}
              fill="#1e293b"
              stroke={selected?.mac === router.mac ? '#818cf8' : '#475569'}
              strokeWidth={selected?.mac === router.mac ? 3 : 2}/>
            <text x={CX} y={CY}
              textAnchor="middle" dominantBaseline="middle" fontSize="22">
              🌐
            </text>
            <text x={CX} y={CY + 52}
              textAnchor="middle" fill="#94a3b8" fontSize="12">
              {router.ip ? `Router · ${router.ip}` : 'Router'}
            </text>
          </g>

          {/* ── Device nodes ── */}
          {nodes.map(({ x, y, device }, i) => {
            const c     = getBand(device.band);
            const isSel = selected?.mac === device.mac;
            return (
              <g key={`node-${i}`} className="topo-node" onClick={() => toggle(device)}>
                <circle cx={x} cy={y} r={28}
                  fill="#1e293b"
                  stroke={c.ring} strokeWidth={4}
                  strokeOpacity={isSel ? 1 : 0.6}
                  strokeDasharray={c.dashed ? '4 2' : undefined}/>
                <text x={x} y={y}
                  textAnchor="middle" dominantBaseline="middle" fontSize="18">
                  {device.icon || '🖥️'}
                </text>
                <text x={x} y={y + 42}
                  textAnchor="middle"
                  fill={isSel ? '#e2e8f0' : '#94a3b8'}
                  fontSize="12">
                  {shortLabel(device)}
                </text>
              </g>
            );
          })}
        </svg>
      </div>

      {/* ── Selected device detail card ── */}
      {selected && (
        <div className="mt-4 bg-slate-900/70 border border-white/10 rounded-xl p-4">
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center gap-2">
              <span className="text-2xl">
                {selected.mac === router.mac ? '🌐' : (selected.icon || '🖥️')}
              </span>
              <div>
                <p className="text-white font-medium text-sm">
                  {selected.enriched?.deviceName || selected.hostname
                    || selected.nickname || selected.vendor || 'Unknown Device'}
                </p>
                <p className="text-slate-500 text-xs font-mono">{selected.mac}</p>
              </div>
            </div>
            <button onClick={() => setSelected(null)}
              className="text-slate-500 hover:text-white text-sm
              transition-colors px-2">✕</button>
          </div>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs">
            <div>
              <p className="text-slate-500 mb-0.5">IP Address</p>
              <p className="text-white font-mono">{selected.ip || '—'}</p>
            </div>
            <div>
              <p className="text-slate-500 mb-0.5">Vendor</p>
              <p className="text-white">{selected.vendor || '—'}</p>
            </div>
            <div>
              <p className="text-slate-500 mb-0.5">Band</p>
              <p className="text-white">{selected.band || 'Unknown'}</p>
            </div>
            <div>
              <p className="text-slate-500 mb-0.5">Packets</p>
              <p className="text-white">{selected.packets?.toLocaleString() || '—'}</p>
            </div>
            {selected.enriched?.enrichmentSource?.length > 0 && (
              <div>
                <p className="text-slate-500 mb-0.5">Top Protocol</p>
                <p className="text-white">{selected.enriched.enrichmentSource[0]}</p>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
