import { useState } from 'react';

const BAND_COLORS = {
  '2.4 GHz': { ring: '#22c55e', line: '#22c55e', label: '2.4 GHz' },
  '5 GHz':   { ring: '#3b82f6', line: '#3b82f6', label: '5 GHz' },
  '6 GHz':   { ring: '#a855f7', line: '#a855f7', label: '6 GHz' },
  unknown:   { ring: '#6b7280', line: '#6b7280', label: 'Unknown', dashed: true },
};

function getBandColors(band) {
  return BAND_COLORS[band] || BAND_COLORS.unknown;
}

/** Find the router: device with IP ending in .1, else highest-bytes device. */
function detectRouter(devices) {
  const withIp = devices.filter(d => d.ip);
  const gw = withIp.find(d => /\.1$/.test(d.ip));
  if (gw) return gw;
  return [...devices].sort((a, b) => (b.bytes || 0) - (a.bytes || 0))[0];
}

function deviceLabel(d) {
  const raw = d.enriched?.deviceName || d.hostname || d.nickname || d.vendor || d.mac;
  return raw.length > 15 ? raw.slice(0, 14) + '…' : raw;
}

export default function TopologyMap({ devices }) {
  const [selected, setSelected] = useState(null);

  if (!devices || devices.length === 0) return null;

  const hasBandData = devices.some(d => d.band);
  const router      = detectRouter(devices);
  const others      = devices.filter(d => d.mac !== router.mac);

  const CX = 400, CY = 290;
  const RADIUS = Math.min(220, 40 + others.length * 18);
  const n = others.length;

  const nodePositions = others.map((d, i) => {
    const angle = (2 * Math.PI * i) / Math.max(n, 1) - Math.PI / 2;
    return {
      x: CX + RADIUS * Math.cos(angle),
      y: CY + RADIUS * Math.sin(angle),
      device: d,
    };
  });

  const handleSelect = (d) =>
    setSelected(prev => prev?.mac === d.mac ? null : d);

  return (
    <div className="bg-slate-800/40 backdrop-blur-md border
    border-white/5 rounded-2xl p-6">

      {/* Header + Legend */}
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
          {Object.entries(BAND_COLORS).map(([key, c]) => (
            <span key={key} className="flex items-center gap-1
            text-xs text-slate-400">
              <svg width="10" height="10">
                <circle cx="5" cy="5" r="4" fill="none"
                  stroke={c.ring} strokeWidth="2"/>
              </svg>
              {c.label}
            </span>
          ))}
        </div>
      </div>

      {/* No-band banner */}
      {!hasBandData && (
        <div className="bg-slate-700/40 border border-slate-600/50
        rounded-xl px-4 py-2 mb-4 text-xs text-slate-400">
          ℹ️ Band data unavailable — use{' '}
          <span className="font-mono text-slate-300">capture_monitor.py</span>{' '}
          for 2.4 / 5 GHz detection. All devices shown in grey.
        </div>
      )}

      {/* SVG Map */}
      <div className="w-full overflow-hidden rounded-xl bg-slate-900/50">
        <svg
          viewBox="0 0 800 580"
          className="w-full"
          style={{ maxHeight: '460px' }}
        >
          {/* Connection lines */}
          {nodePositions.map(({ x, y, device }, i) => {
            const c = getBandColors(device.band);
            return (
              <line
                key={`line-${i}`}
                x1={CX} y1={CY} x2={x} y2={y}
                stroke={c.line}
                strokeWidth="1.2"
                strokeOpacity="0.35"
                strokeDasharray={c.dashed ? '5,4' : undefined}
              />
            );
          })}

          {/* Router node */}
          <g
            style={{ cursor: 'pointer' }}
            onClick={() => handleSelect(router)}
          >
            <circle
              cx={CX} cy={CY} r={38}
              fill="#1e293b"
              stroke={selected?.mac === router.mac ? '#94a3b8' : '#475569'}
              strokeWidth={selected?.mac === router.mac ? 2.5 : 1.5}
            />
            <text x={CX} y={CY} textAnchor="middle"
              dominantBaseline="middle" fontSize="22">🌐</text>
            <text x={CX} y={CY + 52} textAnchor="middle"
              fill="#94a3b8" fontSize="11">
              Router{router.ip ? ` · ${router.ip}` : ''}
            </text>
          </g>

          {/* Device nodes */}
          {nodePositions.map(({ x, y, device }, i) => {
            const c = getBandColors(device.band);
            const isSel = selected?.mac === device.mac;
            return (
              <g
                key={`node-${i}`}
                style={{ cursor: 'pointer' }}
                onClick={() => handleSelect(device)}
              >
                {/* Band ring */}
                <circle
                  cx={x} cy={y} r={30}
                  fill="#1e293b"
                  stroke={c.ring}
                  strokeWidth={isSel ? 3 : 1.8}
                  strokeOpacity={isSel ? 1 : 0.65}
                />
                <text x={x} y={y} textAnchor="middle"
                  dominantBaseline="middle" fontSize="17">
                  {device.icon || '🖥️'}
                </text>
                <text x={x} y={y + 42} textAnchor="middle"
                  fill={isSel ? '#e2e8f0' : '#94a3b8'} fontSize="9.5">
                  {deviceLabel(device)}
                </text>
              </g>
            );
          })}
        </svg>
      </div>

      {/* Selected device detail card */}
      {selected && (
        <div className="mt-4 bg-slate-900/70 border border-white/10
        rounded-xl p-4 animate-fade-in">
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center gap-2">
              <span className="text-2xl">
                {selected.mac === router.mac ? '🌐' : (selected.icon || '🖥️')}
              </span>
              <div>
                <p className="text-white font-medium text-sm">
                  {selected.enriched?.deviceName
                    || selected.hostname
                    || selected.nickname
                    || selected.vendor
                    || 'Unknown Device'}
                </p>
                <p className="text-slate-500 text-xs font-mono">
                  {selected.mac}
                </p>
              </div>
            </div>
            <button
              onClick={() => setSelected(null)}
              className="text-slate-500 hover:text-white text-sm
              transition-colors px-2"
            >✕</button>
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
          </div>
        </div>
      )}
    </div>
  );
}
