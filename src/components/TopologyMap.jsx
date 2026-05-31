import { useState } from 'react';

const BAND_COLORS = {
  '2.4 GHz': { ring: '#22c55e', line: '#22c55e', label: '2.4 GHz' },
  '5 GHz': { ring: '#3b82f6', line: '#3b82f6', label: '5 GHz' },
  '6 GHz': { ring: '#a855f7', line: '#a855f7', label: '6 GHz' },
  unknown: { ring: '#64748b', line: '#64748b', label: 'Unknown', dashed: true },
};

const ROUTER_HINTS = [
  'router',
  'gateway',
  'access_point',
  'netgear',
  'tp-link',
  'tplink',
  'huawei',
  'd-link',
  'dlink',
  'ubiquiti',
  'asus',
  'linksys',
  'cisco',
];

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
      ROUTER_HINTS.some(t => `${d.vendor || ''} ${d.type || ''}`.toLowerCase().includes(t)) ||
      ['switch', 'access_point'].includes(d.type),
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

const getBand = band => BAND_COLORS[band] || BAND_COLORS.unknown;

function isIpv4(ip) {
  return /^(\d{1,3}\.){3}\d{1,3}$/.test(ip || '');
}

function sameDevice(a, b) {
  if (!a || !b) return false;
  if (a.mac && b.mac && a.mac === b.mac) return true;
  if (a.ip && b.ip && a.ip === b.ip) return true;
  return false;
}

function routerScore(device) {
  const text = `${device.vendor || ''} ${device.type || ''} ${device.hostname || ''} ${device.nickname || ''}`.toLowerCase();
  return ROUTER_HINTS.reduce((score, hint) => score + (text.includes(hint) ? 1 : 0), 0);
}

function inferGatewayIp(devices) {
  const ip = devices.map(d => d.ip).find(isIpv4);
  if (!ip) return null;
  const parts = ip.split('.');
  return `${parts[0]}.${parts[1]}.${parts[2]}.1`;
}

function detectRouter(devices) {
  const exactGateway = devices.find(d => isIpv4(d.ip) && d.ip.endsWith('.1'));
  if (exactGateway) return { router: exactGateway, inferred: false };

  const routerLike = devices
    .filter(d => routerScore(d) > 0)
    .sort((a, b) => routerScore(b) - routerScore(a))[0];
  if (routerLike) return { router: routerLike, inferred: false };

  const gatewayIp = inferGatewayIp(devices);
  if (gatewayIp) {
    return {
      router: {
        mac: `gateway-${gatewayIp}`,
        ip: gatewayIp,
        vendor: 'Gateway',
        hostname: 'Gateway',
        nickname: 'Gateway',
        packets: 0,
        bytes: 0,
        virtual: true,
      },
      inferred: true,
    };
  }

  return { router: devices[0], inferred: false };
}

function classify(device) {
  for (const cluster of CLUSTER_DEFS) {
    if (cluster.match(device)) return cluster.name;
  }
  return 'Other';
}

function shortLabel(device) {
  const label = device.enriched?.deviceName || device.hostname || device.nickname || device.vendor || device.mac || 'Device';
  return label.length > 16 ? `${label.slice(0, 15)}...` : label;
}

function fullLabel(device) {
  return device.enriched?.deviceName || device.hostname || device.nickname || device.vendor || 'Unknown Device';
}

function connectorBadge(device) {
  const source = device.enriched?.enrichmentSource;
  if (source && source.length > 0) return source[0];
  return `${device.packets || 0}p`;
}

function nodeGlyph(device) {
  if (device.virtual) return 'GW';
  if (device.icon && device.icon.length <= 3) return device.icon;
  if (device.type === 'smart_bulb') return 'LB';
  if (device.type === 'smart_speaker') return 'SP';
  if (device.type === 'nas' || device.type === 'server') return 'NAS';
  if (device.type === 'phone' || device.type === 'tablet') return 'MB';
  if (routerScore(device) > 0) return 'AP';
  return 'D';
}

export default function TopologyMap({ devices, captureMode = 'standard' }) {
  const [selected, setSelected] = useState(null);

  if (!devices || devices.length === 0) return null;

  const hasBandData = devices.some(d => d.band);
  const { router, inferred } = detectRouter(devices);
  const others = devices.filter(d => !sameDevice(d, router));

  const clusterMap = {};
  for (const device of others) {
    const name = classify(device);
    clusterMap[name] = clusterMap[name] || [];
    clusterMap[name].push(device);
  }

  const activeClusters = CLUSTER_DEFS.map(c => c.name).filter(name => clusterMap[name]?.length);
  const center = { x: 500, y: 315 };
  const clusterDistance = activeClusters.length <= 2 ? 250 : 235;

  const clusterMeta = activeClusters.map((name, index) => {
    const angle = (2 * Math.PI * index) / Math.max(activeClusters.length, 1) - Math.PI / 2;
    return {
      name,
      x: center.x + clusterDistance * Math.cos(angle),
      y: center.y + clusterDistance * Math.sin(angle),
      devices: clusterMap[name],
    };
  });

  const nodes = [];
  for (const cluster of clusterMeta) {
    const count = cluster.devices.length;
    const radius = Math.max(78, Math.min(125, 58 + count * 14));
    cluster.devices.forEach((device, index) => {
      const angle = count === 1 ? -Math.PI / 2 : (2 * Math.PI * index) / count - Math.PI / 2;
      nodes.push({
        x: cluster.x + radius * Math.cos(angle),
        y: cluster.y + radius * Math.sin(angle),
        cluster: cluster.name,
        device,
      });
    });
  }

  const toggle = device => setSelected(current => sameDevice(current, device) ? null : device);
  const selectedIsRouter = sameDevice(selected, router);

  return (
    <div className="bg-slate-800/40 backdrop-blur-md border border-white/5 rounded-2xl p-6">
      <style>{`
        .topo-node {
          transform-box: fill-box;
          transform-origin: center;
          transition: transform 0.18s ease, filter 0.18s ease;
          cursor: pointer;
        }
        .topo-node:hover {
          transform: scale(1.12);
          filter: drop-shadow(0 0 14px rgba(125, 211, 252, 0.25));
        }
      `}</style>

      <div className="flex flex-wrap items-center justify-between gap-3 mb-4">
        <h2 className="text-lg font-semibold text-white flex items-center gap-2">
          <span className="w-2 h-2 rounded-full bg-purple-400 shadow-[0_0_8px_rgba(168,85,247,0.8)]" />
          Network Topology Map
          <span className="text-slate-500 text-sm font-normal ml-1">
            ({devices.length} device{devices.length !== 1 ? 's' : ''})
          </span>
        </h2>
        <div className="flex items-center gap-3 flex-wrap">
          {Object.entries(BAND_COLORS).map(([key, color]) => (
            <span key={key} className="flex items-center gap-1 text-xs text-slate-400">
              <svg width="10" height="10" aria-hidden="true">
                <circle cx="5" cy="5" r="4" fill="none" stroke={color.ring} strokeWidth="2" />
              </svg>
              {color.label}
            </span>
          ))}
        </div>
      </div>

      {!hasBandData && (
        <div className="bg-slate-900/40 border border-slate-700/50 rounded-xl px-4 py-2 mb-4 text-xs text-slate-500">
          {captureMode === 'monitor'
            ? 'Monitor mode is selected, but this capture did not include band metadata yet. Check the monitor-mode adapter and interface.'
            : 'Standard capture: Wi-Fi band rings require Monitor mode with a compatible USB adapter.'}
        </div>
      )}

      <div className="w-full overflow-hidden rounded-xl bg-slate-950/50 border border-white/5">
        <svg viewBox="0 0 1000 630" className="w-full h-[580px]">
          <defs>
            <radialGradient id="routerGlow" cx="50%" cy="50%" r="50%">
              <stop offset="0%" stopColor="rgba(129,140,248,0.35)" />
              <stop offset="100%" stopColor="rgba(129,140,248,0)" />
            </radialGradient>
          </defs>

          {clusterMeta.map(cluster => (
            <g key={`cluster-${cluster.name}`}>
              <circle
                cx={cluster.x}
                cy={cluster.y}
                r="128"
                fill="rgba(15,23,42,0.35)"
                stroke="rgba(148,163,184,0.08)"
                strokeWidth="1"
              />
              <text x={cluster.x} y={cluster.y - 140} textAnchor="middle" fontSize="12" fill="#64748b">
                {cluster.name}
              </text>
            </g>
          ))}

          {nodes.map(({ x, y, device }, index) => {
            const color = getBand(device.band);
            const speed = Math.max(0.5, 2.2 - (device.packets || 0) / 450);
            const midX = (x + center.x) / 2;
            const midY = (y + center.y) / 2;
            return (
              <g key={`conn-${device.mac || device.ip || index}`}>
                <line
                  x1={center.x}
                  y1={center.y}
                  x2={x}
                  y2={y}
                  stroke={color.line}
                  strokeWidth="2"
                  strokeOpacity="0.42"
                  strokeDasharray="8 6"
                >
                  <animate attributeName="stroke-dashoffset" from="28" to="0" dur={`${speed}s`} repeatCount="indefinite" />
                </line>
                <rect x={midX - 24} y={midY - 11} width="48" height="20" rx="6" fill="rgba(2,6,23,0.78)" />
                <text x={midX} y={midY + 4} textAnchor="middle" fontSize="10" fill="#cbd5e1">
                  {connectorBadge(device)}
                </text>
              </g>
            );
          })}

          <g className="topo-node" onClick={() => toggle(router)}>
            <circle cx={center.x} cy={center.y} r="76" fill="url(#routerGlow)">
              <animate attributeName="r" values="64;82;64" dur="2.6s" repeatCount="indefinite" />
              <animate attributeName="opacity" values="0.8;0.25;0.8" dur="2.6s" repeatCount="indefinite" />
            </circle>
            <circle
              cx={center.x}
              cy={center.y}
              r="46"
              fill="#172033"
              stroke={selectedIsRouter ? '#a5b4fc' : '#64748b'}
              strokeWidth={selectedIsRouter ? 4 : 2}
            />
            <text x={center.x} y={center.y + 6} textAnchor="middle" fontSize="18" fontWeight="700" fill="#e0f2fe">
              GW
            </text>
            <text x={center.x} y={center.y + 66} textAnchor="middle" fill="#cbd5e1" fontSize="13" fontWeight="600">
              {inferred ? 'Inferred Gateway' : 'Gateway'}
            </text>
            <text x={center.x} y={center.y + 83} textAnchor="middle" fill="#94a3b8" fontSize="12">
              {router.ip || 'unknown'}
            </text>
          </g>

          {nodes.map(({ x, y, device }, index) => {
            const color = getBand(device.band);
            const isSelected = sameDevice(selected, device);
            return (
              <g key={`node-${device.mac || device.ip || index}`} className="topo-node" onClick={() => toggle(device)}>
                <circle
                  cx={x}
                  cy={y}
                  r="40"
                  fill="rgba(15,23,42,0.95)"
                  stroke={color.ring}
                  strokeWidth="5"
                  strokeOpacity={isSelected ? 1 : 0.75}
                  strokeDasharray={color.dashed ? '6 4' : undefined}
                />
                <circle cx={x} cy={y} r="29" fill="rgba(30,41,59,0.92)" />
                <text x={x} y={y + 5} textAnchor="middle" fontSize="14" fontWeight="700" fill="#e2e8f0">
                  {nodeGlyph(device)}
                </text>
                <text
                  x={x}
                  y={y + 58}
                  textAnchor="middle"
                  fill={isSelected ? '#f8fafc' : '#cbd5e1'}
                  fontSize="13"
                  fontWeight={isSelected ? '600' : '500'}
                >
                  {shortLabel(device)}
                </text>
                {device.ip && (
                  <text x={x} y={y + 75} textAnchor="middle" fill="#64748b" fontSize="10">
                    {device.ip}
                  </text>
                )}
              </g>
            );
          })}
        </svg>
      </div>

      {selected && (
        <div className="mt-4 bg-slate-900/70 border border-white/10 rounded-xl p-4">
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center gap-3">
              <span className="w-10 h-10 rounded-full bg-slate-800 border border-white/10 flex items-center justify-center text-sky-100 text-sm font-bold">
                {nodeGlyph(selected)}
              </span>
              <div>
                <p className="text-white font-medium text-sm">
                  {selectedIsRouter ? (inferred ? 'Inferred Gateway' : 'Gateway') : fullLabel(selected)}
                </p>
                <p className="text-slate-500 text-xs font-mono">{selected.mac || selected.ip}</p>
              </div>
            </div>
            <button
              onClick={() => setSelected(null)}
              className="text-slate-500 hover:text-white text-sm transition-colors px-2"
              type="button"
            >
              x
            </button>
          </div>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs">
            <div>
              <p className="text-slate-500 mb-0.5">IP Address</p>
              <p className="text-white font-mono">{selected.ip || '-'}</p>
            </div>
            <div>
              <p className="text-slate-500 mb-0.5">Vendor</p>
              <p className="text-white">{selected.vendor || '-'}</p>
            </div>
            <div>
              <p className="text-slate-500 mb-0.5">Band</p>
              <p className="text-white">{selected.band || 'Unknown'}</p>
            </div>
            <div>
              <p className="text-slate-500 mb-0.5">Packets</p>
              <p className="text-white">{selected.packets?.toLocaleString() || '-'}</p>
            </div>
            {selected.enriched?.enrichmentSource?.length > 0 && (
              <div>
                <p className="text-slate-500 mb-0.5">Top Protocol</p>
                <p className="text-white">{selected.enriched.enrichmentSource[0]}</p>
              </div>
            )}
            {inferred && selectedIsRouter && (
              <div className="md:col-span-3">
                <p className="text-slate-500 mb-0.5">How this was chosen</p>
                <p className="text-white">
                  The gateway was not seen directly in the capture, so SniffPal inferred the subnet gateway address.
                </p>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
