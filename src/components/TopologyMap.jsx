import { useMemo, useState } from 'react';
import { createPortal } from 'react-dom';

const ROUTER_HINTS = [
  'router', 'gateway', 'access_point', 'netgear', 'tp-link', 'tplink',
  'huawei', 'd-link', 'dlink', 'ubiquiti', 'asus', 'linksys', 'cisco',
];

const CLUSTER_DEFS = [
  {
    name: 'Network',
    tone: 'cyan',
    match: d => ROUTER_HINTS.some(t => `${d.vendor || ''} ${d.type || ''}`.toLowerCase().includes(t)) ||
      ['switch', 'access_point'].includes(d.type),
  },
  {
    name: 'Computers',
    tone: 'blue',
    match: d => ['VMware', 'Raspberry', 'Dell', 'HP', 'Lenovo', 'Realtek']
      .some(t => (d.vendor || '').includes(t)) || ['nas', 'server', 'pc'].includes(d.type),
  },
  {
    name: 'Mobile',
    tone: 'violet',
    match: d => ['Apple', 'Samsung', 'OnePlus', 'Xiaomi', 'Realme', 'OPPO', 'Vivo']
      .some(t => (d.vendor || '').includes(t)) || ['phone', 'tablet'].includes(d.type),
  },
  {
    name: 'IoT',
    tone: 'emerald',
    match: d => ['Amazon', 'Google Home', 'Philips', 'Nest', 'Sonos', 'Ring', 'Lifx', 'Tuya']
      .some(t => (d.vendor || '').includes(t)) ||
      ['smart_bulb', 'smart_speaker', 'smart_home', 'streaming_device', 'doorbell'].includes(d.type),
  },
  { name: 'Other', tone: 'slate', match: () => true },
];

const TONE_CLASSES = {
  cyan: 'border-cyan-700/60 bg-cyan-950/20 text-cyan-200',
  blue: 'border-blue-700/60 bg-blue-950/20 text-blue-200',
  violet: 'border-violet-700/60 bg-violet-950/20 text-violet-200',
  emerald: 'border-emerald-700/60 bg-emerald-950/20 text-emerald-200',
  slate: 'border-slate-700/70 bg-slate-900/60 text-slate-200',
};

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

function fullLabel(device) {
  return device.enriched?.deviceName || device.hostname || device.nickname || device.vendor || 'Unknown Device';
}

function subLabel(device) {
  return device.ip || device.mac || 'No address';
}

function nodeGlyph(device) {
  if (device.virtual) return 'GW';
  if (device.icon && device.icon.length <= 3) return device.icon;
  if (routerScore(device) > 0) return 'AP';
  if (device.type === 'nas' || device.type === 'server') return 'NAS';
  if (device.type === 'phone' || device.type === 'tablet') return 'MB';
  if (device.type === 'smart_speaker') return 'SP';
  if (device.type === 'smart_bulb') return 'LB';
  return 'D';
}

function DeviceBox({ device, selected, onClick, compact = false }) {
  return (
    <button
      type="button"
      onClick={() => onClick(device)}
      className={`w-full text-left rounded-lg border px-3 py-2 transition-all
      ${selected ? 'border-cyan-400 bg-cyan-900/30' : 'border-white/10 bg-slate-950/50 hover:border-cyan-700/60'}`}
    >
      <div className="flex items-center gap-2 min-w-0">
        <span className="w-8 h-8 flex-shrink-0 rounded-md bg-slate-800 border border-white/10
        flex items-center justify-center text-xs font-bold text-slate-200">
          {nodeGlyph(device)}
        </span>
        <div className="min-w-0">
          <p className="text-white text-xs font-medium truncate" title={fullLabel(device)}>
            {fullLabel(device)}
          </p>
          {!compact && (
            <p className="text-slate-500 text-[11px] font-mono truncate" title={subLabel(device)}>
              {subLabel(device)}
            </p>
          )}
        </div>
      </div>
    </button>
  );
}

function DetailPanel({ selected, router, inferred, onClose }) {
  if (!selected) return null;
  const selectedIsRouter = sameDevice(selected, router);
  return (
    <div className="bg-slate-900/80 border border-white/10 rounded-xl p-4">
      <div className="flex items-start justify-between gap-3 mb-3">
        <div>
          <p className="text-white text-sm font-semibold">
            {selectedIsRouter ? (inferred ? 'Inferred Gateway' : 'Gateway') : fullLabel(selected)}
          </p>
          <p className="text-slate-500 text-xs font-mono">{selected.mac || selected.ip}</p>
        </div>
        <button type="button" onClick={onClose} className="text-slate-500 hover:text-white text-sm">Close</button>
      </div>
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs">
        <div><p className="text-slate-500">IP</p><p className="text-white font-mono truncate">{selected.ip || '-'}</p></div>
        <div><p className="text-slate-500">Vendor</p><p className="text-white truncate">{selected.vendor || '-'}</p></div>
        <div><p className="text-slate-500">Packets</p><p className="text-white">{selected.packets?.toLocaleString() || '-'}</p></div>
        <div><p className="text-slate-500">Band</p><p className="text-white">{selected.band || 'Unknown'}</p></div>
      </div>
      {inferred && selectedIsRouter && (
        <p className="text-slate-400 text-xs mt-3">
          The gateway was not seen directly, so SniffPal inferred the subnet gateway address.
        </p>
      )}
    </div>,
    document.body
  );
}

function buildTopology(devices) {
  const { router, inferred } = detectRouter(devices);
  const others = devices.filter(d => !sameDevice(d, router));
  const clusters = CLUSTER_DEFS.map(def => ({
    ...def,
    devices: others.filter(d => classify(d) === def.name),
  })).filter(c => c.devices.length > 0);
  return { router, inferred, clusters };
}

function TopologyModal({ devices, captureMode, onClose }) {
  const [selected, setSelected] = useState(null);
  const { router, inferred, clusters } = useMemo(() => buildTopology(devices), [devices]);
  const hasBandData = devices.some(d => d.band);

  if (typeof document === 'undefined') return null;

  return createPortal(
    <div className="fixed inset-0 z-[9999] w-screen h-screen bg-slate-950/90 backdrop-blur-md p-3 md:p-6 print:hidden">
      <div className="h-full w-full max-w-[1600px] mx-auto bg-slate-950 border border-white/10 rounded-2xl overflow-hidden shadow-2xl flex flex-col">
        <div className="px-6 py-4 border-b border-white/10 flex items-start justify-between gap-4">
          <div>
            <h2 className="text-xl font-semibold text-white">Network Topology</h2>
            <p className="text-slate-500 text-sm">
              Expanded connected-box view for {devices.length} device{devices.length === 1 ? '' : 's'}.
            </p>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="border border-white/10 rounded-lg px-3 py-1.5 text-sm text-slate-300 hover:text-white"
          >
            Close
          </button>
        </div>

        {!hasBandData && (
          <div className="mx-6 mt-4 bg-slate-900/60 border border-slate-700/50 rounded-xl px-4 py-2 text-xs text-slate-500">
            {captureMode === 'monitor'
              ? 'Monitor mode is selected, but this capture did not include band metadata yet.'
              : 'Standard capture: Wi-Fi band rings require Monitor mode with a compatible USB adapter.'}
          </div>
        )}

        <div className="flex-1 overflow-auto p-6 space-y-5">
          <div className="grid grid-cols-1 lg:grid-cols-[260px_1fr] gap-6 items-start">
            <div className="lg:sticky lg:top-0">
              <div className="border border-cyan-700/60 bg-cyan-950/20 rounded-xl p-4">
                <p className="text-cyan-300 text-xs uppercase tracking-wide mb-2">
                  {inferred ? 'Inferred Gateway' : 'Gateway'}
                </p>
                <DeviceBox device={router} selected={sameDevice(selected, router)} onClick={setSelected} />
              </div>
            </div>

            <div className="space-y-4">
              {clusters.map(cluster => (
                <div key={cluster.name} className="relative pl-8">
                  <div className="absolute left-0 top-7 w-8 border-t border-slate-700" />
                  <div className={`rounded-xl border p-4 ${TONE_CLASSES[cluster.tone]}`}>
                    <div className="flex items-center justify-between mb-3">
                      <h3 className="text-sm font-semibold">{cluster.name}</h3>
                      <span className="text-xs opacity-70">{cluster.devices.length} device{cluster.devices.length === 1 ? '' : 's'}</span>
                    </div>
                    <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-3 gap-3">
                      {cluster.devices.map(device => (
                        <DeviceBox
                          key={device.mac || device.ip || fullLabel(device)}
                          device={device}
                          selected={sameDevice(selected, device)}
                          onClick={setSelected}
                        />
                      ))}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>

          <DetailPanel
            selected={selected}
            router={router}
            inferred={inferred}
            onClose={() => setSelected(null)}
          />
        </div>
      </div>
    </div>
  );
}

export default function TopologyMap({ devices, captureMode = 'standard' }) {
  const [expanded, setExpanded] = useState(false);
  const [selected, setSelected] = useState(null);

  if (!devices || devices.length === 0) return null;

  const { router, inferred, clusters } = buildTopology(devices);
  const previewDevices = clusters.flatMap(c => c.devices.slice(0, 2)).slice(0, 8);

  return (
    <div className="bg-slate-800/40 backdrop-blur-md border border-white/5 rounded-2xl p-6">
      {expanded && (
        <TopologyModal
          devices={devices}
          captureMode={captureMode}
          onClose={() => setExpanded(false)}
        />
      )}

      <div className="flex flex-wrap items-center justify-between gap-3 mb-4">
        <div>
          <h2 className="text-lg font-semibold text-white flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-purple-400 shadow-[0_0_8px_rgba(168,85,247,0.8)]" />
            Network Topology
            <span className="text-slate-500 text-sm font-normal ml-1">
              ({devices.length} device{devices.length !== 1 ? 's' : ''})
            </span>
          </h2>
          <p className="text-slate-500 text-xs mt-1">
            Compact preview. Open the expanded map for detailed connected boxes.
          </p>
        </div>
        <button
          type="button"
          onClick={() => setExpanded(true)}
          className="bg-purple-600 hover:bg-purple-500 text-white text-sm px-4 py-2 rounded-xl transition-colors"
        >
          Expand Map
        </button>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-[240px_1fr] gap-4 items-start">
        <div className="border border-cyan-700/60 bg-cyan-950/20 rounded-xl p-4">
          <p className="text-cyan-300 text-xs uppercase tracking-wide mb-2">
            {inferred ? 'Inferred Gateway' : 'Gateway'}
          </p>
          <DeviceBox device={router} selected={sameDevice(selected, router)} onClick={setSelected} compact />
        </div>

        <div className="relative">
          <div className="hidden lg:block absolute left-[-16px] top-1/2 w-4 border-t border-slate-700" />
          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-3">
            {previewDevices.map(device => (
              <DeviceBox
                key={device.mac || device.ip || fullLabel(device)}
                device={device}
                selected={sameDevice(selected, device)}
                onClick={setSelected}
                compact
              />
            ))}
          </div>
          {devices.length > previewDevices.length + 1 && (
            <button
              type="button"
              onClick={() => setExpanded(true)}
              className="mt-3 text-xs text-purple-300 hover:text-purple-200"
            >
              Show {devices.length - previewDevices.length - 1} more device{devices.length - previewDevices.length - 1 === 1 ? '' : 's'} in expanded map
            </button>
          )}
        </div>
      </div>

      <DetailPanel
        selected={selected}
        router={router}
        inferred={inferred}
        onClose={() => setSelected(null)}
      />
    </div>
  );
}
