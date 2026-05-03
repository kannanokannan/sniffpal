import { X } from 'lucide-react';

export default function DataPanel({ data, devices, onClose }) {
  if (!data) return null;

  // Find related devices
  const relatedDevices = devices?.filter(d =>
    d.topTraffic === data.name ||
    (data.type === 'protocol' &&
      Object.keys(d.trafficTypes || {}).includes(data.name))
  ).slice(0, 5) || [];

  const totalPackets = devices?.reduce(
    (sum, d) => sum + d.packets, 0
  ) || 1;

  const pct = data.total
    ? ((data.value / data.total) * 100).toFixed(1)
    : null;

  return (
    <div className="bg-slate-800/60 backdrop-blur-md border
    border-cyan-500/20 rounded-2xl p-6 shadow-lg
    animate-[fadeIn_0.2s_ease-out]">

      {/* Header */}
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-white font-semibold flex items-center gap-2">
          <span className="w-2 h-2 rounded-full bg-cyan-400
          shadow-[0_0_8px_rgba(34,211,238,0.8)]"></span>
          Data Insight
          <span className="text-cyan-400 ml-1">{data.name}</span>
        </h3>
        <button
          onClick={onClose}
          className="text-slate-500 hover:text-white transition-colors"
        >
          <X className="w-4 h-4" />
        </button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">

        {/* Main Stats */}
        <div className="bg-slate-900/50 rounded-xl p-4">
          <p className="text-slate-500 text-xs mb-3 uppercase tracking-wide">
            Volume
          </p>
          <div className="space-y-2">
            <div className="flex justify-between items-center">
              <span className="text-slate-400 text-xs">Count</span>
              <span className="text-white font-bold">
                {data.value?.toLocaleString()}
              </span>
            </div>
            {pct && (
              <div className="flex justify-between items-center">
                <span className="text-slate-400 text-xs">Share</span>
                <span className="text-cyan-400 font-bold">{pct}%</span>
              </div>
            )}
            {data.value && (
              <div className="mt-2 w-full bg-slate-700
              rounded-full h-2">
                <div
                  className="bg-gradient-to-r from-cyan-500
                  to-blue-500 h-2 rounded-full"
                  style={{ width: `${pct || 50}%` }}
                />
              </div>
            )}
          </div>
        </div>

        {/* Context */}
        <div className="bg-slate-900/50 rounded-xl p-4">
          <p className="text-slate-500 text-xs mb-3 uppercase tracking-wide">
            Context
          </p>
          <div className="space-y-2">
            {data.encrypted !== undefined && (
              <div className="flex justify-between items-center">
                <span className="text-slate-400 text-xs">Encrypted</span>
                <span className={data.encrypted
                  ? 'text-green-400 text-xs'
                  : 'text-red-400 text-xs'}>
                  {data.encrypted ? '🔒 Yes' : '⚠️ No'}
                </span>
              </div>
            )}
            {data.category && (
              <div className="flex justify-between items-center">
                <span className="text-slate-400 text-xs">Category</span>
                <span className="text-slate-300 text-xs">
                  {data.category}
                </span>
              </div>
            )}
            {data.ip && (
              <div className="flex justify-between items-center">
                <span className="text-slate-400 text-xs">IP</span>
                <span className="text-cyan-400 font-mono text-xs">
                  {data.ip}
                </span>
              </div>
            )}
            {data.vendor && (
              <div className="flex justify-between items-center">
                <span className="text-slate-400 text-xs">Vendor</span>
                <span className="text-slate-300 text-xs">
                  {data.vendor}
                </span>
              </div>
            )}
            {data.bandwidthMB && (
              <div className="flex justify-between items-center">
                <span className="text-slate-400 text-xs">Bandwidth</span>
                <span className="text-slate-300 text-xs">
                  {data.bandwidthMB} MB
                </span>
              </div>
            )}
          </div>
        </div>

        {/* Related Devices */}
        <div className="bg-slate-900/50 rounded-xl p-4">
          <p className="text-slate-500 text-xs mb-3 uppercase tracking-wide">
            {data.mac ? 'Traffic Types' : 'Related Devices'}
          </p>
          {data.mac ? (
            <div className="space-y-1">
              {Object.entries(data.trafficTypes || {})
                .sort((a, b) => b[1] - a[1])
                .slice(0, 5)
                .map(([type, count], i) => (
                  <div key={i} className="flex justify-between
                  items-center">
                    <span className="text-slate-400 text-xs truncate">
                      {type}
                    </span>
                    <span className="text-slate-300 text-xs">
                      {count}
                    </span>
                  </div>
                ))}
              {Object.keys(data.trafficTypes || {}).length === 0 && (
                <p className="text-slate-600 text-xs">
                  No traffic type data
                </p>
              )}
            </div>
          ) : relatedDevices.length > 0 ? (
            <div className="space-y-1">
              {relatedDevices.map((d, i) => (
                <div key={i} className="flex items-center gap-2">
                  <span className="text-base">{d.icon}</span>
                  <span className="text-slate-300 text-xs truncate">
                    {d.hostname || d.nickname}
                  </span>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-slate-600 text-xs">
              No related devices found
            </p>
          )}
        </div>

      </div>
    </div>
  );
}
