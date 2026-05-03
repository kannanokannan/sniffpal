import { useState } from 'react';

export default function DeviceTable({ devices, onDeviceClick, trustedDevices, onTrust }) {
  const [search, setSearch] = useState('');

  const filtered = devices.filter(d =>
    d.mac.toLowerCase().includes(search.toLowerCase()) ||
    d.vendor.toLowerCase().includes(search.toLowerCase()) ||
    (d.ip || '').includes(search) ||
    (d.hostname || '').toLowerCase().includes(search.toLowerCase())
  );

  return (
    <div className="bg-slate-800/40 backdrop-blur-md border
    border-white/5 rounded-2xl overflow-hidden shadow-lg">

      {/* Header */}
      <div className="flex items-center justify-between
      px-6 py-4 border-b border-white/5">
        <h2 className="text-lg font-semibold text-white
        flex items-center gap-2">
          <span className="w-2 h-2 rounded-full bg-violet-400
          shadow-[0_0_8px_rgba(167,139,250,0.8)]"></span>
          Devices
          <span className="text-slate-500 text-sm font-normal">
            ({filtered.length})
          </span>
        </h2>

        {/* Search */}
        <input
          type="text"
          placeholder="Search by MAC, IP, vendor..."
          value={search}
          onChange={e => setSearch(e.target.value)}
          className="bg-slate-900/50 border border-white/10
          rounded-xl px-4 py-2 text-sm text-slate-300
          placeholder-slate-600 focus:outline-none
          focus:border-cyan-500/50 w-64"
        />
      </div>

      {/* Column Headers */}
      <div className="flex items-center gap-3 px-4 py-2
      text-xs text-slate-500 border-b border-white/5
      bg-slate-900/20">
        <span className="w-5">#</span>
        <span className="w-6"></span>
        <span className="flex-1">Device</span>
        <span className="w-28 hidden md:block">IP Address</span>
        <span className="w-28 hidden lg:block">Activity</span>
        <span className="w-24">Packets</span>
        <span className="w-16">Trust</span>
      </div>

      {/* Scrollable List */}
      <div style={{ height: 450, overflowY: 'auto' }}>
        {filtered.length > 0 ? filtered.map((device, index) => {
          const isTrusted = trustedDevices?.includes(device.mac);
          const isTop = index === 0;

          return (
            <div
              key={device.mac}
              onClick={() => onDeviceClick?.(device)}
              className={`flex items-center gap-3 px-4
              border-b border-white/5 cursor-pointer
              transition-all duration-150 h-14
              ${isTrusted
                ? 'opacity-40 hover:opacity-60'
                : 'hover:bg-slate-700/30'
              }`}
            >
              {/* Rank */}
              <span className="text-slate-600 text-xs w-5 flex-shrink-0">
                {index + 1}
              </span>

              {/* Icon */}
              <span className="text-xl flex-shrink-0">
                {device.icon}
              </span>

              {/* Device Info */}
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2">
                  <span className="text-white text-xs font-medium truncate">
                    {device.hostname || device.nickname}
                  </span>
                  {isTrusted && (
                    <span className="text-green-400 text-xs">
                      ✓ Trusted
                    </span>
                  )}
                  {isTop && !isTrusted && (
                    <span className="bg-cyan-900/50 text-cyan-400
                    text-xs px-1.5 rounded-full">
                      Top
                    </span>
                  )}
                </div>
                <div className="text-slate-500 text-xs truncate">
                  {device.vendor}
                </div>
              </div>

              {/* IP */}
              <div className="text-cyan-400 font-mono text-xs
              w-28 flex-shrink-0 hidden md:block">
                {device.ip || '—'}
              </div>

              {/* Traffic */}
              <div className="text-slate-400 text-xs w-28
              flex-shrink-0 hidden lg:block truncate">
                {device.topTraffic || '🔀 Mixed'}
              </div>

              {/* Activity Bar */}
              <div className="flex items-center gap-2
              w-24 flex-shrink-0">
                <div className="flex-1 bg-slate-700
                rounded-full h-1.5">
                  <div
                    className="bg-gradient-to-r from-cyan-500
                    to-blue-500 h-1.5 rounded-full"
                    style={{
                      width: `${Math.min(100,
                        (device.packets / devices[0].packets) * 100
                      )}%`
                    }}
                  />
                </div>
                <span className="text-slate-400 text-xs
                w-10 text-right">
                  {device.packets > 999
                    ? `${(device.packets / 1000).toFixed(1)}k`
                    : device.packets}
                </span>
              </div>

              {/* Trust Button */}
              <button
                onClick={(e) => {
                  e.stopPropagation();
                  onTrust?.(device.mac);
                }}
                className={`text-xs px-2 py-1 rounded-lg
                w-16 flex-shrink-0 transition-all
                ${isTrusted
                  ? 'bg-green-900/30 text-green-400 hover:bg-red-900/30 hover:text-red-400'
                  : 'bg-slate-700/50 text-slate-500 hover:bg-green-900/30 hover:text-green-400'
                }`}
              >
                {isTrusted ? '✓' : 'Trust'}
              </button>
            </div>
          );
        }) : (
          <div className="flex items-center justify-center
          h-32 text-slate-600 text-sm">
            No devices match your search
          </div>
        )}
      </div>
    </div>
  );
}
