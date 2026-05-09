import { useState, useEffect, useCallback } from 'react';
import { FixedSizeList } from 'react-window';

const ROW_HEIGHT = 48;
const LIST_HEIGHT = 480;

export default function DeviceTable({ devices, onDeviceClick, trustedDevices, onTrust, selfIp, onSetSelf }) {
  const [search, setSearch] = useState('');
  const [trustedSet, setTrustedSet] = useState(new Set());

  useEffect(() => {
    if (!devices?.length || !trustedDevices?.length) {
      setTrustedSet(new Set());
      return;
    }
    let cancelled = false;
    (async () => {
      const pairs = await Promise.all(
        devices.map(async d => {
          const buf = await crypto.subtle.digest(
            'SHA-256', new TextEncoder().encode(d.mac.toLowerCase())
          );
          const hash = Array.from(new Uint8Array(buf))
            .map(b => b.toString(16).padStart(2, '0')).join('');
          return [d.mac, hash];
        })
      );
      if (!cancelled)
        setTrustedSet(new Set(
          pairs.filter(([, h]) => trustedDevices.includes(h)).map(([m]) => m)
        ));
    })();
    return () => { cancelled = true; };
  }, [devices, trustedDevices]);

  const filtered = (devices || []).filter(d =>
    d.mac.toLowerCase().includes(search.toLowerCase()) ||
    d.vendor.toLowerCase().includes(search.toLowerCase()) ||
    (d.ip || '').includes(search) ||
    (d.hostname || '').toLowerCase().includes(search.toLowerCase())
  );

  const maxPackets = filtered[0]?.packets || 1;

  const Row = useCallback(({ index, style }) => {
    const device = filtered[index];
    const isTrusted = trustedSet.has(device.mac);
    const isTop = index === 0;
    const isSelf = device.ip && device.ip === selfIp;

    return (
      <div
        style={style}
        onClick={() => onDeviceClick?.(device)}
        className={`flex items-center gap-3 px-4
        border-b border-white/5 cursor-pointer
        transition-all duration-150
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
            {isSelf && (
              <span className="text-blue-400 text-xs">🏠 Mine</span>
            )}
            {isTrusted && (
              <span className="text-green-400 text-xs">✓ Trusted</span>
            )}
            {isTop && !isTrusted && !isSelf && (
              <span className="bg-cyan-900/50 text-cyan-400 text-xs px-1.5 rounded-full">
                Top
              </span>
            )}
          </div>
          <div className="text-slate-500 text-xs truncate">{device.vendor}</div>
        </div>

        {/* IP */}
        <div className="text-cyan-400 font-mono text-xs w-28 flex-shrink-0 hidden md:block">
          {device.ip || '—'}
        </div>

        {/* Traffic */}
        <div className="text-slate-400 text-xs w-28 flex-shrink-0 hidden lg:block truncate">
          {device.topTraffic || '🔀 Mixed'}
        </div>

        {/* Activity Bar */}
        <div className="flex items-center gap-2 w-24 flex-shrink-0">
          <div className="flex-1 bg-slate-700 rounded-full h-1.5">
            <div
              className="bg-gradient-to-r from-cyan-500 to-blue-500 h-1.5 rounded-full"
              style={{ width: `${Math.min(100, (device.packets / maxPackets) * 100)}%` }}
            />
          </div>
          <span className="text-slate-400 text-xs w-10 text-right">
            {device.packets > 999
              ? `${(device.packets / 1000).toFixed(1)}k`
              : device.packets}
          </span>
        </div>

        {/* Trust Button */}
        <button
          onClick={(e) => { e.stopPropagation(); onTrust?.(device.mac); }}
          className={`text-xs px-2 py-1 rounded-lg w-16 flex-shrink-0 transition-all
          ${isTrusted
            ? 'bg-green-900/30 text-green-400 hover:bg-red-900/30 hover:text-red-400'
            : 'bg-slate-700/50 text-slate-500 hover:bg-green-900/30 hover:text-green-400'
          }`}
        >
          {isTrusted ? '✓' : 'Trust'}
        </button>

        {/* Self button — only show for devices with an IP */}
        {device.ip && (
          <button
            onClick={(e) => {
              e.stopPropagation();
              onSetSelf?.(isSelf ? null : device.ip);
            }}
            className={`text-xs px-2 py-1 rounded-lg w-14 flex-shrink-0 transition-all
            ${isSelf
              ? 'bg-blue-900/40 text-blue-400 hover:bg-slate-700/50 hover:text-slate-500'
              : 'bg-slate-700/50 text-slate-500 hover:bg-blue-900/30 hover:text-blue-400'
            }`}
            title={isSelf ? 'Unmark as my device' : 'Mark as my device'}
          >
            {isSelf ? '🏠' : 'Mine'}
          </button>
        )}
      </div>
    );
  }, [filtered, trustedSet, onDeviceClick, onTrust, maxPackets, selfIp, onSetSelf]);

  return (
    <div className="bg-slate-800/40 backdrop-blur-md border border-white/5 rounded-2xl overflow-hidden shadow-lg">

      {/* Header */}
      <div className="flex items-center justify-between px-6 py-4 border-b border-white/5">
        <h2 className="text-lg font-semibold text-white flex items-center gap-2">
          <span className="w-2 h-2 rounded-full bg-violet-400 shadow-[0_0_8px_rgba(167,139,250,0.8)]"></span>
          Devices
          <span className="text-slate-500 text-sm font-normal">({filtered.length})</span>
        </h2>
        <input
          type="text"
          placeholder="Search by MAC, IP, vendor..."
          value={search}
          onChange={e => setSearch(e.target.value)}
          className="bg-slate-900/50 border border-white/10 rounded-xl px-4 py-2 text-sm
          text-slate-300 placeholder-slate-600 focus:outline-none focus:border-cyan-500/50 w-64"
        />
      </div>

      {/* Column Headers */}
      <div className="flex items-center gap-3 px-4 py-2 text-xs text-slate-500 border-b border-white/5 bg-slate-900/20">
        <span className="w-5">#</span>
        <span className="w-6"></span>
        <span className="flex-1">Device</span>
        <span className="w-28 hidden md:block">IP Address</span>
        <span className="w-28 hidden lg:block">Activity</span>
        <span className="w-24">Packets</span>
        <span className="w-16">Trust</span>
        <span className="w-14">Mine</span>
      </div>

      {/* Virtual List */}
      {filtered.length > 0 ? (
        <FixedSizeList
          height={LIST_HEIGHT}
          itemCount={filtered.length}
          itemSize={ROW_HEIGHT}
          width="100%"
        >
          {Row}
        </FixedSizeList>
      ) : (
        <div className="flex items-center justify-center h-32 text-slate-600 text-sm">
          No devices match your search
        </div>
      )}
    </div>
  );
}
