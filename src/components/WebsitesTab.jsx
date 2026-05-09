import { useState } from 'react';

export default function WebsitesTab({ websites, trackers, selfIp, onGoToDevices }) {
  const [hideMyTraffic, setHideMyTraffic] = useState(true);

  if (!websites || websites.length === 0) {
    return (
      <div className="bg-slate-800/40 backdrop-blur-md border
      border-white/5 rounded-2xl p-12 text-center">
        <div className="text-5xl mb-4">🌐</div>
        <p className="text-slate-400 font-medium">No websites detected</p>
        <p className="text-slate-600 text-sm mt-2">
          Try capturing with Wireshark while browsing,
          or enable TLS/DNS dissection
        </p>
      </div>
    );
  }

  // Split sites into mine vs. others
  const mySites    = selfIp ? websites.filter(s => s.srcIps?.includes(selfIp)) : [];
  const otherSites = selfIp ? websites.filter(s => !s.srcIps?.includes(selfIp)) : websites;
  const visibleSites = (selfIp && hideMyTraffic) ? otherSites : websites;

  const categories = [...new Set(visibleSites.map(w => w.category))];

  return (
    <div className="space-y-6">

      {/* Self-device banner or toggle */}
      {!selfIp ? (
        <div className="bg-blue-900/20 border border-blue-800/40 rounded-2xl
        px-5 py-4 flex items-center justify-between gap-4">
          <p className="text-blue-300 text-sm">
            ℹ️ Seeing your own browsing here? Mark your device in the Devices tab
            to separate your traffic from other devices on the network.
          </p>
          {onGoToDevices && (
            <button
              onClick={onGoToDevices}
              className="flex-shrink-0 text-xs bg-blue-700/50 hover:bg-blue-600/60
              text-blue-200 px-3 py-1.5 rounded-lg transition-all"
            >
              Go to Devices ↓
            </button>
          )}
        </div>
      ) : mySites.length > 0 && (
        <div className="bg-blue-900/20 border border-blue-800/40 rounded-2xl
        px-5 py-3 flex items-center justify-between gap-4">
          <span className="text-blue-300 text-sm">
            🏠 {mySites.length} site{mySites.length !== 1 ? 's' : ''} hidden — your device ({selfIp})
          </span>
          <button
            onClick={() => setHideMyTraffic(h => !h)}
            className="flex-shrink-0 text-xs bg-blue-700/50 hover:bg-blue-600/60
            text-blue-200 px-3 py-1.5 rounded-lg transition-all"
          >
            {hideMyTraffic ? 'Show my traffic' : 'Hide my traffic'}
          </button>
        </div>
      )}

      {/* Category Summary */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {categories.slice(0, 4).map((cat) => {
          const count = visibleSites.filter(w => w.category === cat).length;
          return (
            <div key={cat} className="bg-slate-800/40 backdrop-blur-md
            border border-white/5 rounded-2xl p-4 text-center">
              <div className="text-2xl mb-1">{cat.split(' ')[0]}</div>
              <div className="text-white font-bold">{count}</div>
              <div className="text-slate-500 text-xs">
                {cat.split(' ').slice(1).join(' ')}
              </div>
            </div>
          );
        })}
      </div>

      {/* Sites Table */}
      <div className="bg-slate-800/40 backdrop-blur-md border
      border-white/5 rounded-2xl p-6">
        <h2 className="text-lg font-semibold text-white mb-4
        flex items-center gap-2">
          <span className="w-2 h-2 rounded-full bg-blue-400
          shadow-[0_0_8px_rgba(96,165,250,0.8)]"></span>
          Sites Visited on Your Network
          <span className="text-slate-500 text-sm font-normal ml-1">
            ({visibleSites.length} domains)
          </span>
        </h2>
        <div className="overflow-auto max-h-[500px]">
          <table className="w-full text-sm">
            <thead className="sticky top-0 bg-slate-800">
              <tr className="text-slate-400 border-b border-white/5">
                <th className="text-left pb-3 pr-4">Site</th>
                <th className="text-left pb-3 pr-4">Category</th>
                <th className="text-left pb-3 pr-4">Security</th>
                <th className="text-right pb-3">Requests</th>
              </tr>
            </thead>
            <tbody>
              {visibleSites.map((site, i) => (
                <tr key={i} className="border-b border-white/5
                hover:bg-slate-700/30 transition-colors">
                  <td className="py-3 pr-4">
                    <div className="flex items-center gap-2">
                      <span className="text-xl">{site.icon}</span>
                      <div>
                        <div className="text-white text-xs font-medium
                        truncate max-w-[200px]">
                          {site.domain}
                        </div>
                        {site.failed > 0 && (
                          <div className="text-red-400 text-xs">
                            ⚠️ {site.failed} failed lookups
                          </div>
                        )}
                      </div>
                    </div>
                  </td>
                  <td className="py-3 pr-4 text-slate-400 text-xs">
                    {site.category}
                  </td>
                  <td className="py-3 pr-4">
                    {site.encrypted === true ? (
                      <span className="bg-green-900/50 text-green-400
                      text-xs px-2 py-1 rounded-full border border-green-800">
                        🔒 HTTPS
                      </span>
                    ) : site.encrypted === false ? (
                      <span className="bg-red-900/50 text-red-400
                      text-xs px-2 py-1 rounded-full border border-red-800">
                        ⚠️ HTTP
                      </span>
                    ) : null}
                  </td>
                  <td className="py-3 text-right">
                    <div className="flex items-center justify-end gap-2">
                      <div className="w-16 bg-slate-700 rounded-full h-1.5">
                        <div
                          className="bg-gradient-to-r from-blue-500
                          to-cyan-400 h-1.5 rounded-full"
                          style={{
                            width: `${Math.min(100,
                              (site.count / (visibleSites[0]?.count || 1)) * 100)}%`
                          }}
                        />
                      </div>
                      <span className="text-slate-400 text-xs w-8 text-right">
                        {site.count}
                      </span>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Tracker Detection */}
      {trackers && trackers.length > 0 && (
        <div className="bg-slate-800/40 backdrop-blur-md border
        border-white/5 rounded-2xl p-6">
          <h2 className="text-lg font-semibold text-white mb-2
          flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-red-400
            shadow-[0_0_8px_rgba(248,113,113,0.8)]"></span>
            👁️ Who Is Tracking You
            <span className="text-slate-500 text-sm font-normal">
              ({trackers.length} trackers detected)
            </span>
          </h2>
          <p className="text-slate-500 text-xs mb-4">
            These advertising and analytics domains were contacted
            by devices on your network
          </p>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {trackers.map((tracker, i) => (
              <div key={i} className="bg-slate-900/50 rounded-xl p-4
              border border-red-900/30 flex items-center justify-between
              hover:border-red-700/50 transition-all">
                <div className="flex items-center gap-3">
                  <span className="text-xl">{tracker.icon}</span>
                  <div>
                    <div className="text-white text-xs font-medium">
                      {tracker.domain}
                    </div>
                    <div className="text-slate-500 text-xs">{tracker.type}</div>
                  </div>
                </div>
                <span className="bg-red-900/40 text-red-400
                text-xs px-2 py-1 rounded-full font-mono">
                  {tracker.count}x
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

    </div>
  );
}
