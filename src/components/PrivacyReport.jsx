import { Eye } from 'lucide-react';

export default function PrivacyReport({ trackers }) {
  if (!trackers || trackers.length === 0) return (
    <div className="bg-slate-800/40 backdrop-blur-md border
    border-white/5 rounded-2xl p-6 shadow-lg h-full flex
    flex-col items-center justify-center text-center">
      <div className="text-4xl mb-3">🛡️</div>
      <p className="text-slate-400 font-medium text-sm">
        No Trackers Detected
      </p>
      <p className="text-slate-600 text-xs mt-1">
        No ad networks or telemetry servers found
      </p>
    </div>
  );

  const totalPings = trackers.reduce((sum, t) => sum + t.count, 0);

  return (
    <div className="bg-slate-800/40 backdrop-blur-md border
    border-white/5 rounded-2xl p-6 shadow-lg h-full flex flex-col">

      {/* Header */}
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-base font-semibold text-white
        tracking-wide flex items-center gap-2">
          <span className="w-2 h-2 rounded-full bg-fuchsia-500
          shadow-[0_0_8px_rgba(217,70,239,0.8)]"></span>
          Privacy Report
        </h3>
        <span className="bg-fuchsia-500/10 text-fuchsia-400
        border border-fuchsia-500/20 px-3 py-1 rounded-full
        text-xs font-semibold">
          {totalPings} pings
        </span>
      </div>

      <p className="text-xs text-slate-500 mb-4">
        Ad networks and telemetry servers contacted
        during this capture.
      </p>

      {/* Tracker List */}
      <div className="overflow-y-auto flex-1 space-y-2">
        {trackers.map((tracker, i) => (
          <div key={i}
            className="flex items-center justify-between
            p-3 rounded-xl bg-slate-900/40 border border-white/5
            group hover:bg-slate-900/80 hover:border-fuchsia-500/30
            transition-all">
            <div className="flex items-center gap-2">
              <Eye className="w-3.5 h-3.5 text-slate-500
              group-hover:text-fuchsia-400 transition-colors
              flex-shrink-0" />
              <div>
                <div className="text-slate-300 font-mono text-xs
                truncate max-w-[140px]">
                  {tracker.domain}
                </div>
                <div className="text-slate-600 text-xs">
                  {tracker.type}
                </div>
              </div>
            </div>
            <span className="text-fuchsia-400 font-medium
            text-xs flex-shrink-0">
              {tracker.count}x
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}
