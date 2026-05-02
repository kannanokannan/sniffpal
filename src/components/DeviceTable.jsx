export default function DeviceTable({ devices }) {
  return (
    <div className="bg-slate-800/40 backdrop-blur-md border 
    border-white/5 rounded-2xl p-6 shadow-lg">
      <h2 className="text-lg font-semibold text-white mb-4 
      flex items-center gap-2">
        <span className="w-2 h-2 rounded-full bg-violet-400 
        shadow-[0_0_8px_rgba(167,139,250,0.8)]"></span>
        Devices on Your Network
      </h2>
      <div className="overflow-auto max-h-96">
        <table className="w-full text-sm">
          <thead>
            <tr className="text-slate-400 border-b border-white/5">
              <th className="text-left pb-3 pr-4">Device</th>
              <th className="text-left pb-3 pr-4">IP Address</th>
              <th className="text-left pb-3 pr-4">MAC</th>
              <th className="text-right pb-3">Activity</th>
            </tr>
          </thead>
          <tbody>
            {devices.map((device, index) => (
              <tr key={device.mac}
                className="border-b border-white/5 
                hover:bg-slate-700/30 transition-colors">

                {/* Device Icon + Name */}
                <td className="py-3 pr-4">
                  <div className="flex items-center gap-2">
                    <span className="text-2xl">{device.icon}</span>
                    <div>
                      <div className="text-white font-medium text-xs">
                        {device.hostname || device.nickname}
                      </div>
                      <div className="text-slate-500 text-xs">
                        {device.vendor}
                      </div>
                    </div>
                  </div>
                </td>

                {/* IP */}
                <td className="py-3 pr-4 text-cyan-400 
                font-mono text-xs">
                  {device.ip || "—"}
                </td>

                {/* MAC */}
                <td className="py-3 pr-4 text-slate-500 
                font-mono text-xs">
                  {device.mac}
                </td>

                {/* Activity bar */}
                <td className="py-3 text-right">
                  <div className="flex items-center 
                  justify-end gap-2">
                    <div className="w-16 bg-slate-700 
                    rounded-full h-1.5">
                      <div
                        className="bg-gradient-to-r from-cyan-500 
                        to-blue-500 h-1.5 rounded-full"
                        style={{
                          width: `${Math.min(100, 
                            (device.packets / devices[0].packets) 
                            * 100)}%`
                        }}
                      />
                    </div>
                    <span className="text-slate-400 text-xs 
                    w-12 text-right">
                      {device.packets.toLocaleString()}
                    </span>
                  </div>
                </td>

              </tr>
            ))}
          </tbody>
        </table>
        {devices.length === 0 && (
          <p className="text-center text-slate-600 py-8">
            No devices found
          </p>
        )}
      </div>
    </div>
  );
}