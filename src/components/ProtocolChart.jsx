import { PieChart, Pie, Cell, BarChart, Bar, XAxis, 
  YAxis, Tooltip, ResponsiveContainer } from 'recharts';

const COLORS = ['#22d3ee','#3b82f6','#6366f1',
  '#8b5cf6','#a855f7','#64748b','#06b6d4'];

const tooltipStyle = {
  backgroundColor: 'rgba(15, 23, 42, 0.9)',
  backdropFilter: 'blur(8px)',
  border: '1px solid rgba(255,255,255,0.1)',
  borderRadius: '0.75rem',
  color: '#e2e8f0',
  boxShadow: '0 0 20px rgba(0,0,0,0.3)'
};

export default function ProtocolChart({ protocols, devices }) {
  // Build top talkers from devices
  const talkerData = (devices || [])
    .slice(0, 6)
    .map(d => ({ ip: d.mac, count: d.packets }));

  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">

      {/* Protocol Pie Chart */}
      <div className="bg-slate-800/40 backdrop-blur-md border 
      border-white/5 rounded-2xl p-6 flex flex-col shadow-lg 
      hover:border-white/10 transition-colors">
        <h3 className="text-lg font-semibold text-white mb-4 
        tracking-wide flex items-center gap-2">
          <span className="w-2 h-2 rounded-full bg-cyan-400 
          shadow-[0_0_8px_rgba(34,211,238,0.8)]"></span>
          Protocol Distribution
        </h3>
        <div className="min-h-[300px]">
          <ResponsiveContainer width="100%" height={300}>
            <PieChart>
              <Pie
                data={protocols}
                cx="50%"
                cy="50%"
                innerRadius={80}
                outerRadius={120}
                paddingAngle={3}
                dataKey="value"
                stroke="none"
                label={({ name, percent }) => 
                  `${name} ${(percent * 100).toFixed(0)}%`}
                labelLine={false}
              >
                {protocols.map((_, index) => (
                  <Cell key={`cell-${index}`} 
                  fill={COLORS[index % COLORS.length]} />
                ))}
              </Pie>
              <Tooltip contentStyle={tooltipStyle} 
              itemStyle={{ color: '#e2e8f0' }} />
            </PieChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Top Talkers Bar Chart */}
      <div className="bg-slate-800/40 backdrop-blur-md border 
      border-white/5 rounded-2xl p-6 flex flex-col shadow-lg 
      hover:border-white/10 transition-colors">
        <h3 className="text-lg font-semibold text-white mb-4 
        tracking-wide flex items-center gap-2">
          <span className="w-2 h-2 rounded-full bg-blue-500 
          shadow-[0_0_8px_rgba(59,130,246,0.8)]"></span>
          Top Talkers
        </h3>
        <div className="min-h-[300px]">
          <ResponsiveContainer width="100%" height={300}>
            <BarChart data={talkerData} layout="vertical"
            margin={{ top: 0, right: 0, left: 40, bottom: 0 }}>
              <defs>
                <linearGradient id="colorCyan" x1="0" y1="0" 
                x2="1" y2="0">
                  <stop offset="0%" stopColor="#3b82f6" 
                  stopOpacity={0.8}/>
                  <stop offset="100%" stopColor="#22d3ee" 
                  stopOpacity={1}/>
                </linearGradient>
              </defs>
              <XAxis type="number" stroke="#64748b" fontSize={12}
              tickLine={false} axisLine={false} />
              <YAxis dataKey="ip" type="category" stroke="#94a3b8"
              fontSize={10} width={130} tickLine={false} 
              axisLine={false} />
              <Tooltip cursor={{ fill: 'rgba(255,255,255,0.05)' }}
              contentStyle={tooltipStyle} />
              <Bar dataKey="count" fill="url(#colorCyan)" 
              radius={[0, 4, 4, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

    </div>
  );
}