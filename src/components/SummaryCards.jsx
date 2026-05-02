import { Activity, HardDrive, Share2, Wifi } from 'lucide-react';

export default function SummaryCards({ data }) {
  const totalPackets = data?.totalPackets || 0;
  const totalDevices = data?.devices?.length || 0;
  const topTraffic = data?.trafficTypes?.[0]?.name || 'N/A';
  const totalMB = data?.totalMB || '0';

  const cards = [
    { title: 'Total Packets',  value: totalPackets.toLocaleString(),
      icon: Activity, color: 'text-cyan-400' },
    { title: 'Active Devices', value: totalDevices,
      icon: HardDrive, color: 'text-blue-400' },
    { title: 'Data Captured',  value: `${totalMB} MB`,
      icon: Wifi, color: 'text-indigo-400' },
    { title: 'Top Activity',   value: topTraffic,
      icon: Share2, color: 'text-violet-400' },
  ];

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 
    lg:grid-cols-4 gap-6">
      {cards.map((card, i) => (
        <div key={i} className="bg-slate-800/40 backdrop-blur-md 
        border border-white/5 rounded-2xl p-6 shadow-lg relative 
        overflow-hidden group hover:border-cyan-500/30 
        transition-all duration-300">
          <div className="absolute top-0 left-0 w-full h-1 
          bg-gradient-to-r from-cyan-500 to-blue-500 opacity-0 
          group-hover:opacity-100 transition-opacity duration-300">
          </div>
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-slate-400 mb-1">
                {card.title}
              </p>
              <h4 className="text-xl font-bold text-white 
              tracking-tight truncate max-w-[140px]">
                {card.value}
              </h4>
            </div>
            <div className={`p-3 rounded-xl bg-slate-900/50 
            border border-white/5 group-hover:scale-110 
            transition-transform duration-300 ${card.color}`}>
              <card.icon className="w-6 h-6" />
            </div>
          </div>
        </div>
      ))}
    </div>
  );
}