import { useState } from 'react';
import FileUpload from './components/FileUpload';
import DeviceTable from './components/DeviceTable';
import ProtocolChart from './components/ProtocolChart';
import SummaryCards from './components/SummaryCards';
import WebsitesTab from './components/WebsitesTab';
import SecurityTab from './components/SecurityTab';
import { parseWiresharkJSON } from './utils/parser';
import { Activity, Monitor, Globe, Shield, BarChart2 } from 'lucide-react';

const TABS = [
  { id: "overview",  label: "Overview",  icon: BarChart2 },
  { id: "devices",   label: "Devices",   icon: Monitor   },
  { id: "websites",  label: "Websites",  icon: Globe     },
  { id: "security",  label: "Security",  icon: Shield    },
];

export default function App() {
  const [parsedData, setParsedData] = useState(null);
  const [activeTab, setActiveTab] = useState("overview");

  function handleFile(file) {
    const reader = new FileReader();
    reader.onload = (e) => {
      try {
        const json = JSON.parse(e.target.result);
        const data = parseWiresharkJSON(json);
        setParsedData(data);
        setActiveTab("overview");
      } catch {
        alert("Invalid file! Export from Wireshark as JSON.");
      }
    };
    reader.readAsText(file);
  }

  return (
    <div className="min-h-screen bg-slate-950 text-slate-200
    font-sans relative overflow-hidden">

      {/* Background Orbs */}
      <div className="absolute top-[-10%] left-[-10%] w-96 h-96
      bg-cyan-600/20 rounded-full blur-[128px] pointer-events-none"/>
      <div className="absolute bottom-[-10%] right-[-10%] w-96 h-96
      bg-blue-600/10 rounded-full blur-[128px] pointer-events-none"/>

      {/* Header */}
      <header className="bg-slate-900/50 backdrop-blur-lg border-b
      border-white/5 sticky top-0 z-20">
        <div className="max-w-7xl mx-auto px-6 py-4 flex
        items-center justify-between">
          <div className="flex items-center gap-3">
            <Activity className="w-8 h-8 text-cyan-400
            drop-shadow-[0_0_8px_rgba(34,211,238,0.8)]" />
            <div>
              <h1 className="text-xl font-bold bg-gradient-to-r
              from-cyan-400 via-blue-400 to-indigo-400
              bg-clip-text text-transparent">
                SniffPal
              </h1>
              <p className="text-slate-500 text-xs">
                Network Intelligence Tool
              </p>
            </div>
          </div>
          {parsedData && (
            <div className="flex items-center gap-4">
              <span className="text-slate-500 text-xs">
                {parsedData.totalPackets.toLocaleString()} packets
                · {parsedData.totalMB} MB
              </span>
              <button
                onClick={() => setParsedData(null)}
                className="text-sm text-slate-400
                hover:text-cyan-400 transition-all"
              >
                ← New File
              </button>
            </div>
          )}
        </div>

        {/* Tabs */}
        {parsedData && (
          <div className="max-w-7xl mx-auto px-6 flex gap-1 pb-0">
            {TABS.map((tab) => {
              const Icon = tab.icon;
              const isActive = activeTab === tab.id;
              const alertCount = tab.id === "security"
                ? parsedData.security.filter(a => a.severity !== "good").length
                : tab.id === "websites" && parsedData.trackers?.length > 0
                ? parsedData.trackers.length
                : null;
              return (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id)}
                  className={`flex items-center gap-2 px-4 py-3
                  text-sm font-medium border-b-2 transition-all
                  relative ${isActive
                    ? "border-cyan-400 text-cyan-400"
                    : "border-transparent text-slate-400 hover:text-slate-200"
                  }`}
                >
                  <Icon className="w-4 h-4" />
                  {tab.label}
                  {alertCount > 0 && (
                    <span className="bg-red-500 text-white text-xs
                    rounded-full w-4 h-4 flex items-center
                    justify-center font-bold">
                      {alertCount}
                    </span>
                  )}
                </button>
              );
            })}
          </div>
        )}
      </header>

      {/* Main */}
      <main className="max-w-7xl mx-auto px-6 py-8 relative z-10">
        {!parsedData ? (
          <div className="flex flex-col items-center
          justify-center min-h-[75vh]">
            <div className="text-center mb-8">
              <h2 className="text-3xl font-bold text-white mb-2">
                Your Network. Instantly Understood.
              </h2>
              <p className="text-slate-400 text-sm max-w-md mx-auto">
                Like Chrome DevTools — but for your entire network.
                Drop a Wireshark file and see every device,
                website, and security alert.
                <span className="text-green-400"> 100% local.</span>
              </p>
              <div className="flex items-center justify-center
              gap-6 mt-4 text-xs text-slate-500">
                <span>📱 Device Detection</span>
                <span>🌐 Sites Visited</span>
                <span>⚠️ Security Alerts</span>
                <span>👁️ Tracker Detection</span>
              </div>
            </div>
            <FileUpload onFile={handleFile} />
            <p className="mt-6 text-slate-600 text-xs">
              Export from Wireshark: File → Export Packet Dissections → As JSON
            </p>
          </div>
        ) : (
          <div className="space-y-6">
            <SummaryCards data={parsedData} />

            {activeTab === "overview" && (
              <ProtocolChart
                protocols={parsedData.protocols}
                devices={parsedData.devices}
                trafficTypes={parsedData.trafficTypes}
              />
            )}

            {activeTab === "devices" && (
              <DeviceTable devices={parsedData.devices} />
            )}

            {activeTab === "websites" && (
              <WebsitesTab
                websites={parsedData.websites}
                trackers={parsedData.trackers}
              />
            )}

            {activeTab === "security" && (
              <SecurityTab
                alerts={parsedData.security}
                retransmissions={parsedData.retransmissions}
                avgRtt={parsedData.avgRtt}
                nxdomainCount={parsedData.nxdomainCount}
              />
            )}
          </div>
        )}
      </main>

      <div className="text-center text-slate-700 text-xs py-6">
        SniffPal — Open Source Network Intelligence
      </div>
    </div>
  );
}
