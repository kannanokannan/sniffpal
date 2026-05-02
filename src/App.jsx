import { useState, useCallback } from 'react';
import FileUpload from './components/FileUpload';
import DeviceTable from './components/DeviceTable';
import ProtocolChart from './components/ProtocolChart';
import SummaryCards from './components/SummaryCards';
import WebsitesTab from './components/WebsitesTab';
import SecurityTab from './components/SecurityTab';
import PrivacyReport from './components/PrivacyReport';
import { Activity, AlertTriangle, Cpu } from 'lucide-react';

export default function App() {
  const [parsedData, setParsedData] = useState(null);
  const [progress, setProgress] = useState(null);
  // progress = { value: 0-100, label: string } | null

  const handleFile = useCallback((file) => {
    setParsedData(null);
    setProgress({ value: 0, label: "Reading file..." });

    const reader = new FileReader();

    reader.onload = (e) => {
      const text = e.target.result;

      // ── Spawn Web Worker ──────────────────────────
      const worker = new Worker(
        new URL('./workers/parser.worker.js', import.meta.url),
        { type: 'module' }
      );

      worker.postMessage({ text, fileSize: file.size });

      worker.onmessage = (msg) => {
        const { type, value, label, data, message } = msg.data;

        if (type === 'progress') {
          setProgress({ value, label });
        }

        if (type === 'result') {
          setParsedData(data);
          setProgress(null);
          worker.terminate();
        }

        if (type === 'error') {
          alert(message);
          setProgress(null);
          worker.terminate();
        }
      };

      worker.onerror = (err) => {
        alert("Worker error: " + err.message);
        setProgress(null);
        worker.terminate();
      };
    };

    reader.readAsText(file);
  }, []);

  const criticalAlerts = parsedData?.security?.filter(
    a => a.severity === "critical"
  ) || [];

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
                Network Intelligence Tool · v1.1.0
              </p>
            </div>
          </div>

          {parsedData && (
            <div className="flex items-center gap-4">
              {parsedData.sampled && (
                <div className="flex items-center gap-2
                bg-yellow-900/30 border border-yellow-800/50
                px-3 py-1.5 rounded-full">
                  <Cpu className="w-3.5 h-3.5 text-yellow-400" />
                  <span className="text-yellow-400 text-xs font-medium">
                    Sampled {parsedData.processedPackets.toLocaleString()}
                    /{parsedData.totalPackets.toLocaleString()} packets
                  </span>
                </div>
              )}
              {criticalAlerts.length > 0 && (
                <div className="flex items-center gap-2
                bg-red-900/30 border border-red-800/50
                px-3 py-1.5 rounded-full">
                  <AlertTriangle className="w-3.5 h-3.5 text-red-400" />
                  <span className="text-red-400 text-xs font-medium">
                    {criticalAlerts.length} threat{criticalAlerts.length > 1 ? "s" : ""} detected
                  </span>
                </div>
              )}
              <span className="text-slate-500 text-xs">
                {parsedData.totalPackets.toLocaleString()} packets
                · {parsedData.fileSizeMB} MB file
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
      </header>

      {/* Main */}
      <main className="max-w-7xl mx-auto px-6 py-8 relative z-10">

        {/* ── Progress Screen ─────────────────────── */}
        {progress && (
          <div className="flex flex-col items-center
          justify-center min-h-[75vh] gap-6">
            <div className="text-center">
              <div className="text-5xl mb-4">🔍</div>
              <h2 className="text-xl font-bold text-white mb-1">
                Analysing Your Capture
              </h2>
              <p className="text-slate-400 text-sm">
                Running in background — UI stays responsive
              </p>
            </div>

            {/* Progress Bar */}
            <div className="w-full max-w-md">
              <div className="flex justify-between text-xs
              text-slate-400 mb-2">
                <span>{progress.label}</span>
                <span>{progress.value}%</span>
              </div>
              <div className="w-full bg-slate-800 rounded-full h-2">
                <div
                  className="bg-gradient-to-r from-cyan-500
                  to-blue-500 h-2 rounded-full transition-all
                  duration-300"
                  style={{ width: `${progress.value}%` }}
                />
              </div>
              <p className="text-slate-600 text-xs mt-3 text-center">
                Large files are sampled intelligently —
                first 25,000 packets analysed
              </p>
            </div>
          </div>
        )}

        {/* ── Upload Screen ───────────────────────── */}
        {!parsedData && !progress && (
          <div className="flex flex-col items-center
          justify-center min-h-[75vh]">
            <div className="text-center mb-8">
              <h2 className="text-3xl font-bold text-white mb-2">
                Your Network. Instantly Understood.
              </h2>
              <p className="text-slate-400 text-sm max-w-md mx-auto">
                Like Chrome DevTools — but for your entire network.
                Drop any size Wireshark file. Processed locally,
                never uploaded.
                <span className="text-green-400"> 100% private.</span>
              </p>
              <div className="flex items-center justify-center
              gap-6 mt-4 text-xs text-slate-500">
                <span>📱 Devices</span>
                <span>🌐 Websites</span>
                <span>👁️ Trackers</span>
                <span>⚠️ Security</span>
                <span>🔥 500MB+ support</span>
              </div>
            </div>
            <FileUpload onFile={handleFile} />
            <p className="mt-6 text-slate-600 text-xs">
              Wireshark: File → Export Packet Dissections → As JSON
            </p>
          </div>
        )}

        {/* ── Dashboard ───────────────────────────── */}
        {parsedData && !progress && (
          <div className="space-y-6">

            {/* Sampling notice */}
            {parsedData.sampled && (
              <div className="bg-yellow-900/20 border
              border-yellow-800/40 rounded-2xl p-4 flex
              items-start gap-3">
                <Cpu className="w-5 h-5 text-yellow-400
                flex-shrink-0 mt-0.5" />
                <div>
                  <p className="text-yellow-400 font-medium text-sm">
                    Large File — Intelligent Sampling Applied
                  </p>
                  <p className="text-slate-400 text-xs mt-0.5">
                    File size: {parsedData.fileSizeMB} MB ·
                    Total packets: {parsedData.totalPackets.toLocaleString()} ·
                    Analysed: {parsedData.processedPackets.toLocaleString()} evenly
                    sampled packets across entire capture.
                    Results are statistically representative.
                  </p>
                </div>
              </div>
            )}

            {/* Summary Cards */}
            <SummaryCards data={parsedData} />

            {/* Critical Alerts Strip */}
            {criticalAlerts.length > 0 && (
              <div className="bg-red-900/20 border
              border-red-800/40 rounded-2xl p-4">
                <div className="flex items-center gap-2 mb-3">
                  <AlertTriangle className="w-4 h-4 text-red-400" />
                  <span className="text-red-400 font-semibold text-sm">
                    Security Threats Detected
                  </span>
                </div>
                <div className="space-y-2">
                  {criticalAlerts.map((alert, i) => (
                    <div key={i} className="flex items-start gap-3
                    bg-red-900/20 rounded-xl p-3">
                      <span className="text-lg">{alert.icon}</span>
                      <div>
                        <div className="text-white text-xs font-medium">
                          {alert.title}
                        </div>
                        <div className="text-slate-400 text-xs mt-0.5">
                          {alert.detail}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Charts + Privacy side by side */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              <div className="lg:col-span-2">
                <ProtocolChart
                  protocols={parsedData.protocols}
                  devices={parsedData.devices}
                  trafficTypes={parsedData.trafficTypes}
                />
              </div>
              <div className="lg:col-span-1 min-h-[400px]">
                <PrivacyReport trackers={parsedData.trackers} />
              </div>
            </div>

            {/* Devices */}
            <DeviceTable devices={parsedData.devices} />

            {/* Websites */}
            <WebsitesTab
              websites={parsedData.websites}
              trackers={parsedData.trackers}
            />

            {/* Security */}
            <SecurityTab
              alerts={parsedData.security}
              retransmissions={parsedData.retransmissions}
              avgRtt={parsedData.avgRtt}
              nxdomainCount={parsedData.nxdomainCount}
            />

          </div>
        )}
      </main>

      <div className="text-center text-slate-700 text-xs py-6">
        SniffPal v1.1.0 — Open Source Network Intelligence ·
        <a
          href="https://github.com/kannanokannan/sniffpal"
          target="_blank"
          rel="noreferrer"
          className="hover:text-cyan-600 transition-colors ml-1"
        >
          GitHub ⭐
        </a>
      </div>
    </div>
  );
}
