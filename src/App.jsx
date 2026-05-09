import { useState, useCallback, useEffect } from 'react';
import FileUpload from './components/FileUpload';
import DeviceTable from './components/DeviceTable';
import ProtocolChart from './components/ProtocolChart';
import SummaryCards from './components/SummaryCards';
import WebsitesTab from './components/WebsitesTab';
import SecurityTab from './components/SecurityTab';
import PrivacyReport from './components/PrivacyReport';
import HealthScore from './components/HealthScore';
import DataPanel from './components/DataPanel';
import PrintReport from './components/PrintReport';
import { saveSession, loadSession, clearSession, timeAgo } from './utils/useSession';
import { calculateHealthScore } from './utils/healthScore';
import { Activity, AlertTriangle, Cpu, Clock } from 'lucide-react';

export default function App() {
  const [parsedData, setParsedData] = useState(null);
  const [progress, setProgress] = useState(null);
  const [trustedDevices, setTrustedDevices] = useState(() => {
    try {
      const stored = JSON.parse(localStorage.getItem('sniffpal_trusted') || '[]');
      // Migrate: drop any legacy entries that are raw MACs (contain colons)
      const hashes = stored.filter(v => typeof v === 'string' && !v.includes(':'));
      if (hashes.length !== stored.length)
        localStorage.setItem('sniffpal_trusted', JSON.stringify(hashes));
      return hashes;
    } catch { return []; }
  });
  const [selectedDataPoint, setSelectedDataPoint] = useState(null);
  const [resumeSession, setResumeSession] = useState(null);
  const [healthScore, setHealthScore] = useState(null);
  const [currentFileName, setCurrentFileName] = useState(null);

  // ── Load saved session on startup ─────────────────
  useEffect(() => {
    loadSession().then(session => {
      if (session) setResumeSession(session);
    });
  }, []);

  // ── Trust device toggle ───────────────────────────
  const handleTrust = useCallback(async (mac) => {
    const buf = await crypto.subtle.digest(
      'SHA-256', new TextEncoder().encode(mac.toLowerCase())
    );
    const hash = Array.from(new Uint8Array(buf))
      .map(b => b.toString(16).padStart(2, '0')).join('');
    setTrustedDevices(prev => {
      const updated = prev.includes(hash)
        ? prev.filter(h => h !== hash)
        : [...prev, hash];
      localStorage.setItem('sniffpal_trusted', JSON.stringify(updated));
      return updated;
    });
  }, []);

  // ── Handle file parse ─────────────────────────────
  const handleFile = useCallback((file) => {
    setParsedData(null);
    setResumeSession(null);
    setSelectedDataPoint(null);
    setProgress({ value: 0, label: 'Reading file…' });

    const worker = new Worker(
      new URL('./workers/parser.worker.js', import.meta.url),
      { type: 'module' }
    );

    worker.onmessage = (msg) => {
      const { type, value, label, data, message } = msg.data;
      if (type === 'progress') setProgress({ value, label });
      if (type === 'result') {
        const score = calculateHealthScore(data);
        setParsedData(data);
        setHealthScore(score);
        setCurrentFileName(file.name);
        setProgress(null);
        saveSession(data, file.name);
        worker.terminate();
      }
      if (type === 'error') {
        alert(message);
        setProgress(null);
        worker.terminate();
      }
    };

    worker.onerror = (err) => {
      alert('Worker error: ' + err.message);
      setProgress(null);
      worker.terminate();
    };

    // Pass the File reference directly — zero copy, no main-thread reading.
    // The worker slices it in 16 MB chunks so memory stays bounded regardless of size.
    worker.postMessage({ file, fileSize: file.size });
  }, []);

  // ── Resume session ────────────────────────────────
  const handleResume = useCallback(() => {
    if (resumeSession) {
      const score = calculateHealthScore(resumeSession.data);
      setParsedData(resumeSession.data);
      setHealthScore(score);
      setResumeSession(null);
    }
  }, [resumeSession]);

  const handleClearSession = useCallback(() => {
    clearSession();
    setResumeSession(null);
  }, []);

  const criticalAlerts = parsedData?.security?.filter(
    a => a.severity === 'critical'
  ) || [];

  return (
    <>
    <div className="print:hidden min-h-screen bg-slate-950 text-slate-200
    font-sans relative overflow-hidden">

      {/* Background Orbs */}
      <div className="absolute top-[-10%] left-[-10%] w-96 h-96
      bg-cyan-600/20 rounded-full blur-[128px] pointer-events-none"/>
      <div className="absolute bottom-[-10%] right-[-10%] w-96 h-96
      bg-blue-600/10 rounded-full blur-[128px] pointer-events-none"/>

      {/* Header */}
      <header className="bg-slate-900/50 backdrop-blur-lg
      border-b border-white/5 sticky top-0 z-20">
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
                Network Intelligence · v2.1
              </p>
            </div>
          </div>

          {parsedData && (
            <div className="flex items-center gap-3 flex-wrap justify-end">
              {parsedData.sampled && (
                <div className="flex items-center gap-2
                bg-yellow-900/30 border border-yellow-800/50
                px-3 py-1.5 rounded-full">
                  <Cpu className="w-3.5 h-3.5 text-yellow-400" />
                  <span className="text-yellow-400 text-xs font-medium">
                    Sampled {parsedData.processedPackets?.toLocaleString()}
                    /{parsedData.totalPackets?.toLocaleString()}
                  </span>
                </div>
              )}
              {criticalAlerts.length > 0 && (
                <div className="flex items-center gap-2
                bg-red-900/30 border border-red-800/50
                px-3 py-1.5 rounded-full">
                  <AlertTriangle className="w-3.5 h-3.5 text-red-400" />
                  <span className="text-red-400 text-xs font-medium">
                    {criticalAlerts.length} threat{criticalAlerts.length > 1 ? 's' : ''}
                  </span>
                </div>
              )}
              {healthScore && (
                <div className={`flex items-center gap-2
                px-3 py-1.5 rounded-full border
                ${healthScore.score >= 80
                  ? 'bg-green-900/30 border-green-800/50'
                  : healthScore.score >= 60
                  ? 'bg-yellow-900/30 border-yellow-800/50'
                  : 'bg-red-900/30 border-red-800/50'
                }`}>
                  <span className={`text-xs font-bold
                  ${healthScore.color}`}>
                    {healthScore.grade} · {healthScore.score}/100
                  </span>
                </div>
              )}
              <span className="text-slate-500 text-xs hidden md:block">
                {parsedData.totalPackets?.toLocaleString()} pkts
                · {parsedData.fileSizeMB} MB
              </span>
              <button
                onClick={() => window.print()}
                className="text-sm bg-cyan-600 hover:bg-cyan-500
                text-white px-4 py-1.5 rounded-xl transition-all
                font-medium flex items-center gap-1.5"
              >
                📄 Generate Report
              </button>
              <button
                onClick={() => {
                  setParsedData(null);
                  setSelectedDataPoint(null);
                  setHealthScore(null);
                  setCurrentFileName(null);
                }}
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

        {/* ── Progress ────────────────────────────── */}
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
            <div className="w-full max-w-md">
              <div className="flex justify-between text-xs
              text-slate-400 mb-2">
                <span>{progress.label}</span>
                <span>{progress.value}%</span>
              </div>
              <div className="w-full bg-slate-800 rounded-full h-2">
                <div
                  className="bg-gradient-to-r from-cyan-500
                  to-blue-500 h-2 rounded-full transition-all duration-300"
                  style={{ width: `${progress.value}%` }}
                />
              </div>
              <p className="text-slate-600 text-xs mt-3 text-center">
                Large files sampled intelligently across entire capture
              </p>
            </div>
          </div>
        )}

        {/* ── Upload Screen ────────────────────────── */}
        {!parsedData && !progress && (
          <div className="flex flex-col items-center
          justify-center min-h-[75vh]">

            {/* Resume Banner */}
            {resumeSession && (
              <div className="w-full max-w-2xl mb-6
              bg-slate-800/60 backdrop-blur-md border
              border-cyan-500/20 rounded-2xl p-5">
                <div className="flex items-start justify-between gap-4">
                  <div className="flex items-start gap-3">
                    <Clock className="w-5 h-5 text-cyan-400
                    flex-shrink-0 mt-0.5" />
                    <div>
                      <p className="text-white font-medium text-sm">
                        Resume last session?
                      </p>
                      <p className="text-slate-400 text-xs mt-0.5">
                        {resumeSession.fileName} ·{' '}
                        {resumeSession.data.totalPackets?.toLocaleString()} packets ·{' '}
                        {timeAgo(resumeSession.savedAt)}
                      </p>
                    </div>
                  </div>
                  <div className="flex gap-2 flex-shrink-0">
                    <button
                      onClick={handleResume}
                      className="bg-cyan-600 hover:bg-cyan-500
                      text-white text-xs px-4 py-2 rounded-xl
                      transition-all font-medium"
                    >
                      Resume
                    </button>
                    <button
                      onClick={handleClearSession}
                      className="bg-slate-700 hover:bg-slate-600
                      text-slate-300 text-xs px-4 py-2 rounded-xl
                      transition-all"
                    >
                      Clear
                    </button>
                  </div>
                </div>
              </div>
            )}

            <div className="text-center mb-8">
              <h2 className="text-3xl font-bold text-white mb-2">
                Your Network. Instantly Understood.
              </h2>
              <p className="text-slate-400 text-sm max-w-md mx-auto">
                Like Chrome DevTools — but for your entire network.
                Drop any Wireshark file. 100% local. Never uploaded.
                <span className="text-green-400"> Zero privacy risk.</span>
              </p>
              <div className="flex items-center justify-center
              gap-4 mt-4 text-xs text-slate-500 flex-wrap">
                <span>📱 Devices</span>
                <span>🌐 Websites</span>
                <span>👁️ Trackers</span>
                <span>⚠️ Security</span>
                <span>🏠 IoT</span>
                <span>📊 Health Score</span>
              </div>
            </div>
            <FileUpload onFile={handleFile} />
            <p className="mt-6 text-slate-600 text-xs">
              Wireshark: File → Export Packet Dissections → As JSON
            </p>
          </div>
        )}

        {/* ── Dashboard ────────────────────────────── */}
        {parsedData && !progress && (
          <div className="space-y-6">

            {/* Sampling notice */}
            {parsedData.sampled && (
              <div className="bg-yellow-900/20 border
              border-yellow-800/40 rounded-2xl p-4
              flex items-start gap-3">
                <Cpu className="w-5 h-5 text-yellow-400
                flex-shrink-0 mt-0.5" />
                <div>
                  <p className="text-yellow-400 font-medium text-sm">
                    Large File — Intelligent Sampling Applied
                  </p>
                  <p className="text-slate-400 text-xs mt-0.5">
                    {parsedData.fileSizeMB} MB file ·
                    {parsedData.totalPackets?.toLocaleString()} total packets ·
                    Analysed {parsedData.processedPackets?.toLocaleString()} evenly
                    sampled — results are statistically representative
                  </p>
                </div>
              </div>
            )}

            {/* Health Score */}
            {healthScore && (
              <HealthScore score={healthScore} />
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
                    <div key={i} className="flex items-start
                    gap-3 bg-red-900/20 rounded-xl p-3">
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

            {/* Charts + Privacy + Data Panel */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              <div className="lg:col-span-2">
                <ProtocolChart
                  protocols={parsedData.protocols}
                  devices={parsedData.devices}
                  trafficTypes={parsedData.trafficTypes}
                  onDataClick={setSelectedDataPoint}
                />
              </div>
              <div className="flex flex-col gap-6">
                <PrivacyReport trackers={parsedData.trackers} />
              </div>
            </div>

            {/* Data Panel — shows when chart clicked */}
            {selectedDataPoint && (
              <DataPanel
                data={selectedDataPoint}
                devices={parsedData.devices}
                onClose={() => setSelectedDataPoint(null)}
              />
            )}

            {/* Device Table */}
            <DeviceTable
              devices={parsedData.devices}
              trustedDevices={trustedDevices}
              onTrust={handleTrust}
              onDeviceClick={setSelectedDataPoint}
            />

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
        SniffPal v2.1 — Open Source Network Intelligence ·
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

    {/* Print-only report — hidden on screen, visible when window.print() fires */}
    <div className="hidden print:block">
      <PrintReport
        data={parsedData}
        healthScore={healthScore}
        fileName={currentFileName}
      />
    </div>
    </>
  );
}
