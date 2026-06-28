import { useState, useCallback, useEffect, useRef } from 'react';
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
import TopologyMap from './components/TopologyMap';
import { saveSession, loadSession, clearSession, timeAgo } from './utils/useSession';
import { calculateHealthScore } from './core/healthScore';
import { Activity, AlertTriangle, Cpu, Clock } from 'lucide-react';

function isPrivateLanHost(hostname) {
  return /^(10|192\.168|172\.(1[6-9]|2\d|3[0-1]))\./.test(hostname);
}

function isPiHost(hostname, port) {
  const host = hostname.toLowerCase();
  return host === 'sniffpal.local' ||
    host.endsWith('.local') ||
    ((host === 'localhost' || host === '127.0.0.1' || host === '::1') && port === '8080') ||
    isPrivateLanHost(host);
}

const IS_PI_MODE = isPiHost(window.location.hostname, window.location.port);
const DEFAULT_PI_SETTINGS = {
  interval: 10,
  interface: 'wlan0',
  mode: 'standard',
  monitorInterface: 'wlan1mon',
  monitorPackets: 500,
};

function formatUptime(seconds) {
  if (!seconds) return '0m';
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  if (days > 0) return `${days}d ${hours}h`;
  if (hours > 0) return `${hours}h ${minutes}m`;
  return `${minutes}m`;
}

function isPiDevice(device, piDevice) {
  if (!device || !piDevice) return false;
  if (piDevice.mac && device.mac?.toLowerCase() === piDevice.mac.toLowerCase()) return true;
  if (piDevice.ip && device.ip === piDevice.ip) return true;
  return false;
}

export default function App() {
  const [parsedData, setParsedData] = useState(null);
  const [progress, setProgress] = useState(null);
  const [trustedDevices, setTrustedDevices] = useState(() => {
    try {
      const stored = JSON.parse(sessionStorage.getItem('sniffpal_trusted') || '[]');
      // Migrate: drop any legacy entries that are raw MACs (contain colons)
      const hashes = stored.filter(v => typeof v === 'string' && !v.includes(':'));
      if (hashes.length !== stored.length)
        sessionStorage.setItem('sniffpal_trusted', JSON.stringify(hashes));
      return hashes;
    } catch { return []; }
  });
  const [selectedDataPoint, setSelectedDataPoint] = useState(null);
  const [resumeSession, setResumeSession] = useState(null);
  const [healthScore, setHealthScore] = useState(null);
  const [currentFileName, setCurrentFileName] = useState(null);
  const [selfIp, setSelfIp] = useState(() =>
    sessionStorage.getItem('sniffpal_self_ip') || null
  );
  const deviceTableRef = useRef(null);

  // ── Pi mode state ─────────────────────────────────
  const [piStatus, setPiStatus] = useState(null);
  const [piCapturing, setPiCapturing] = useState(false);
  const [piSettingsOpen, setPiSettingsOpen] = useState(false);
  const [piSettings, setPiSettings] = useState(() => {
    try {
      return {
        ...DEFAULT_PI_SETTINGS,
        ...(JSON.parse(localStorage.getItem('sniffpal_pi_settings') || 'null') || {}),
      };
    } catch { return DEFAULT_PI_SETTINGS; }
  });
  const piPollRef = useRef(null);
  const piEventRef = useRef(null);

  // ── Load saved session on startup ─────────────────
  useEffect(() => {
    loadSession().then(session => {
      if (session) setResumeSession(session);
    });
  }, []);

  // ── Pi mode: fetch status on mount + cleanup poll ─
  useEffect(() => {
    if (!IS_PI_MODE) return;
    fetchPiStatus();
    return () => {
      if (piPollRef.current) clearInterval(piPollRef.current);
      if (piEventRef.current) piEventRef.current.close();
    };
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

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
      sessionStorage.setItem('sniffpal_trusted', JSON.stringify(updated));
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
      new URL('./core/parser.worker.js', import.meta.url),
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

  const handleSetSelf = useCallback((ip) => {
    setSelfIp(ip);
    if (ip) sessionStorage.setItem('sniffpal_self_ip', ip);
    else sessionStorage.removeItem('sniffpal_self_ip');
  }, []);

  const scrollToDevices = useCallback(() => {
    deviceTableRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }, []);

  // ── Pi mode functions ─────────────────────────────
  const fetchPiStatus = useCallback(async () => {
    try {
      const res = await fetch('/api/status');
      const data = await res.json();
      setPiStatus(data);
      setPiCapturing(Boolean(data.capture?.running));
    } catch { /* server may not be ready yet */ }
  }, []);

  const handlePiLoadLatest = useCallback(async () => {
    try {
      setProgress({ value: 10, label: 'Fetching latest capture from Pi…' });
      const res = await fetch('/api/digests/latest');
      if (!res.ok) {
        alert('No captures available yet. Start a capture first.');
        setProgress(null);
        return;
      }
      const data = await res.json();
      const packets = data.packets || data;
      const blob = new Blob([JSON.stringify(packets)], { type: 'application/json' });
      const file = new File(
        [blob],
        `pi-capture-${data.timestamp || 'latest'}.json`,
        { type: 'application/json' }
      );
      handleFile(file);
    } catch (e) {
      alert('Failed to load capture: ' + e.message);
      setProgress(null);
    }
  }, [handleFile]);

  const handlePiStartCapture = useCallback(async () => {
    try {
      await fetch('/api/capture/start', { method: 'POST' });
      setPiCapturing(true);
      if (piPollRef.current) clearInterval(piPollRef.current);
      piPollRef.current = setInterval(fetchPiStatus, 3000);
      if (piEventRef.current) piEventRef.current.close();
      if (typeof EventSource !== 'undefined') {
        piEventRef.current = new EventSource('/api/capture/events');
        piEventRef.current.onmessage = event => {
          try {
            const capture = JSON.parse(event.data);
            setPiStatus(prev => ({ ...(prev || {}), capture }));
            setPiCapturing(Boolean(capture.running));
            if (!capture.running && piEventRef.current) {
              piEventRef.current.close();
              piEventRef.current = null;
              fetchPiStatus();
            }
          } catch { /* ignore malformed progress frames */ }
        };
      }
    } catch (e) {
      alert('Failed to start capture: ' + e.message);
    }
  }, [fetchPiStatus]);

  const handlePiStopAndAnalyze = useCallback(async () => {
    try {
      setPiStatus(prev => ({
        ...(prev || {}),
        capture: {
          ...(prev?.capture || {}),
          running: true,
          lastMessage: 'Stopping capture and saving...',
        },
      }));

      const res = await fetch('/api/capture/stop', { method: 'POST' });
      if (!res.ok) {
        throw new Error(
          res.status === 405
            ? 'Pi backend needs restart. Run: sudo systemctl restart sniffpal'
            : 'Stop request failed'
        );
      }

      for (let i = 0; i < 45; i++) {
        await new Promise(resolve => setTimeout(resolve, 1000));
        const statusRes = await fetch('/api/status');
        const status = await statusRes.json();
        setPiStatus(status);
        setPiCapturing(Boolean(status.capture?.running));
        if (!status.capture?.running) {
          await handlePiLoadLatest();
          return;
        }
      }

      alert('Capture is still stopping. Try Load Latest in a few seconds.');
    } catch (e) {
      alert('Failed to stop capture: ' + e.message);
    }
  }, [handlePiLoadLatest]);

  const handlePiModeChange = useCallback(async (mode) => {
    const nextSettings = { ...piSettings, mode };
    setPiSettings(nextSettings);
    localStorage.setItem('sniffpal_pi_settings', JSON.stringify(nextSettings));
    try {
      await fetch('/api/settings', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          interval: nextSettings.interval,
          interface: nextSettings.interface,
          mode: nextSettings.mode,
          monitorInterface: nextSettings.monitorInterface,
          monitorPackets: nextSettings.monitorPackets,
        }),
      });
      fetchPiStatus();
    } catch { /* keep local UI state even if server save fails */ }
  }, [fetchPiStatus, piSettings]);

  const handlePiSaveSettings = useCallback(async () => {
    localStorage.setItem('sniffpal_pi_settings', JSON.stringify(piSettings));
    try {
      await fetch('/api/settings', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          interval: piSettings.interval,
          interface: piSettings.interface,
          mode: piSettings.mode,
          monitorInterface: piSettings.monitorInterface,
          monitorPackets: piSettings.monitorPackets,
        }),
      });
    } catch { /* saved locally regardless */ }
    setPiSettingsOpen(false);
  }, [piSettings]);

  const criticalAlerts = parsedData?.security?.filter(
    a => a.severity === 'critical'
  ) || [];
  const piDeviceInfo = IS_PI_MODE ? piStatus?.device : null;
  const displayData = parsedData && piDeviceInfo
    ? { ...parsedData, devices: parsedData.devices?.filter(d => !isPiDevice(d, piDeviceInfo)) || [] }
    : parsedData;
  const effectiveSelfIp = selfIp || piDeviceInfo?.ip || null;

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
                Network Intelligence · v2.1.1.1
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
              {selfIp && (
                <div className="flex items-center gap-1.5
                bg-blue-900/30 border border-blue-800/50
                px-3 py-1.5 rounded-full">
                  <span className="text-blue-400 text-xs font-medium">
                    🏠 My device: {selfIp}
                  </span>
                  <button
                    onClick={() => handleSetSelf(null)}
                    className="text-blue-600 hover:text-blue-400
                    text-xs ml-1 transition-colors"
                    title="Clear self-device"
                  >✕</button>
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

            {IS_PI_MODE ? (
              /* ── Pi Dashboard ─────────────────────── */
              <div className="w-full max-w-lg space-y-4">
                <div className="text-center mb-2">
                  <div className="text-5xl mb-3">📡</div>
                  <h2 className="text-2xl font-bold text-white">Pi Monitor</h2>
                  <p className="text-cyan-400 text-sm mt-1">
                    Connected to SniffPal Pi
                  </p>
                </div>

                {/* Status Card */}
                <div className="bg-slate-800/60 backdrop-blur-md border
                border-white/10 rounded-2xl p-5">
                  <div className="flex items-center gap-2 mb-4">
                    <span className={`w-2 h-2 rounded-full inline-block
                    ${piCapturing ? 'bg-cyan-400 animate-pulse' : 'bg-green-400'}`}/>
                    <span className={`${piCapturing ? 'text-cyan-400' : 'text-green-400'} text-sm font-medium`}>
                      {piCapturing ? 'Capturing' : 'Live'}
                    </span>
                  </div>
                  <div className="grid grid-cols-2 gap-4 text-sm">
                    <div>
                      <p className="text-slate-500 text-xs">Digests stored</p>
                      <p className="text-white font-medium">
                        {piStatus?.digests ?? '—'}
                      </p>
                    </div>
                    <div>
                      <p className="text-slate-500 text-xs">Last capture</p>
                      <p className="text-white font-medium text-xs truncate">
                        {piStatus?.latest ?? 'None yet'}
                      </p>
                    </div>
                    <div>
                      <p className="text-slate-500 text-xs">Schedule</p>
                      <p className="text-white font-medium">
                        Every {piStatus?.settings?.interval ?? piSettings.interval} min
                      </p>
                    </div>
                    <div>
                      <p className="text-slate-500 text-xs">Interface</p>
                      <p className="text-white font-medium">
                        {(piStatus?.settings?.mode ?? piSettings.mode) === 'monitor'
                          ? (piStatus?.settings?.monitorInterface ?? piSettings.monitorInterface)
                          : (piStatus?.settings?.interface ?? piSettings.interface)}
                      </p>
                    </div>
                    <div>
                      <p className="text-slate-500 text-xs">Mode</p>
                      <p className="text-white font-medium capitalize">
                        {piStatus?.settings?.mode ?? piSettings.mode ?? 'standard'}
                      </p>
                    </div>
                    <div>
                      <p className="text-slate-500 text-xs">This monitor</p>
                      <p className="text-white font-medium text-xs truncate">
                        {piStatus?.device?.ip || piStatus?.device?.hostname || 'Detecting'}
                      </p>
                    </div>
                  </div>
                </div>

                {piStatus?.system && (
                  <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
                    <div className="bg-slate-800/50 border border-white/10 rounded-2xl p-4">
                      <p className="text-slate-500 text-xs mb-1">CPU</p>
                      <p className="text-white font-semibold">{piStatus.system.cpuPercent}%</p>
                    </div>
                    <div className="bg-slate-800/50 border border-white/10 rounded-2xl p-4">
                      <p className="text-slate-500 text-xs mb-1">RAM</p>
                      <p className="text-white font-semibold">{piStatus.system.ramPercent}%</p>
                    </div>
                    <div className="bg-slate-800/50 border border-white/10 rounded-2xl p-4">
                      <p className="text-slate-500 text-xs mb-1">Network</p>
                      <p className="text-white font-semibold text-xs">
                        ↓ {piStatus.system.netRxKBps ?? 0} KB/s · ↑ {piStatus.system.netTxKBps ?? 0} KB/s
                      </p>
                    </div>
                    <div className="bg-slate-800/50 border border-white/10 rounded-2xl p-4">
                      <p className="text-slate-500 text-xs mb-1">Temp</p>
                      <p className="text-white font-semibold">
                        {piStatus.system.tempC == null ? 'N/A' : `${piStatus.system.tempC}°C`}
                      </p>
                    </div>
                    <div className="bg-slate-800/50 border border-white/10 rounded-2xl p-4">
                      <p className="text-slate-500 text-xs mb-1">Uptime</p>
                      <p className="text-white font-semibold">{formatUptime(piStatus.system.uptimeSeconds)}</p>
                    </div>
                    <div className="bg-slate-800/50 border border-white/10 rounded-2xl p-4">
                      <p className="text-slate-500 text-xs mb-1">Pi time</p>
                      <p className="text-white font-semibold">{piStatus.system.localTime || '--:--'}</p>
                    </div>
                  </div>
                )}

                {/* Capture Mode */}
                <div className="bg-slate-800/50 border border-white/10 rounded-2xl p-4">
                  <div className="flex items-center justify-between gap-3 mb-3">
                    <div>
                      <p className="text-white text-sm font-semibold">Capture mode</p>
                      <p className="text-slate-500 text-xs">
                        Choose built-in Wi-Fi or USB monitor adapter before capture.
                      </p>
                    </div>
                    {piCapturing && (
                      <span className="text-[10px] text-amber-300 bg-amber-900/30 border border-amber-800/50 rounded-full px-2 py-1">
                        Locked while capturing
                      </span>
                    )}
                  </div>
                  <div className="grid grid-cols-2 gap-2">
                    {[
                      ['standard', 'Standard Wi-Fi', piSettings.interface || 'wlan0'],
                      ['monitor', 'USB Monitor', piSettings.monitorInterface || 'wlan1mon'],
                    ].map(([mode, label, hint]) => (
                      <button
                        key={mode}
                        type="button"
                        disabled={piCapturing}
                        onClick={() => handlePiModeChange(mode)}
                        className={`text-left rounded-xl border px-3 py-3 transition-all disabled:opacity-50
                        ${piSettings.mode === mode
                          ? 'bg-cyan-600/20 border-cyan-500/70 text-white'
                          : 'bg-slate-900/60 border-white/10 text-slate-300 hover:border-white/25'
                        }`}
                      >
                        <span className="block text-sm font-semibold">{label}</span>
                        <span className="block text-[11px] text-slate-500 mt-0.5">{hint}</span>
                      </button>
                    ))}
                  </div>
                  <p className="text-slate-500 text-[11px] mt-3">
                    USB Monitor adds 2.4 / 5 / 6 GHz band data when a compatible adapter is configured.
                  </p>
                </div>

                {/* Capture Progress */}
                {(piCapturing || piStatus?.capture?.lastMessage || piStatus?.capture?.error) && (
                  <div className="bg-blue-900/20 border border-blue-800/40
                  rounded-2xl p-4">
                    <div className="flex items-start gap-3">
                      {piCapturing && (
                        <div className="w-4 h-4 border-2 border-cyan-400
                        border-t-transparent rounded-full animate-spin
                        flex-shrink-0 mt-0.5"/>
                      )}
                      <div>
                        <p className={`${piStatus?.capture?.error ? 'text-red-400' : 'text-cyan-400'} text-sm font-medium`}>
                          {piStatus?.capture?.error || piStatus?.capture?.lastMessage || 'Capture running...'}
                        </p>
                        <p className="text-slate-500 text-xs">
                          {(piStatus?.capture?.packets || 0).toLocaleString()} packets ·
                          {' '}{(piStatus?.capture?.devices || 0).toLocaleString()} devices
                        </p>
                        {piStatus?.capture?.protocols && Object.keys(piStatus.capture.protocols).length > 0 && (
                          <div className="flex flex-wrap gap-1.5 mt-2">
                            {Object.entries(piStatus.capture.protocols).map(([name, count]) => (
                              <span key={name} className="text-[10px] bg-slate-900/70 border border-white/10
                              text-slate-300 px-2 py-0.5 rounded-full">
                                {name}: {count}
                              </span>
                            ))}
                          </div>
                        )}
                      </div>
                    </div>
                  </div>
                )}

                {/* Action Buttons */}
                <div className={`grid gap-3 ${piCapturing ? 'grid-cols-1 sm:grid-cols-3' : 'grid-cols-2'}`}>
                  <button
                    onClick={handlePiStartCapture}
                    disabled={piCapturing}
                    className="bg-cyan-600 hover:bg-cyan-500
                    disabled:bg-slate-700 disabled:text-slate-500
                    text-white font-medium py-3 px-4 rounded-xl
                    transition-all flex items-center justify-center gap-2"
                  >
                    ▶ Start Capture
                  </button>
                  {piCapturing && (
                    <button
                      onClick={handlePiStopAndAnalyze}
                      className="bg-amber-600 hover:bg-amber-500
                      text-white font-medium py-3 px-4 rounded-xl
                      transition-all flex items-center justify-center gap-2"
                    >
                      Stop & Analyze
                    </button>
                  )}
                  <button
                    onClick={handlePiLoadLatest}
                    disabled={!piStatus?.latest || piCapturing}
                    className="bg-slate-700 hover:bg-slate-600
                    disabled:bg-slate-800 disabled:text-slate-600
                    text-white font-medium py-3 px-4 rounded-xl
                    transition-all flex items-center justify-center gap-2"
                  >
                    📂 Load Latest
                  </button>
                </div>

                <p className="text-slate-600 text-xs text-center">
                  Auto-capture every {piSettings.interval} minutes
                </p>

                {/* Settings Toggle */}
                <button
                  onClick={() => setPiSettingsOpen(o => !o)}
                  className="w-full text-slate-400 hover:text-white text-sm
                  py-2 transition-colors flex items-center justify-center gap-2"
                >
                  ⚙ Settings {piSettingsOpen ? '▲' : '▼'}
                </button>

                {/* Settings Panel */}
                {piSettingsOpen && (
                  <div className="bg-slate-800/60 border border-white/10
                  rounded-2xl p-5 space-y-4">
                    <div>
                      <label className="text-slate-400 text-xs block mb-1">
                        Capture Interval
                      </label>
                      <select
                        value={piSettings.interval}
                        onChange={e => setPiSettings(s =>
                          ({ ...s, interval: Number(e.target.value) })
                        )}
                        className="w-full bg-slate-700 border border-white/10
                        text-white text-sm rounded-lg px-3 py-2"
                      >
                        <option value={5}>5 minutes</option>
                        <option value={10}>10 minutes</option>
                        <option value={30}>30 minutes</option>
                        <option value={60}>1 hour</option>
                      </select>
                    </div>
                    <div>
                      <label className="text-slate-400 text-xs block mb-1">
                        {piSettings.mode === 'monitor' ? 'Monitor Interface' : 'Network Interface'}
                      </label>
                      <input
                        type="text"
                        value={piSettings.mode === 'monitor' ? piSettings.monitorInterface : piSettings.interface}
                        onChange={e => setPiSettings(s =>
                          piSettings.mode === 'monitor'
                            ? ({ ...s, monitorInterface: e.target.value })
                            : ({ ...s, interface: e.target.value })
                        )}
                        className="w-full bg-slate-700 border border-white/10
                        text-white text-sm rounded-lg px-3 py-2"
                        placeholder={piSettings.mode === 'monitor' ? 'wlan1mon' : 'wlan0'}
                      />
                    </div>
                    {piSettings.mode === 'monitor' && (
                      <div>
                        <label className="text-slate-400 text-xs block mb-1">
                          Monitor Packet Count
                        </label>
                        <input
                          type="number"
                          min={50}
                          step={50}
                          value={piSettings.monitorPackets}
                          onChange={e => setPiSettings(s =>
                            ({ ...s, monitorPackets: Number(e.target.value) })
                          )}
                          className="w-full bg-slate-700 border border-white/10
                          text-white text-sm rounded-lg px-3 py-2"
                        />
                      </div>
                    )}
                    <button
                      onClick={handlePiSaveSettings}
                      className="w-full bg-cyan-600 hover:bg-cyan-500
                      text-white font-medium py-2 rounded-xl
                      transition-all text-sm"
                    >
                      Save Settings
                    </button>
                  </div>
                )}
              </div>
            ) : (
              /* ── Web upload mode ──────────────────── */
              <>
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
              </>
            )}
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
            <SummaryCards data={displayData} />

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
                  devices={displayData.devices}
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
                devices={displayData.devices}
                onClose={() => setSelectedDataPoint(null)}
              />
            )}

            {/* Device Table */}
            <div ref={deviceTableRef}>
              <DeviceTable
                devices={displayData.devices}
                trustedDevices={trustedDevices}
                onTrust={handleTrust}
                onDeviceClick={setSelectedDataPoint}
                selfIp={effectiveSelfIp}
                onSetSelf={handleSetSelf}
              />
            </div>

            {/* Websites */}
            <WebsitesTab
              websites={parsedData.websites}
              trackers={parsedData.trackers}
              selfIp={effectiveSelfIp}
              onGoToDevices={scrollToDevices}
            />

            {/* Topology Map */}
            <TopologyMap
              devices={displayData.devices}
              piDevice={piDeviceInfo}
              captureMode={piStatus?.settings?.mode || piSettings.mode}
            />

            {/* Security */}
            <SecurityTab
              alerts={parsedData.security}
              retransmissions={parsedData.retransmissions}
              avgRtt={parsedData.avgRtt}
              nxdomainCount={parsedData.nxdomainCount}
              selfIp={effectiveSelfIp}
              onGoToDevices={scrollToDevices}
              findings={parsedData.findings || []}
              deviceCount={displayData.devices?.length || 0}
              guestWifi={parsedData.guestWifi}
            />

          </div>
        )}
      </main>

      <div className="text-center text-slate-700 text-xs py-6">
        SniffPal v2.1.1 — Open Source Network Intelligence ·
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
