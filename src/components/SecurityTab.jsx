import { useState, useEffect } from 'react';
import {
  explainFindings, summarizeSession,
  getAIStatus, initAI, probeStatus,
} from '../utils/geminiNano.js';

/** Build instant template explanations from findings — shown before AI loads */
function buildTemplateExplanations(findings) {
  return (findings || []).map(f => ({ id: f.id, explanation: f.description }));
}

export default function SecurityTab({
  alerts, retransmissions, avgRtt, nxdomainCount, selfIp, onGoToDevices,
  findings, deviceCount,
}) {
  const [selfExpanded, setSelfExpanded]   = useState(false);
  const [explanations, setExplanations]   = useState([]);     // [{id, explanation}] — templates or AI-upgraded
  const [aiSummary, setAiSummary]         = useState(null);   // string
  const [aiLoading, setAiLoading]         = useState(false);
  const [downloadProgress, setDownloadProgress] = useState(null); // {percent, message}
  // "both"|"summarizer"|"languagemodel"|"downloading"|"transformers"|"loading"|"unavailable"|"checking"
  const [aiStatus, setAiStatus]           = useState('checking');

  // Quick Chrome-only probe on mount — never triggers a download
  useEffect(() => {
    probeStatus().then(setAiStatus);
  }, []);

  // Full AI init + explanations when findings arrive (after file upload)
  useEffect(() => {
    if (!findings || findings.length === 0) return;
    let cancelled = false;

    // Show template explanations immediately — no waiting for AI
    setExplanations(buildTemplateExplanations(findings));

    (async () => {
      // initAI() defers itself via setTimeout(0) — never blocks initial render
      await initAI((percent, message) => {
        if (cancelled) return;
        setDownloadProgress({ percent, message });
        setAiStatus(getAIStatus());
      });

      if (cancelled) return;
      const status = getAIStatus();
      setAiStatus(status);
      if (!['both', 'summarizer', 'languagemodel', 'transformers'].includes(status)) return;

      setAiLoading(true);
      try {
        const critCount = (alerts || []).filter(a => a.severity === 'critical').length;
        const warnCount = (alerts || []).filter(a => a.severity === 'warning').length;

        // Yield to browser before kicking off AI calls so templates remain interactive
        await new Promise(r => setTimeout(r, 0));

        const [aiExplanations, summary] = await Promise.all([
          explainFindings(findings),
          summarizeSession(
            deviceCount || 0,
            { critical: critCount, warning: warnCount, info: findings.length },
            findings.slice(0, 3)
          ),
        ]);
        if (!cancelled) {
          // AI upgrades templates quietly — only replace if we got results
          if (aiExplanations) setExplanations(aiExplanations);
          setAiSummary(summary);
        }
      } catch (err) {
        console.error('[SniffPal] AI explanation failed:', err);
      } finally {
        if (!cancelled) setAiLoading(false);
      }
    })();

    return () => { cancelled = true; };
  }, [findings, alerts, deviceCount]);

  // Separate self-device activity from real network alerts
  const selfAlerts = selfIp
    ? alerts.filter(a => a.detail?.includes(selfIp) || a.type === 'credential' || a.type === 'cleartext')
        .filter(a => a.detail?.includes(selfIp)) // only move if IP actually appears
    : [];
  const realAlerts = selfIp
    ? alerts.filter(a => !selfAlerts.includes(a))
    : alerts;

  const criticalCount = realAlerts.filter(a => a.severity === 'critical').length;
  const warningCount  = realAlerts.filter(a => a.severity === 'warning').length;

  return (
    <div className="space-y-6">

      {/* Self-device banner when IP not set */}
      {!selfIp && (
        <div className="bg-blue-900/20 border border-blue-800/40 rounded-2xl
        px-5 py-4 flex items-center justify-between gap-4">
          <p className="text-blue-300 text-sm">
            ℹ️ Seeing alerts from your own device? Mark it in the Devices tab
            to separate your traffic from real network threats.
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
      )}

      {/* Score Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className={`rounded-2xl p-6 border text-center
        ${criticalCount > 0
          ? 'bg-red-900/20 border-red-800/50'
          : warningCount > 0
          ? 'bg-yellow-900/20 border-yellow-800/50'
          : 'bg-green-900/20 border-green-800/50'}`}>
          <div className="text-4xl mb-2">
            {criticalCount > 0 ? '🔴' : warningCount > 0 ? '🟡' : '🟢'}
          </div>
          <div className="text-white font-bold text-lg">
            {criticalCount > 0 ? 'Issues Found' : warningCount > 0 ? 'Warnings' : 'All Clear'}
          </div>
          <div className="text-slate-400 text-xs mt-1">Network Security Status</div>
        </div>

        <div className={`rounded-2xl p-6 border text-center
        ${retransmissions > 100
          ? 'bg-red-900/20 border-red-800/50'
          : retransmissions > 30
          ? 'bg-yellow-900/20 border-yellow-800/50'
          : 'bg-slate-800/40 border-white/5'}`}>
          <div className="text-4xl mb-2">
            {retransmissions > 100 ? '🔴' : retransmissions > 30 ? '🟡' : '🟢'}
          </div>
          <div className="text-white font-bold text-lg">
            {retransmissions} Retransmissions
          </div>
          <div className="text-slate-400 text-xs mt-1">
            {retransmissions > 100 ? 'Poor connection quality'
              : retransmissions > 30 ? 'Some packet loss'
              : 'TCP Health Good'}
          </div>
        </div>

        <div className={`rounded-2xl p-6 border text-center
        ${avgRtt > 150
          ? 'bg-red-900/20 border-red-800/50'
          : avgRtt > 80
          ? 'bg-yellow-900/20 border-yellow-800/50'
          : 'bg-slate-800/40 border-white/5'}`}>
          <div className="text-4xl mb-2">
            {!avgRtt ? '⚪' : avgRtt > 150 ? '🔴' : avgRtt > 80 ? '🟡' : '🟢'}
          </div>
          <div className="text-white font-bold text-lg">
            {avgRtt ? `${avgRtt}ms` : 'N/A'}
          </div>
          <div className="text-slate-400 text-xs mt-1">
            {!avgRtt ? 'No RTT data found'
              : avgRtt > 150 ? 'High latency detected'
              : avgRtt > 80  ? 'Moderate latency'
              : 'Latency Normal'}
          </div>
        </div>
      </div>

      {/* Main Alerts List */}
      <div className="bg-slate-800/40 backdrop-blur-md border
      border-white/5 rounded-2xl p-6">
        <h2 className="text-lg font-semibold text-white mb-4
        flex items-center gap-2">
          <span className="w-2 h-2 rounded-full bg-red-400
          shadow-[0_0_8px_rgba(248,113,113,0.8)]"></span>
          Security Alerts
          <span className="text-slate-500 text-sm font-normal">
            ({realAlerts.length} findings)
          </span>
        </h2>
        <div className="space-y-3">
          {realAlerts.map((alert, i) => (
            <div key={i} className={`rounded-xl p-4 border
            flex items-start gap-4 transition-all hover:border-white/10
            ${alert.severity === 'critical'
              ? 'bg-red-900/20 border-red-800/40'
              : alert.severity === 'warning'
              ? 'bg-yellow-900/20 border-yellow-800/40'
              : 'bg-green-900/20 border-green-800/40'}`}>
              <div className="text-2xl mt-0.5">{alert.icon}</div>
              <div className="flex-1">
                <div className="text-white font-medium text-sm">{alert.title}</div>
                <div className="text-slate-400 text-xs mt-1">{alert.detail}</div>
              </div>
              <span className={`text-xs px-2 py-1 rounded-full
              font-medium uppercase tracking-wide
              ${alert.severity === 'critical'
                ? 'bg-red-900/50 text-red-400'
                : alert.severity === 'warning'
                ? 'bg-yellow-900/50 text-yellow-400'
                : 'bg-green-900/50 text-green-400'}`}>
                {alert.severity === 'good' ? 'clean' : alert.severity}
              </span>
            </div>
          ))}
        </div>
      </div>

      {/* Your device activity — collapsible */}
      {selfAlerts.length > 0 && (
        <div className="bg-slate-800/40 backdrop-blur-md border border-white/5 rounded-2xl overflow-hidden">
          <button
            onClick={() => setSelfExpanded(e => !e)}
            className="w-full flex items-center justify-between px-6 py-4
            text-slate-400 hover:text-white transition-colors text-sm"
          >
            <span className="flex items-center gap-2">
              🏠 Your device activity
              <span className="bg-blue-900/50 text-blue-400 text-xs px-2 py-0.5 rounded-full">
                {selfAlerts.length} — not network threats
              </span>
            </span>
            <span>{selfExpanded ? '▲' : '▼'}</span>
          </button>
          {selfExpanded && (
            <div className="px-6 pb-6 space-y-3 border-t border-white/5">
              <p className="text-slate-500 text-xs pt-4">
                These alerts matched your device ({selfIp}). They are normal activity from your own machine, not attacks from other network devices.
              </p>
              {selfAlerts.map((alert, i) => (
                <div key={i} className="rounded-xl p-4 border bg-slate-900/40 border-white/5
                flex items-start gap-4 opacity-70">
                  <div className="text-2xl mt-0.5">{alert.icon}</div>
                  <div className="flex-1">
                    <div className="text-white font-medium text-sm">{alert.title}</div>
                    <div className="text-slate-400 text-xs mt-1">{alert.detail}</div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* DNS Health */}
      <div className="bg-slate-800/40 backdrop-blur-md border
      border-white/5 rounded-2xl p-6">
        <h2 className="text-lg font-semibold text-white mb-4
        flex items-center gap-2">
          <span className="w-2 h-2 rounded-full bg-purple-400
          shadow-[0_0_8px_rgba(192,132,252,0.8)]"></span>
          DNS Health
        </h2>
        <div className="grid grid-cols-2 gap-4">
          <div className="bg-slate-900/50 rounded-xl p-4 text-center">
            <div className={`text-2xl font-bold mb-1
            ${nxdomainCount > 10 ? 'text-red-400'
              : nxdomainCount > 3  ? 'text-yellow-400'
                                   : 'text-green-400'}`}>
              {nxdomainCount}
            </div>
            <div className="text-slate-400 text-xs">Failed DNS Lookups</div>
            <div className="text-slate-600 text-xs mt-1">
              {nxdomainCount > 10 ? '⚠️ Possible malware activity'
                : nxdomainCount > 3 ? 'Some failures — check config'
                : '✅ Looks healthy'}
            </div>
          </div>
          <div className="bg-slate-900/50 rounded-xl p-4 text-center">
            <div className="text-2xl font-bold mb-1 text-cyan-400">
              {nxdomainCount > 10 ? '⚠️' : '✅'}
            </div>
            <div className="text-slate-400 text-xs">DNS Status</div>
            <div className="text-slate-600 text-xs mt-1">
              {nxdomainCount > 10 ? 'Investigate failed lookups' : 'No DGA activity detected'}
            </div>
          </div>
        </div>
      </div>

      {/* AI Insights */}
      <div className="bg-slate-800/40 backdrop-blur-md border border-white/5 rounded-2xl p-6">

        {/* Header — badge changes with active AI tier */}
        <h2 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
          <span className="w-2 h-2 rounded-full bg-violet-400 shadow-[0_0_8px_rgba(167,139,250,0.8)]"></span>
          AI Insights
          {['both', 'summarizer', 'languagemodel'].includes(aiStatus) && (
            <span className="bg-violet-900/40 text-violet-300 text-xs px-2 py-0.5 rounded-full">
              ⚡ Gemini Nano
            </span>
          )}
          {aiStatus === 'transformers' && (
            <span className="bg-orange-900/40 text-orange-300 text-xs px-2 py-0.5 rounded-full">
              🤗 SmolLM2
            </span>
          )}
        </h2>

        {/* ── checking: probing on mount ── */}
        {aiStatus === 'checking' && (
          <div className="flex items-center gap-3 text-slate-500 text-sm py-3">
            <span className="animate-spin text-lg">⚙️</span>
            Checking AI availability…
          </div>
        )}

        {/* ── downloading: Chrome is pulling down the AI model ── */}
        {aiStatus === 'downloading' && (
          <div className="bg-blue-900/20 border border-blue-800/40 rounded-xl p-4 flex items-start gap-3 mb-4">
            <span className="text-2xl flex-shrink-0">⬇️</span>
            <div>
              <p className="text-blue-300 text-sm font-medium">Chrome AI model downloading…</p>
              <p className="text-blue-500 text-xs mt-1">
                Chrome is installing the AI model in the background. Explanations will be
                ready when it finishes. This happens only once.
              </p>
            </div>
          </div>
        )}

        {/* ── loading: Transformers.js model downloading (~200 MB) ── */}
        {aiStatus === 'loading' && (
          <div className="bg-slate-900/50 border border-white/5 rounded-xl p-5 space-y-3 mb-4">
            <div className="flex items-center gap-3">
              <span className="animate-spin text-xl flex-shrink-0">⚙️</span>
              <p className="text-slate-300 text-sm font-medium">
                {downloadProgress?.message || 'Loading AI model…'}
              </p>
            </div>
            <div className="w-full bg-slate-700 rounded-full h-2">
              <div
                className="bg-gradient-to-r from-violet-500 to-orange-400 h-2 rounded-full transition-all duration-500"
                style={{ width: `${downloadProgress?.percent ?? 0}%` }}
              />
            </div>
            <p className="text-slate-600 text-xs">
              First-time download only — cached in your browser after this.
            </p>
          </div>
        )}

        {/* ── content: templates shown immediately, AI upgrades quietly ── */}
        {(!findings || findings.length === 0) ? (
          aiStatus !== 'checking' && (
            <p className="text-slate-500 text-sm">No enrichment findings to display.</p>
          )
        ) : (
          <div className="space-y-4">
            {/* Subtle AI-enhancing indicator — content already visible below */}
            {aiLoading && (
              <div className="flex items-center gap-2 text-slate-500 text-xs">
                <span className="animate-spin">⚙️</span>
                {aiStatus === 'transformers' ? 'Enhancing with SmolLM2…' : 'Enhancing with Gemini Nano…'}
              </div>
            )}

            {/* Session summary — appears once AI delivers it */}
            {aiSummary && (
              <div className="bg-violet-900/20 border border-violet-800/40 rounded-xl p-4">
                <p className="text-violet-300 text-sm leading-relaxed">{aiSummary}</p>
              </div>
            )}

            {/* Per-finding cards — templates shown instantly, silently upgraded by AI */}
            {explanations.length > 0 && (
              <div className="space-y-3">
                {explanations.map((item) => {
                  const finding = (findings || []).find(f => f.id === item.id);
                  return (
                    <div key={item.id}
                      className="bg-slate-900/50 rounded-xl p-4 border border-white/5">
                      <div className="flex items-start gap-3">
                        <span className="text-violet-400 font-mono text-xs mt-0.5 flex-shrink-0">
                          {item.id}
                        </span>
                        <div>
                          {finding && (
                            <p className="text-white text-xs font-medium mb-1">{finding.title}</p>
                          )}
                          <p className="text-slate-400 text-xs leading-relaxed">{item.explanation}</p>
                          {finding && (
                            <p className="text-cyan-700 text-xs font-mono mt-1">✓ Fix: {finding.fix}</p>
                          )}
                        </div>
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        )}
      </div>

      {/* What SniffPal Checks */}
      <div className="bg-slate-800/40 backdrop-blur-md border
      border-white/5 rounded-2xl p-6">
        <h2 className="text-lg font-semibold text-white mb-4
        flex items-center gap-2">
          <span className="w-2 h-2 rounded-full bg-cyan-400
          shadow-[0_0_8px_rgba(34,211,238,0.8)]"></span>
          What SniffPal Checks For
        </h2>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {[
            { icon: '👥', title: 'ARP Spoofing',        severity: 'critical', desc: 'Attacker floods network with fake ARP replies to impersonate your router and intercept all traffic.',       checked: 'MAC claiming multiple IPs + ARP reply floods' },
            { icon: '📡', title: 'Rogue DHCP Server',   severity: 'critical', desc: 'Fake DHCP server handing out bad configs, forcing traffic through attacker\'s machine.',                    checked: 'Multiple DHCP offer sources detected' },
            { icon: '🔀', title: 'ICMP Redirect Attack', severity: 'critical', desc: 'Attacker sends ICMP type 5 packets to silently reroute traffic through a malicious gateway.',              checked: 'Any ICMP type 5 packets = suspicious' },
            { icon: '🔓', title: 'Cleartext Credentials',severity: 'warning',  desc: 'Passwords sent unencrypted over HTTP or FTP — visible to anyone sniffing the network.',                   checked: 'HTTP Authorization headers + FTP USER/PASS' },
            { icon: '🧬', title: 'DNS Malware / DGA',   severity: 'warning',  desc: 'High NXDOMAIN rate suggests malware using Domain Generation Algorithms to find C2 servers.',               checked: 'Failed DNS lookup rate > 30%' },
            { icon: '💉', title: 'Request Injection',   severity: 'critical', desc: 'SQL injection, XSS, or remote code execution attempts in HTTP request URIs.',                               checked: 'cmd.exe, eval(), SELECT, <script in URIs' },
          ].map((check, i) => (
            <div key={i} className="bg-slate-900/50 rounded-xl
            p-4 border border-white/5 hover:border-white/10 transition-all">
              <div className="flex items-start gap-3">
                <span className="text-2xl">{check.icon}</span>
                <div>
                  <div className="flex items-center gap-2 mb-1">
                    <span className="text-white font-medium text-sm">{check.title}</span>
                    <span className={`text-xs px-2 py-0.5 rounded-full
                    ${check.severity === 'critical'
                      ? 'bg-red-900/50 text-red-400'
                      : 'bg-yellow-900/50 text-yellow-400'}`}>
                      {check.severity}
                    </span>
                  </div>
                  <p className="text-slate-400 text-xs mb-2">{check.desc}</p>
                  <p className="text-cyan-600 text-xs font-mono">✓ {check.checked}</p>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>

    </div>
  );
}
