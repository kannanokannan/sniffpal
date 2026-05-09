import { useCallback, useState } from 'react';
import { UploadCloud, ChevronDown, ChevronUp } from 'lucide-react';

export default function FileUpload({ onFile }) {
  const [isDragging, setIsDragging] = useState(false);
  const [error, setError] = useState('');
  const [showHelp, setShowHelp] = useState(false);

  const processFile = (file) => {
    setError('');
    const ok = file.name.endsWith('.json') ||
               file.name.endsWith('.pcap') ||
               file.name.endsWith('.pcapng');
    if (!ok) {
      setError('Please upload a .json, .pcap, or .pcapng file');
      return;
    }
    onFile(file);
  };

  const handleDrop = useCallback((e) => {
    e.preventDefault();
    setIsDragging(false);
    if (e.dataTransfer.files?.length) {
      processFile(e.dataTransfer.files[0]);
    }
  }, []);

  return (
    <div className="w-full max-w-2xl mx-auto space-y-4">

      {/* Drop Zone */}
      <div
        onDragOver={(e) => { e.preventDefault(); setIsDragging(true); }}
        onDragLeave={() => setIsDragging(false)}
        onDrop={handleDrop}
        className={`w-full p-12 border-2 border-dashed rounded-2xl
        text-center transition-all duration-300 backdrop-blur-xl
        ${isDragging
          ? 'border-cyan-400 bg-cyan-500/10 shadow-[0_0_30px_rgba(34,211,238,0.2)] scale-[1.02]'
          : 'border-slate-700/60 bg-slate-800/40 hover:bg-slate-800/60 hover:border-cyan-500/50'
        }`}
      >
        <div className="relative inline-block mb-4">
          <div className={`absolute inset-0 bg-cyan-500/20
          rounded-full blur-xl transition-all duration-500
          ${isDragging ? 'opacity-100 scale-150' : 'opacity-0'}`}/>
          <UploadCloud className={`w-16 h-16 mx-auto relative z-10
          transition-colors duration-300
          ${isDragging ? 'text-cyan-300' : 'text-cyan-500'}`} />
        </div>

        <h3 className="text-xl font-semibold text-white mb-1">
          Drop your capture file here
        </h3>
        <p className="text-slate-400 text-sm mb-3">
          Supports .pcap, .pcapng (native) and Wireshark/tshark JSON exports
        </p>

        {/* File size info */}
        <div className="flex items-center justify-center gap-3 mb-6 flex-wrap">
          <span className="flex items-center gap-1.5 bg-green-900/30
          border border-green-800/50 text-green-400 text-xs
          px-3 py-1 rounded-full font-medium">
            ✅ No file size limit
          </span>
          <span className="flex items-center gap-1.5 bg-slate-700/40
          border border-white/5 text-slate-400 text-xs
          px-3 py-1 rounded-full">
            📊 Large files sampled to 25,000 packets
          </span>
          <span className="flex items-center gap-1.5 bg-slate-700/40
          border border-white/5 text-slate-400 text-xs
          px-3 py-1 rounded-full">
            🔒 100% local — never uploaded
          </span>
        </div>

        <label className="cursor-pointer bg-gradient-to-r
        from-cyan-600 to-blue-600 text-white px-8 py-3
        rounded-xl font-medium shadow-[0_0_15px_rgba(34,211,238,0.3)]
        hover:shadow-[0_0_25px_rgba(34,211,238,0.5)]
        hover:scale-105 transition-all duration-200 inline-block">
          Browse Files
          <input
            type="file"
            accept=".json,.pcap,.pcapng"
            className="hidden"
            onChange={(e) => e.target.files?.length &&
              processFile(e.target.files[0])}
          />
        </label>

        {error && (
          <p className="mt-4 text-rose-400 text-sm font-medium">
            {error}
          </p>
        )}
      </div>

      {/* How to export — collapsible */}
      <div className="bg-slate-800/40 backdrop-blur-md border
      border-white/5 rounded-2xl overflow-hidden">
        <button
          onClick={() => setShowHelp(!showHelp)}
          className="w-full flex items-center justify-between
          px-6 py-4 text-slate-400 hover:text-white
          transition-colors text-sm"
        >
          <span>📖 How to export — Wireshark, tshark & PCAPdroid</span>
          {showHelp
            ? <ChevronUp className="w-4 h-4" />
            : <ChevronDown className="w-4 h-4" />
          }
        </button>

        {showHelp && (
          <div className="px-6 pb-6 space-y-5 border-t border-white/5">

            {/* Wireshark GUI */}
            <div>
              <div className="flex items-center gap-2 mb-2 mt-4">
                <span className="text-lg">🦈</span>
                <span className="text-white font-medium text-sm">
                  Wireshark (GUI)
                </span>
                <span className="bg-green-900/40 text-green-400
                text-xs px-2 py-0.5 rounded-full">
                  Easiest
                </span>
              </div>
              <div className="bg-slate-900/60 rounded-xl p-4
              font-mono text-xs text-slate-300 space-y-1">
                <p>1. Capture your traffic in Wireshark</p>
                <p>2. File → Export Packet Dissections</p>
                <p>3. Select <span className="text-cyan-400">
                  "As JSON..."</span></p>
                <p>4. Save and drop into SniffPal</p>
              </div>
            </div>

            {/* tshark CLI */}
            <div>
              <div className="flex items-center gap-2 mb-2">
                <span className="text-lg">⌨️</span>
                <span className="text-white font-medium text-sm">
                  tshark (Command Line)
                </span>
                <span className="bg-blue-900/40 text-blue-400
                text-xs px-2 py-0.5 rounded-full">
                  Faster for large files
                </span>
              </div>
              <div className="bg-slate-900/60 rounded-xl p-4
              font-mono text-xs space-y-2">
                <p className="text-slate-400">
                  # Convert any .pcap or .pcapng to JSON:
                </p>
                <p className="text-cyan-400 select-all">
                  tshark -r capture.pcap -T json &gt; capture.json
                </p>
                <p className="text-slate-400 mt-2">
                  # Large file? Limit packets for speed:
                </p>
                <p className="text-cyan-400 select-all">
                  tshark -r capture.pcap -T json -c 50000 &gt; capture.json
                </p>
              </div>
              <p className="text-slate-500 text-xs mt-2 px-1">
                tshark comes free with Wireshark.{' '}
                <a
                  href="https://tshark.dev/capture/tshark/"
                  target="_blank"
                  rel="noreferrer"
                  className="text-cyan-600 hover:text-cyan-400
                  transition-colors"
                >
                  tshark docs →
                </a>
              </p>
            </div>

            {/* PCAPdroid */}
            <div>
              <div className="flex items-center gap-2 mb-2">
                <span className="text-lg">📱</span>
                <span className="text-white font-medium text-sm">
                  PCAPdroid (Android)
                </span>
                <span className="bg-purple-900/40 text-purple-400
                text-xs px-2 py-0.5 rounded-full">
                  Mobile traffic
                </span>
              </div>
              <div className="bg-slate-900/60 rounded-xl p-4
              text-xs text-slate-300 space-y-2">
                <p>1. Install{' '}
                  <a
                    href="https://play.google.com/store/apps/details?id=com.emanuelef.remote_capture"
                    target="_blank"
                    rel="noreferrer"
                    className="text-cyan-400 hover:text-cyan-300"
                  >
                    PCAPdroid from Play Store
                  </a>
                </p>
                <p>2. Start capture → stop when done</p>
                <p>3. Export as <span className="text-cyan-400">
                  .pcap file</span></p>
                <p>4. Transfer to laptop → convert with tshark:</p>
                <div className="bg-slate-950/60 rounded-lg p-3
                font-mono mt-2">
                  <p className="text-cyan-400 select-all">
                    tshark -r pcapdroid_capture.pcap -T json &gt; capture.json
                  </p>
                </div>
                <p>5. Drop the JSON into SniffPal ✅</p>
              </div>
              <p className="text-slate-500 text-xs mt-2 px-1">
                PCAPdroid captures phone traffic without root.{' '}
                <a
                  href="https://emanuele-f.github.io/PCAPdroid/dump_modes.html"
                  target="_blank"
                  rel="noreferrer"
                  className="text-cyan-600 hover:text-cyan-400
                  transition-colors"
                >
                  PCAPdroid export guide →
                </a>
              </p>
            </div>

          </div>
        )}
      </div>

    </div>
  );
}
