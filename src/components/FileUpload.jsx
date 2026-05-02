import { useCallback, useState } from 'react';
import { UploadCloud } from 'lucide-react';

export default function FileUpload({ onFile }) {
  const [isDragging, setIsDragging] = useState(false);
  const [error, setError] = useState('');

  const processFile = (file) => {
    setError('');
    if (!file.name.endsWith('.json')) {
      setError('Please upload a valid Wireshark JSON file.');
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
    <div
      onDragOver={(e) => { e.preventDefault(); setIsDragging(true); }}
      onDragLeave={() => setIsDragging(false)}
      onDrop={handleDrop}
      className={`w-full max-w-2xl mx-auto p-12 border-2 
      border-dashed rounded-2xl text-center transition-all 
      duration-300 backdrop-blur-xl ${
        isDragging
          ? 'border-cyan-400 bg-cyan-500/10 shadow-[0_0_30px_rgba(34,211,238,0.2)] scale-[1.02]'
          : 'border-slate-700/60 bg-slate-800/40 hover:bg-slate-800/60 hover:border-cyan-500/50 hover:shadow-[0_0_20px_rgba(34,211,238,0.1)]'
      }`}
    >
      {/* Icon */}
      <div className="relative inline-block mb-4">
        <div className={`absolute inset-0 bg-cyan-500/20 rounded-full 
        blur-xl transition-all duration-500 
        ${isDragging ? 'opacity-100 scale-150' : 'opacity-0 scale-100'}`}>
        </div>
        <UploadCloud className={`w-16 h-16 mx-auto relative z-10 
        transition-colors duration-300 
        ${isDragging ? 'text-cyan-300' : 'text-cyan-500'}`} />
      </div>

      <h3 className="text-xl font-semibold text-white mb-2 tracking-wide">
        Upload Wireshark Capture
      </h3>
      <p className="text-slate-400 mb-6">
        Drag & drop your TShark JSON export here
      </p>

      <label className="cursor-pointer bg-gradient-to-r from-cyan-600 
      to-blue-600 text-white px-8 py-3 rounded-xl font-medium 
      shadow-[0_0_15px_rgba(34,211,238,0.3)] 
      hover:shadow-[0_0_25px_rgba(34,211,238,0.5)] 
      hover:scale-105 transition-all duration-200 inline-block">
        Browse Files
        <input
          type="file"
          accept=".json"
          className="hidden"
          onChange={(e) => e.target.files?.length && 
            processFile(e.target.files[0])}
        />
      </label>

      {error && (
        <p className="mt-6 text-rose-400 text-sm font-medium animate-bounce">
          {error}
        </p>
      )}
    </div>
  );
}