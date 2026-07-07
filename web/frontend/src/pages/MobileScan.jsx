import { useState, useRef, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Upload, Smartphone, FileWarning, AlertTriangle, CheckCircle,
  Loader2, Shield,
} from 'lucide-react';
import {
  Card, useToast,
} from '../components/ui';
import { uploadMobileApp } from '../lib/api';

const ALLOWED_TYPES = {
  apk: { ext: '.apk', mime: ['application/vnd.android.package-archive', 'application/octet-stream'], label: 'APK' },
  ipa: { ext: '.ipa', mime: ['application/octet-stream', 'application/zip'], label: 'IPA' },
};

const SCAN_MODES = [
  { value: 'quick', label: 'Quick', desc: 'Fast scan — key findings only' },
  { value: 'standard', label: 'Standard', desc: 'Balanced depth and speed' },
  { value: 'deep', label: 'Deep', desc: 'Thorough analysis — all categories' },
];

export default function MobileScan() {
  const [file, setFile] = useState(null);
  const [fileError, setFileError] = useState('');
  const [targetType, setTargetType] = useState('apk');
  const [scanMode, setScanMode] = useState('standard');
  const [instruction, setInstruction] = useState('');
  const [uploading, setUploading] = useState(false);
  const [result, setResult] = useState(null);
  const [dragOver, setDragOver] = useState(false);
  const fileInputRef = useRef(null);
  const toast = useToast();
  const navigate = useNavigate();

  const validateFile = useCallback((f) => {
    if (!f) { setFile(null); setFileError(''); return; }
    const ext = '.' + f.name.split('.').pop().toLowerCase();
    const type = targetType;
    const expected = ALLOWED_TYPES[type];
    if (ext !== expected.ext) {
      setFileError(`Expected ${expected.label} file (.${type}), got ${ext}`);
      setFile(null);
      return;
    }
    if (f.size > 500 * 1024 * 1024) {
      setFileError('File too large — maximum 500 MB');
      setFile(null);
      return;
    }
    setFile(f);
    setFileError('');
  }, [targetType]);

  const handleDrop = useCallback((e) => {
    e.preventDefault();
    setDragOver(false);
    const f = e.dataTransfer.files?.[0];
    validateFile(f);
  }, [validateFile]);

  const handleDragOver = useCallback((e) => {
    e.preventDefault();
    setDragOver(true);
  }, []);

  const handleDragLeave = useCallback((e) => {
    e.preventDefault();
    setDragOver(false);
  }, []);

  const handleFileSelect = useCallback((e) => {
    const f = e.target.files?.[0];
    validateFile(f);
  }, [validateFile]);

  const handleSubmit = async () => {
    if (!file) { toast('Please select a file first', 'error'); return; }
    setUploading(true);
    setResult(null);
    try {
      const res = await uploadMobileApp(file, scanMode, instruction);
      setResult(res);
      toast(`Scan started: ${res.target}`, 'success', 5000);
    } catch (err) {
      toast(err.message, 'error');
    } finally {
      setUploading(false);
    }
  };

  const formatSize = (bytes) => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
    return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
  };

  return (
    <div className="space-y-6" onDragOver={handleDragOver} onDragLeave={handleDragLeave} onDrop={handleDrop}>
      {/* Header */}
      <div>
        <h1 className="text-3xl font-bold text-gray-900 dark:text-white">Mobile App Scan</h1>
        <p className="text-gray-500 dark:text-gray-400 mt-1">
          Upload an APK or IPA file for static security analysis
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left: Upload + Config */}
        <div className="lg:col-span-2 space-y-6">
          {/* File Upload */}
          <Card title="Upload App Binary" icon={Upload}>
            <div className="space-y-4">
              {/* Target type toggle */}
              <div className="flex gap-3">
                <button
                  onClick={() => { setTargetType('apk'); setFile(null); setFileError(''); }}
                  className={`flex items-center gap-2 px-5 py-3 rounded-xl border text-sm font-medium transition-all flex-1 justify-center ${
                    targetType === 'apk'
                      ? 'bg-green-500/10 border-green-500/30 text-green-400'
                      : 'bg-white dark:bg-gray-900 border-gray-200 dark:border-gray-800 text-gray-500 dark:text-gray-400 hover:border-gray-300 dark:hover:border-gray-700'
                  }`}
                >
                  <Smartphone className="w-4 h-4" />
                  Android (.apk)
                </button>
                <button
                  onClick={() => { setTargetType('ipa'); setFile(null); setFileError(''); }}
                  className={`flex items-center gap-2 px-5 py-3 rounded-xl border text-sm font-medium transition-all flex-1 justify-center ${
                    targetType === 'ipa'
                      ? 'bg-green-500/10 border-green-500/30 text-green-400'
                      : 'bg-white dark:bg-gray-900 border-gray-200 dark:border-gray-800 text-gray-500 dark:text-gray-400 hover:border-gray-300 dark:hover:border-gray-700'
                  }`}
                >
                  <Smartphone className="w-4 h-4" />
                  iOS (.ipa)
                </button>
              </div>

              {/* Drop zone */}
              <div
                onClick={() => fileInputRef.current?.click()}
                className={`border-2 border-dashed rounded-xl p-10 text-center cursor-pointer transition-all ${
                  dragOver
                    ? 'border-green-500 bg-green-500/5'
                    : file
                      ? 'border-green-500/50 bg-green-500/5'
                      : 'border-gray-700 hover:border-gray-500 bg-gray-900/30'
                }`}
              >
                <input
                  ref={fileInputRef}
                  type="file"
                  accept={`.${targetType}`}
                  onChange={handleFileSelect}
                  className="hidden"
                />

                {file ? (
                  <div className="space-y-2">
                    <CheckCircle className="w-10 h-10 text-green-400 mx-auto" />
                    <p className="text-green-400 font-medium">{file.name}</p>
                    <p className="text-sm text-gray-500">{formatSize(file.size)}</p>
                    <button
                      onClick={(e) => { e.stopPropagation(); setFile(null); setFileError(''); }}
                      className="text-xs text-gray-500 hover:text-red-400 transition-colors"
                    >
                      Remove
                    </button>
                  </div>
                ) : (
                  <div className="space-y-3">
                    <Upload className="w-10 h-10 text-gray-500 mx-auto" />
                    <p className="text-gray-400 font-medium">
                      {dragOver ? 'Drop file here' : `Drop ${targetType.toUpperCase()} file here, or click to browse`}
                    </p>
                    <p className="text-xs text-gray-600">Max 500 MB</p>
                  </div>
                )}
              </div>

              {fileError && (
                <div className="flex items-center gap-2 text-sm text-red-400 bg-red-500/5 border border-red-500/20 rounded-lg px-4 py-3">
                  <FileWarning className="w-4 h-4 flex-shrink-0" />
                  {fileError}
                </div>
              )}
            </div>
          </Card>

          {/* Scan Mode */}
          <Card title="Scan Mode" icon={Shield}>
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
              {SCAN_MODES.map(mode => (
                <button
                  key={mode.value}
                  onClick={() => setScanMode(mode.value)}
                  className={`text-left p-4 rounded-xl border transition-all ${
                    scanMode === mode.value
                      ? 'bg-green-500/10 border-green-500/30'
                      : 'bg-white dark:bg-gray-900 border-gray-200 dark:border-gray-800 hover:border-gray-300 dark:hover:border-gray-700'
                  }`}
                >
                  <p className={`text-sm font-medium ${
                    scanMode === mode.value ? 'text-green-400' : 'text-gray-900 dark:text-white'
                  }`}>
                    {mode.label}
                  </p>
                  <p className="text-xs text-gray-500 mt-1">{mode.desc}</p>
                </button>
              ))}
            </div>
          </Card>

          {/* Instructions */}
          <Card title="Instructions (optional)" icon={AlertTriangle}>
            <textarea
              value={instruction}
              onChange={(e) => setInstruction(e.target.value)}
              placeholder="e.g., Focus on hardcoded secrets and insecure data storage"
              rows={3}
              className="w-full rounded-xl border border-gray-700 bg-gray-800 px-4 py-3 text-white placeholder-gray-500 focus:border-green-500 focus:outline-none text-sm resize-none"
            />
          </Card>
        </div>

        {/* Right: Summary + Submit */}
        <div className="space-y-6">
          <Card title="Scan Summary">
            <div className="space-y-4">
              <div>
                <p className="text-xs text-gray-500 uppercase tracking-wider">Target Type</p>
                <p className="text-sm text-gray-900 dark:text-white font-medium mt-1">
                  {targetType === 'apk' ? 'Android APK' : 'iOS IPA'}
                </p>
              </div>
              <div>
                <p className="text-xs text-gray-500 uppercase tracking-wider">File</p>
                <p className="text-sm text-gray-900 dark:text-white font-medium mt-1 truncate">
                  {file ? file.name : 'No file selected'}
                </p>
              </div>
              <div>
                <p className="text-xs text-gray-500 uppercase tracking-wider">Scan Mode</p>
                <p className="text-sm text-gray-900 dark:text-white font-medium mt-1 capitalize">{scanMode}</p>
              </div>
              {instruction && (
                <div>
                  <p className="text-xs text-gray-500 uppercase tracking-wider">Instructions</p>
                  <p className="text-sm text-gray-400 mt-1 line-clamp-2">{instruction}</p>
                </div>
              )}

              <hr className="border-gray-800" />

              <button
                onClick={handleSubmit}
                disabled={!file || uploading}
                className="w-full py-3 rounded-xl text-sm font-bold transition-all flex items-center justify-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed bg-green-600 hover:bg-green-700 text-white"
              >
                {uploading ? (
                  <>
                    <Loader2 className="w-4 h-4 animate-spin" />
                    Uploading & Starting Scan...
                  </>
                ) : (
                  <>
                    <Upload className="w-4 h-4" />
                    Start Mobile Scan
                  </>
                )}
              </button>
            </div>
          </Card>

          {/* Result */}
          {result && (
            <Card title="Scan Started" icon={CheckCircle}>
              <div className="space-y-3 text-sm">
                <div className="flex items-center gap-2 text-green-400">
                  <CheckCircle className="w-4 h-4" />
                  <span className="font-medium">Scan initiated successfully</span>
                </div>
                <div>
                  <p className="text-xs text-gray-500">Target</p>
                  <p className="text-gray-300 font-mono text-xs mt-1">{result.target}</p>
                </div>
                <div>
                  <p className="text-xs text-gray-500">Scan ID</p>
                  <p className="text-gray-300 font-mono text-xs mt-1">{result.scan_id}</p>
                </div>
                <button
                  onClick={() => navigate(`/scan/${result.scan_id}`)}
                  className="w-full py-2.5 rounded-xl text-sm font-medium bg-gray-800 hover:bg-gray-700 text-gray-300 transition-colors mt-2"
                >
                  View Scan Details
                </button>
              </div>
            </Card>
          )}
        </div>
      </div>

      {/* Global drag-over overlay */}
      {dragOver && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-gray-950/80 backdrop-blur-sm pointer-events-none">
          <div className="text-center">
            <Upload className="w-16 h-16 text-green-400 mx-auto mb-4" />
            <p className="text-2xl font-bold text-green-400">Drop your file here</p>
            <p className="text-gray-500 mt-2">APK or IPA file for security analysis</p>
          </div>
        </div>
      )}
    </div>
  );
}
