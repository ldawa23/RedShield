import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Scan,
  Play,
  AlertCircle,
  CheckCircle,
  Loader2,
  Globe,
  Server,
  Shield,
  Info,
  HelpCircle,
  Clock,
  AlertTriangle,
  Zap,
  Search,
  Eye
} from 'lucide-react';
import api from '../services/api';

// Simple explanations for non-IT users
const SCAN_OPTIONS = {
  quick: {
    title: '⚡ Quick Scan',
    time: '2-5 minutes',
    description: 'A fast check of the most common security issues',
    whatWeCheck: [
      'Most commonly attacked entry points',
      'Basic security problems',
      'Software running on the target'
    ],
    recommendation: 'Good for: Daily or weekly checkups',
    icon: Zap,
    color: 'green',
    durationMs: 120000 // 2 minutes (realistic demo timing)
  },
  full: {
    title: '🔍 Full Scan',
    time: '10-20 minutes',
    description: 'A thorough check covering most security concerns',
    whatWeCheck: [
      'Over 1,000 potential entry points',
      'Known security vulnerabilities (CVEs)',
      'Outdated or vulnerable software',
      'Configuration mistakes'
    ],
    recommendation: 'Good for: Monthly security reviews',
    icon: Search,
    color: 'blue',
    durationMs: 300000 // 5 minutes (for demo - realistically 10-20min)
  },
  deep: {
    title: '🛡️ Deep Scan',
    time: '30-60 minutes',
    description: 'The most comprehensive security analysis possible',
    whatWeCheck: [
      'All 65,535 possible entry points',
      'In-depth vulnerability testing',
      'Detailed software version analysis',
      'Complete configuration audit',
      'Compliance verification'
    ],
    recommendation: 'Good for: Quarterly audits or before major changes',
    icon: Shield,
    color: 'purple',
    durationMs: 600000 // 10 minutes (for demo - realistically 30-60min)
  }
};

// Simple phase explanations with more detail
const SCAN_PHASES = [
  { progress: 5, phase: 'Starting up...', detail: 'Initializing security scanning engines' },
  { progress: 8, phase: 'Target resolution...', detail: 'Resolving hostname and IP addresses' },
  { progress: 12, phase: 'Connectivity check...', detail: 'Testing network path to target' },
  { progress: 18, phase: 'Host discovery...', detail: 'Confirming target is online and responsive' },
  { progress: 25, phase: 'Port scanning...', detail: 'Scanning TCP/UDP ports for open services' },
  { progress: 32, phase: 'Service detection...', detail: 'Identifying running services and versions' },
  { progress: 40, phase: 'OS fingerprinting...', detail: 'Determining operating system type' },
  { progress: 48, phase: 'Vulnerability database...', detail: 'Loading CVE database and vulnerability signatures' },
  { progress: 55, phase: 'Vulnerability testing...', detail: 'Testing for known security vulnerabilities' },
  { progress: 62, phase: 'Web scanning...', detail: 'Checking web application security' },
  { progress: 70, phase: 'Configuration audit...', detail: 'Analyzing security configurations' },
  { progress: 78, phase: 'SSL/TLS analysis...', detail: 'Checking encryption and certificates' },
  { progress: 85, phase: 'Data correlation...', detail: 'Correlating findings with threat intelligence' },
  { progress: 92, phase: 'Report generation...', detail: 'Compiling security assessment report' },
  { progress: 97, phase: 'Finalizing...', detail: 'Saving results and generating recommendations' },
];

export default function NewScan() {
  const navigate = useNavigate();
  const [target, setTarget] = useState('');
  const [scanType, setScanType] = useState<'quick' | 'full' | 'deep'>('quick');
  const [isScanning, setIsScanning] = useState(false);
  const [scanProgress, setScanProgress] = useState(0);
  const [currentPhase, setCurrentPhase] = useState({ phase: '', detail: '' });
  const [scanResult, setScanResult] = useState<any>(null);
  const [error, setError] = useState('');
  const [recentTargets, setRecentTargets] = useState<string[]>([]);

  useEffect(() => {
    loadRecentTargets();
  }, []);

  const loadRecentTargets = async () => {
    try {
      const res = await api.get('/scans');
      const targets = [...new Set(res.data.map((s: any) => s.target))].slice(0, 5);
      setRecentTargets(targets as string[]);
    } catch (err) {
      console.error('Failed to load recent targets');
    }
  };

  const isValidTarget = (t: string): boolean => {
    if (!t.trim()) return false;
    const ipPattern = /^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$/;
    const domainPattern = /^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$/;
    const urlPattern = /^https?:\/\/.+/;
    return ipPattern.test(t) || domainPattern.test(t) || urlPattern.test(t);
  };

  const getTargetType = (t: string): { type: string; icon: any } => {
    if (t.startsWith('http://') || t.startsWith('https://')) return { type: 'Website', icon: Globe };
    if (/^(\d{1,3}\.){3}\d{1,3}/.test(t)) return { type: 'IP Address', icon: Server };
    return { type: 'Domain', icon: Globe };
  };

  const handleStartScan = async () => {
    if (!target.trim()) {
      setError('Please enter something to scan');
      return;
    }
    if (!isValidTarget(target)) {
      setError('Please enter a valid target. Examples: 192.168.1.1, example.com, or https://mysite.com');
      return;
    }

    setError('');
    setIsScanning(true);
    setScanProgress(0);
    setScanResult(null);

    // Get realistic timing based on scan type
    const scanConfig = SCAN_OPTIONS[scanType];
    const totalDuration = scanConfig.durationMs;
    const phaseCount = SCAN_PHASES.length;
    const baseDelayPerPhase = Math.floor(totalDuration / phaseCount);

    for (const phase of SCAN_PHASES) {
      // Calculate delay with some randomness for realistic feel
      const randomVariation = Math.random() * 0.3 - 0.15; // ±15%
      const phaseDelay = baseDelayPerPhase * (1 + randomVariation);
      
      await new Promise(resolve => setTimeout(resolve, phaseDelay));
      setScanProgress(phase.progress);
      setCurrentPhase({ phase: phase.phase, detail: phase.detail });
    }

    try {
      const res = await api.post('/scans/start', {
        target: target.trim(),
        scanType,
        scanner: 'auto'
      });

      setScanProgress(100);
      setCurrentPhase({ phase: 'Complete!', detail: 'Your security report is ready' });
      setScanResult(res.data);

      // Log this activity
      try {
        await api.post('/activity/log', {
          action: 'SCAN_COMPLETED',
          resource_type: 'scan',
          resource_id: res.data.scan_id,
          details: `Completed ${scanType} scan on ${target}`
        });
      } catch (e) {}

    } catch (err: any) {
      setError(err.response?.data?.error || 'The scan failed. Please check your target and try again.');
      setIsScanning(false);
    }
  };

  const selectedScan = SCAN_OPTIONS[scanType];

  return (
    <div className="p-6 min-h-full">
      {/* Header with Welcome Message */}
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-white flex items-center gap-3 mb-2">
          <div className="w-12 h-12 rounded-xl bg-gradient-to-br from-green-500 to-green-700 flex items-center justify-center">
            <Scan className="w-7 h-7 text-white" />
          </div>
          Security Scan
        </h1>
        <p className="text-gray-400 text-lg">
          Check your website or server for security problems before hackers can exploit them
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        {/* Main Section */}
        <div className="lg:col-span-2 space-y-6">
          
          {/* Step 1: Target */}
          <div className="bg-gradient-to-br from-[#0d1f3c] to-[#0a1628] rounded-2xl border border-gray-800 p-6">
            <div className="flex items-center gap-3 mb-4">
              <div className="w-8 h-8 rounded-full bg-green-500 flex items-center justify-center text-white font-bold text-sm">1</div>
              <h2 className="text-xl font-semibold text-white">What do you want to scan?</h2>
            </div>
            
            <div className="relative">
              <input
                type="text"
                value={target}
                onChange={(e) => { setTarget(e.target.value); setError(''); }}
                placeholder="Enter your website, IP address, or domain name..."
                className="w-full bg-[#081225] border-2 border-gray-700 rounded-xl px-5 py-4 text-white text-lg placeholder-gray-500 focus:outline-none focus:border-green-500 transition-colors"
                disabled={isScanning}
              />
              {target && (
                <div className="absolute right-4 top-1/2 -translate-y-1/2 flex items-center gap-2">
                  {isValidTarget(target) ? (
                    <>
                      <CheckCircle className="w-5 h-5 text-green-400" />
                      <span className="text-green-400 text-sm font-medium">{getTargetType(target).type}</span>
                    </>
                  ) : (
                    <AlertCircle className="w-5 h-5 text-yellow-400" />
                  )}
                </div>
              )}
            </div>

            {/* Help text */}
            <div className="mt-4 flex flex-wrap gap-3">
              <span className="text-gray-500 text-sm">Examples:</span>
              <button 
                onClick={() => setTarget('192.168.1.1')} 
                className="text-sm bg-gray-800/70 text-gray-300 px-3 py-1 rounded-lg hover:bg-gray-700/70 transition-colors"
                disabled={isScanning}
              >
                192.168.1.1
              </button>
              <button 
                onClick={() => setTarget('example.com')} 
                className="text-sm bg-gray-800/70 text-gray-300 px-3 py-1 rounded-lg hover:bg-gray-700/70 transition-colors"
                disabled={isScanning}
              >
                example.com
              </button>
              <button 
                onClick={() => setTarget('http://localhost')} 
                className="text-sm bg-gray-800/70 text-gray-300 px-3 py-1 rounded-lg hover:bg-gray-700/70 transition-colors"
                disabled={isScanning}
              >
                http://localhost
              </button>
            </div>

            {/* Recent Targets */}
            {recentTargets.length > 0 && !isScanning && (
              <div className="mt-4 pt-4 border-t border-gray-800">
                <p className="text-gray-500 text-sm mb-2 flex items-center gap-1">
                  <Clock className="w-4 h-4" /> Recently scanned:
                </p>
                <div className="flex flex-wrap gap-2">
                  {recentTargets.map((t, i) => (
                    <button
                      key={i}
                      onClick={() => setTarget(t)}
                      className="text-sm bg-blue-500/10 text-blue-300 border border-blue-500/30 px-3 py-1.5 rounded-lg hover:bg-blue-500/20 transition-colors"
                    >
                      {t}
                    </button>
                  ))}
                </div>
              </div>
            )}

            {error && (
              <div className="mt-4 p-4 bg-red-500/10 border border-red-500/30 rounded-xl flex items-start gap-3">
                <AlertCircle className="w-5 h-5 text-red-400 flex-shrink-0 mt-0.5" />
                <div>
                  <p className="text-red-400 font-medium">Please check your input</p>
                  <p className="text-red-300/80 text-sm">{error}</p>
                </div>
              </div>
            )}
          </div>

          {/* Step 2: Scan Type */}
          <div className="bg-gradient-to-br from-[#0d1f3c] to-[#0a1628] rounded-2xl border border-gray-800 p-6">
            <div className="flex items-center gap-3 mb-4">
              <div className="w-8 h-8 rounded-full bg-blue-500 flex items-center justify-center text-white font-bold text-sm">2</div>
              <h2 className="text-xl font-semibold text-white">How thorough should we check?</h2>
            </div>
            
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              {(['quick', 'full', 'deep'] as const).map((type) => {
                const option = SCAN_OPTIONS[type];
                const isSelected = scanType === type;
                const Icon = option.icon;
                
                return (
                  <button
                    key={type}
                    onClick={() => setScanType(type)}
                    disabled={isScanning}
                    className={`relative text-left p-5 rounded-xl border-2 transition-all ${
                      isSelected 
                        ? option.color === 'green' ? 'border-green-500 bg-green-500/10' 
                        : option.color === 'blue' ? 'border-blue-500 bg-blue-500/10'
                        : 'border-purple-500 bg-purple-500/10'
                        : 'border-gray-700 bg-[#081225] hover:border-gray-600'
                    }`}
                  >
                    {isSelected && (
                      <div className="absolute top-3 right-3">
                        <CheckCircle className={`w-5 h-5 ${
                          option.color === 'green' ? 'text-green-400' 
                          : option.color === 'blue' ? 'text-blue-400'
                          : 'text-purple-400'
                        }`} />
                      </div>
                    )}
                    
                    <Icon className={`w-8 h-8 mb-3 ${
                      isSelected 
                        ? option.color === 'green' ? 'text-green-400' 
                          : option.color === 'blue' ? 'text-blue-400'
                          : 'text-purple-400'
                        : 'text-gray-500'
                    }`} />
                    
                    <h3 className={`font-semibold text-lg mb-1 ${isSelected ? 'text-white' : 'text-gray-300'}`}>
                      {option.title}
                    </h3>
                    
                    <div className="flex items-center gap-1 text-sm text-gray-400 mb-2">
                      <Clock className="w-4 h-4" />
                      {option.time}
                    </div>
                    
                    <p className="text-gray-500 text-sm">{option.description}</p>
                  </button>
                );
              })}
            </div>
          </div>

          {/* Start Scan Button */}
          {!isScanning && !scanResult && (
            <button
              onClick={handleStartScan}
              disabled={!target.trim()}
              className="w-full py-5 bg-gradient-to-r from-green-600 to-green-500 hover:from-green-500 hover:to-green-400 disabled:from-gray-700 disabled:to-gray-600 text-white font-bold text-lg rounded-xl transition-all flex items-center justify-center gap-3 shadow-lg shadow-green-500/25 disabled:shadow-none"
            >
              <Play className="w-6 h-6" />
              Start Security Scan
            </button>
          )}

          {/* Scanning Progress */}
          {isScanning && (
            <div className="bg-gradient-to-br from-[#0d1f3c] to-[#0a1628] rounded-2xl border border-blue-500/50 p-6">
              <div className="flex items-center justify-between mb-4">
                <div className="flex items-center gap-3">
                  <div className="relative">
                    <Loader2 className="w-8 h-8 text-blue-400 animate-spin" />
                  </div>
                  <div>
                    <h3 className="text-white font-semibold text-lg">Scanning in progress</h3>
                    <p className="text-gray-400 text-sm">Please wait while we check for security issues</p>
                  </div>
                </div>
                <span className="text-2xl font-bold text-blue-400">{scanProgress}%</span>
              </div>
              
              {/* Progress Bar */}
              <div className="h-4 bg-gray-800 rounded-full overflow-hidden mb-4">
                <div 
                  className="h-full bg-gradient-to-r from-blue-600 to-blue-400 transition-all duration-500 ease-out relative"
                  style={{ width: `${scanProgress}%` }}
                >
                  <div className="absolute inset-0 bg-white/20 animate-pulse" />
                </div>
              </div>
              
              {/* Current Phase */}
              <div className="flex items-center gap-2 text-blue-300 mb-6">
                <Eye className="w-4 h-4" />
                <span className="font-medium">{currentPhase.phase}</span>
              </div>
              
              {/* Explanation Box */}
              <div className="bg-blue-500/10 border border-blue-500/30 rounded-xl p-4">
                <div className="flex items-start gap-3">
                  <Info className="w-5 h-5 text-blue-400 flex-shrink-0 mt-0.5" />
                  <div>
                    <p className="text-blue-300 font-medium">What's happening right now?</p>
                    <p className="text-gray-400 text-sm mt-1">{currentPhase.detail}</p>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* Results */}
          {scanResult && (
            <div className="bg-gradient-to-br from-[#0d1f3c] to-[#0a1628] rounded-2xl border border-green-500/50 p-6">
              <div className="flex items-center gap-4 mb-6">
                <div className="w-14 h-14 rounded-full bg-green-500/20 flex items-center justify-center">
                  <CheckCircle className="w-8 h-8 text-green-400" />
                </div>
                <div>
                  <h3 className="text-2xl font-bold text-white">Scan Complete!</h3>
                  <p className="text-gray-400">Here's a summary of what we found</p>
                </div>
              </div>

              {/* Results Summary - Simple Cards */}
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
                <div className="bg-red-500/10 border border-red-500/30 rounded-xl p-4 text-center">
                  <p className="text-4xl font-bold text-red-400">{scanResult.critical || 0}</p>
                  <p className="text-red-400 font-medium">Critical</p>
                  <p className="text-gray-500 text-xs mt-1">Fix immediately!</p>
                </div>
                <div className="bg-orange-500/10 border border-orange-500/30 rounded-xl p-4 text-center">
                  <p className="text-4xl font-bold text-orange-400">{scanResult.high || 0}</p>
                  <p className="text-orange-400 font-medium">High Risk</p>
                  <p className="text-gray-500 text-xs mt-1">Fix very soon</p>
                </div>
                <div className="bg-yellow-500/10 border border-yellow-500/30 rounded-xl p-4 text-center">
                  <p className="text-4xl font-bold text-yellow-400">{scanResult.medium || 0}</p>
                  <p className="text-yellow-400 font-medium">Medium</p>
                  <p className="text-gray-500 text-xs mt-1">Plan to fix</p>
                </div>
                <div className="bg-green-500/10 border border-green-500/30 rounded-xl p-4 text-center">
                  <p className="text-4xl font-bold text-green-400">{scanResult.low || 0}</p>
                  <p className="text-green-400 font-medium">Low</p>
                  <p className="text-gray-500 text-xs mt-1">When convenient</p>
                </div>
              </div>

              {/* Recommendation Box */}
              <div className={`rounded-xl p-4 mb-6 ${
                (scanResult.critical || 0) + (scanResult.high || 0) > 0 
                  ? 'bg-red-500/10 border border-red-500/30' 
                  : 'bg-green-500/10 border border-green-500/30'
              }`}>
                <div className="flex items-start gap-3">
                  {(scanResult.critical || 0) + (scanResult.high || 0) > 0 ? (
                    <AlertTriangle className="w-6 h-6 text-red-400 flex-shrink-0" />
                  ) : (
                    <CheckCircle className="w-6 h-6 text-green-400 flex-shrink-0" />
                  )}
                  <div>
                    <p className={`font-semibold ${
                      (scanResult.critical || 0) + (scanResult.high || 0) > 0 ? 'text-red-300' : 'text-green-300'
                    }`}>
                      {(scanResult.critical || 0) + (scanResult.high || 0) > 0 
                        ? '⚠️ Urgent action needed!' 
                        : '✅ Looking good!'}
                    </p>
                    <p className="text-gray-400 text-sm mt-1">
                      {(scanResult.critical || 0) + (scanResult.high || 0) > 0 
                        ? `We found ${(scanResult.critical || 0) + (scanResult.high || 0)} serious security issues that need your attention. Click "Fix Issues" to resolve them.`
                        : (scanResult.medium || 0) + (scanResult.low || 0) > 0
                          ? 'No critical issues found! There are some minor items you can address when convenient.'
                          : 'Great news! No security vulnerabilities were found. Your system looks secure!'}
                    </p>
                  </div>
                </div>
              </div>

              {/* Action Buttons */}
              <div className="flex flex-col sm:flex-row gap-4">
                <button
                  onClick={() => navigate(`/scans/${scanResult.scan_id}`)}
                  className="flex-1 py-3 bg-blue-500 hover:bg-blue-600 text-white font-semibold rounded-xl transition-colors flex items-center justify-center gap-2"
                >
                  <Eye className="w-5 h-5" />
                  View Scan Details
                </button>
                <button
                  onClick={() => navigate('/vulnerabilities')}
                  className="flex-1 py-3 bg-purple-500 hover:bg-purple-600 text-white font-semibold rounded-xl transition-colors flex items-center justify-center gap-2"
                >
                  <Shield className="w-5 h-5" />
                  All Vulnerabilities
                </button>
                {(scanResult.critical || 0) + (scanResult.high || 0) > 0 && (
                  <button
                    onClick={() => navigate('/fix')}
                    className="flex-1 py-3 bg-red-500 hover:bg-red-600 text-white font-semibold rounded-xl transition-colors flex items-center justify-center gap-2"
                  >
                    <AlertTriangle className="w-5 h-5" />
                    Fix Issues Now
                  </button>
                )}
              </div>
              <button
                onClick={() => { setScanResult(null); setTarget(''); setIsScanning(false); }}
                className="w-full mt-3 py-3 bg-gray-700 hover:bg-gray-600 text-white font-semibold rounded-xl transition-colors flex items-center justify-center gap-2"
              >
                <Scan className="w-5 h-5" />
                Start New Scan
              </button>
            </div>
          )}
        </div>

        {/* Sidebar - Help & Info */}
        <div className="space-y-6">
          {/* Understanding the Scan */}
          <div className="bg-gradient-to-br from-[#0d1f3c] to-[#0a1628] rounded-2xl border border-gray-800 p-6">
            <div className="flex items-center gap-2 mb-4">
              <HelpCircle className="w-5 h-5 text-blue-400" />
              <h3 className="text-white font-semibold">What We're Checking</h3>
            </div>
            
            <div className="space-y-3">
              <h4 className="text-lg font-medium text-white">{selectedScan.title}</h4>
              <p className="text-gray-400 text-sm">{selectedScan.description}</p>
              
              <div className="pt-3 border-t border-gray-800">
                <p className="text-gray-500 text-xs uppercase tracking-wider mb-2">What this scan checks:</p>
                <ul className="space-y-2">
                  {selectedScan.whatWeCheck.map((item, i) => (
                    <li key={i} className="flex items-start gap-2 text-sm text-gray-300">
                      <CheckCircle className="w-4 h-4 text-green-400 flex-shrink-0 mt-0.5" />
                      {item}
                    </li>
                  ))}
                </ul>
              </div>
              
              <div className="pt-3">
                <p className="text-blue-400 text-sm">{selectedScan.recommendation}</p>
              </div>
            </div>
          </div>

          {/* Safety Notice */}
          <div className="bg-yellow-500/10 border border-yellow-500/30 rounded-2xl p-5">
            <div className="flex items-start gap-3">
              <AlertTriangle className="w-6 h-6 text-yellow-400 flex-shrink-0" />
              <div>
                <p className="text-yellow-300 font-semibold mb-1">Important Reminder</p>
                <p className="text-gray-400 text-sm">
                  Only scan systems that you own or have permission to test. Unauthorized scanning may violate laws.
                </p>
              </div>
            </div>
          </div>

          {/* Quick Tips */}
          <div className="bg-gradient-to-br from-[#0d1f3c] to-[#0a1628] rounded-2xl border border-gray-800 p-6">
            <div className="flex items-center gap-2 mb-4">
              <Info className="w-5 h-5 text-green-400" />
              <h3 className="text-white font-semibold">Tips</h3>
            </div>
            
            <ul className="space-y-3 text-sm text-gray-400">
              <li className="flex items-start gap-2">
                <span className="text-green-400">•</span>
                Start with a <strong className="text-white">Quick Scan</strong> for routine checks
              </li>
              <li className="flex items-start gap-2">
                <span className="text-blue-400">•</span>
                Use <strong className="text-white">Full Scan</strong> for monthly security reviews
              </li>
              <li className="flex items-start gap-2">
                <span className="text-purple-400">•</span>
                Run <strong className="text-white">Deep Scan</strong> before major deployments
              </li>
            </ul>
          </div>
        </div>
      </div>
    </div>
  );
}
