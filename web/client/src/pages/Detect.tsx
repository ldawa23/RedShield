import { useState } from 'react';
import {
  Radar,
  Play,
  Target,
  AlertTriangle,
  CheckCircle,
  Clock,
  Loader2,
  Shield,
  ChevronDown,
  ChevronRight
} from 'lucide-react';

interface DetectionResult {
  signature_id: string;
  signature_name: string;
  severity: 'Critical' | 'High' | 'Medium' | 'Low';
  port: number;
  service: string;
  confidence: number;
  details: string;
  remediation: string;
}

interface DetectionRun {
  id: string;
  target: string;
  timestamp: string;
  status: 'running' | 'completed' | 'failed';
  results: DetectionResult[];
  duration: number;
}

export default function Detect() {
  const [target, setTarget] = useState('');
  const [ports, setPorts] = useState('22,80,443,3306,5432,27017,6379');
  const [selectedCategory, setSelectedCategory] = useState('all');
  const [selectedSeverity, setSelectedSeverity] = useState('all');
  const [isRunning, setIsRunning] = useState(false);
  const [currentRun, setCurrentRun] = useState<DetectionRun | null>(null);
  const [progress, setProgress] = useState(0);
  const [expandedResult, setExpandedResult] = useState<string | null>(null);

  const categories = [
    { value: 'all', label: 'All Categories' },
    { value: 'A01:2021', label: 'A01:2021 - Broken Access Control' },
    { value: 'A02:2021', label: 'A02:2021 - Cryptographic Failures' },
    { value: 'A03:2021', label: 'A03:2021 - Injection' },
    { value: 'A06:2021', label: 'A06:2021 - Vulnerable Components' },
    { value: 'A07:2021', label: 'A07:2021 - Auth Failures' }
  ];

  const runDetection = async () => {
    if (!target) return;

    setIsRunning(true);
    setProgress(0);
    setCurrentRun({
      id: `detect-${Date.now()}`,
      target,
      timestamp: new Date().toISOString(),
      status: 'running',
      results: [],
      duration: 0
    });

    // Simulate detection progress
    const portList = ports.split(',').map(p => parseInt(p.trim())).filter(p => !isNaN(p));
    const totalSteps = portList.length * 2;
    let step = 0;

    const mockResults: DetectionResult[] = [];

    for (const port of portList) {
      await new Promise(resolve => setTimeout(resolve, 500));
      step++;
      setProgress((step / totalSteps) * 100);

      // Simulate finding vulnerabilities
      if (port === 27017) {
        mockResults.push({
          signature_id: 'RS-DB-001',
          signature_name: 'Exposed MongoDB',
          severity: 'Critical',
          port: 27017,
          service: 'MongoDB',
          confidence: 95,
          details: 'MongoDB instance accessible without authentication on port 27017',
          remediation: 'Enable authentication and bind to localhost'
        });
      }
      if (port === 22) {
        mockResults.push({
          signature_id: 'RS-SSH-001',
          signature_name: 'SSH with Password Auth',
          severity: 'High',
          port: 22,
          service: 'SSH',
          confidence: 88,
          details: 'SSH server allows password authentication (prefer key-based)',
          remediation: 'Disable password authentication, use SSH keys only'
        });
      }
      if (port === 80) {
        mockResults.push({
          signature_id: 'RS-HTTP-001',
          signature_name: 'Unencrypted HTTP',
          severity: 'Medium',
          port: 80,
          service: 'HTTP',
          confidence: 100,
          details: 'Web service running without HTTPS encryption',
          remediation: 'Enable HTTPS with valid SSL/TLS certificate'
        });
      }
      if (port === 3306) {
        mockResults.push({
          signature_id: 'RS-DB-002',
          signature_name: 'Exposed MySQL',
          severity: 'Critical',
          port: 3306,
          service: 'MySQL',
          confidence: 92,
          details: 'MySQL database exposed to external connections',
          remediation: 'Restrict MySQL to localhost and use strong credentials'
        });
      }

      await new Promise(resolve => setTimeout(resolve, 300));
      step++;
      setProgress((step / totalSteps) * 100);
    }

    setCurrentRun(prev => prev ? {
      ...prev,
      status: 'completed',
      results: mockResults,
      duration: portList.length * 0.8
    } : null);
    setIsRunning(false);
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'Critical': return 'text-red-400 bg-red-500/20 border-red-500/50';
      case 'High': return 'text-orange-400 bg-orange-500/20 border-orange-500/50';
      case 'Medium': return 'text-yellow-400 bg-yellow-500/20 border-yellow-500/50';
      case 'Low': return 'text-blue-400 bg-blue-500/20 border-blue-500/50';
      default: return 'text-gray-400 bg-gray-500/20 border-gray-500/50';
    }
  };

  const getConfidenceColor = (confidence: number) => {
    if (confidence >= 90) return 'text-green-400';
    if (confidence >= 70) return 'text-yellow-400';
    return 'text-orange-400';
  };

  return (
    <div className="p-8">
      {/* Header */}
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-white mb-2">Detection Engine</h1>
        <p className="text-gray-400">Run vulnerability detection against targets using custom signatures</p>
      </div>

      {/* Detection Form */}
      <div className="bg-[#1a1a2e] rounded-xl border border-gray-800 p-6 mb-8">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div>
            <label className="block text-gray-400 text-sm mb-2">Target IP / Hostname</label>
            <div className="relative">
              <Target className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-500" />
              <input
                type="text"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                placeholder="192.168.1.100 or example.com"
                className="w-full bg-gray-800 border border-gray-700 rounded-lg pl-10 pr-4 py-3 text-white placeholder-gray-500 focus:border-red-500 focus:outline-none"
              />
            </div>
          </div>
          <div>
            <label className="block text-gray-400 text-sm mb-2">Ports to Check</label>
            <input
              type="text"
              value={ports}
              onChange={(e) => setPorts(e.target.value)}
              placeholder="22,80,443,3306"
              className="w-full bg-gray-800 border border-gray-700 rounded-lg px-4 py-3 text-white placeholder-gray-500 focus:border-red-500 focus:outline-none"
            />
          </div>
          <div>
            <label className="block text-gray-400 text-sm mb-2">OWASP Category Filter</label>
            <select
              value={selectedCategory}
              onChange={(e) => setSelectedCategory(e.target.value)}
              className="w-full bg-gray-800 border border-gray-700 rounded-lg px-4 py-3 text-white focus:border-red-500 focus:outline-none"
            >
              {categories.map(cat => (
                <option key={cat.value} value={cat.value}>{cat.label}</option>
              ))}
            </select>
          </div>
          <div>
            <label className="block text-gray-400 text-sm mb-2">Minimum Severity</label>
            <select
              value={selectedSeverity}
              onChange={(e) => setSelectedSeverity(e.target.value)}
              className="w-full bg-gray-800 border border-gray-700 rounded-lg px-4 py-3 text-white focus:border-red-500 focus:outline-none"
            >
              <option value="all">All Severities</option>
              <option value="Critical">Critical</option>
              <option value="High">High</option>
              <option value="Medium">Medium</option>
              <option value="Low">Low</option>
            </select>
          </div>
        </div>

        <button
          onClick={runDetection}
          disabled={isRunning || !target}
          className="mt-6 w-full flex items-center justify-center gap-2 px-6 py-3 bg-gradient-to-r from-red-500 to-red-600 text-white rounded-lg font-medium hover:from-red-600 hover:to-red-700 transition-all disabled:opacity-50 disabled:cursor-not-allowed"
        >
          {isRunning ? (
            <>
              <Loader2 className="w-5 h-5 animate-spin" />
              Running Detection...
            </>
          ) : (
            <>
              <Play className="w-5 h-5" />
              Start Detection
            </>
          )}
        </button>

        {/* Progress Bar */}
        {isRunning && (
          <div className="mt-4">
            <div className="flex justify-between text-sm mb-1">
              <span className="text-gray-400">Scanning ports...</span>
              <span className="text-white">{Math.round(progress)}%</span>
            </div>
            <div className="h-2 bg-gray-800 rounded-full overflow-hidden">
              <div 
                className="h-full bg-gradient-to-r from-red-500 to-red-600 transition-all duration-300"
                style={{ width: `${progress}%` }}
              />
            </div>
          </div>
        )}
      </div>

      {/* Results */}
      {currentRun && currentRun.status === 'completed' && (
        <div className="bg-[#1a1a2e] rounded-xl border border-gray-800">
          <div className="p-4 border-b border-gray-800 flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 bg-green-500/20 rounded-lg flex items-center justify-center">
                <CheckCircle className="w-5 h-5 text-green-400" />
              </div>
              <div>
                <h2 className="text-lg font-semibold text-white">Detection Complete</h2>
                <p className="text-gray-400 text-sm">
                  Found {currentRun.results.length} vulnerabilities in {currentRun.duration.toFixed(1)}s
                </p>
              </div>
            </div>
            <div className="flex items-center gap-4 text-sm">
              <div className="flex items-center gap-1 text-gray-400">
                <Target className="w-4 h-4" />
                {currentRun.target}
              </div>
              <div className="flex items-center gap-1 text-gray-400">
                <Clock className="w-4 h-4" />
                {new Date(currentRun.timestamp).toLocaleTimeString()}
              </div>
            </div>
          </div>

          {/* Summary Stats */}
          <div className="p-4 border-b border-gray-800 grid grid-cols-4 gap-4">
            {['Critical', 'High', 'Medium', 'Low'].map(severity => {
              const count = currentRun.results.filter(r => r.severity === severity).length;
              return (
                <div key={severity} className={`p-3 rounded-lg ${getSeverityColor(severity)} bg-opacity-10`}>
                  <p className="text-2xl font-bold">{count}</p>
                  <p className="text-sm opacity-80">{severity}</p>
                </div>
              );
            })}
          </div>

          {/* Results List */}
          <div className="p-4 space-y-3">
            {currentRun.results.length === 0 ? (
              <div className="text-center py-8">
                <Shield className="w-12 h-12 text-green-400 mx-auto mb-3" />
                <p className="text-white font-medium">No vulnerabilities detected</p>
                <p className="text-gray-400 text-sm">Target appears to be secure</p>
              </div>
            ) : (
              currentRun.results.map((result, index) => {
                const isExpanded = expandedResult === result.signature_id + index;
                return (
                  <div 
                    key={`${result.signature_id}-${index}`}
                    className="bg-gray-800/30 rounded-lg border border-gray-700"
                  >
                    <div 
                      className="p-4 cursor-pointer"
                      onClick={() => setExpandedResult(isExpanded ? null : result.signature_id + index)}
                    >
                      <div className="flex items-center gap-4">
                        <div className={`w-10 h-10 rounded-lg flex items-center justify-center ${getSeverityColor(result.severity)}`}>
                          <AlertTriangle className="w-5 h-5" />
                        </div>
                        <div className="flex-1">
                          <div className="flex items-center gap-2">
                            <span className="text-gray-500 font-mono text-sm">{result.signature_id}</span>
                            <h3 className="text-white font-medium">{result.signature_name}</h3>
                            <span className={`px-2 py-0.5 rounded text-xs font-medium ${getSeverityColor(result.severity)}`}>
                              {result.severity}
                            </span>
                          </div>
                          <p className="text-gray-400 text-sm mt-1">
                            {result.service} on port {result.port}
                          </p>
                        </div>
                        <div className="flex items-center gap-4">
                          <div className="text-right">
                            <p className={`text-sm font-medium ${getConfidenceColor(result.confidence)}`}>
                              {result.confidence}% confidence
                            </p>
                          </div>
                          {isExpanded ? (
                            <ChevronDown className="w-5 h-5 text-gray-400" />
                          ) : (
                            <ChevronRight className="w-5 h-5 text-gray-400" />
                          )}
                        </div>
                      </div>
                    </div>

                    {isExpanded && (
                      <div className="px-4 pb-4 border-t border-gray-700 pt-4">
                        <div className="grid grid-cols-2 gap-6">
                          <div>
                            <h4 className="text-gray-400 text-sm font-medium mb-2">Details</h4>
                            <p className="text-white text-sm">{result.details}</p>
                          </div>
                          <div>
                            <h4 className="text-gray-400 text-sm font-medium mb-2">Remediation</h4>
                            <p className="text-green-400 text-sm">{result.remediation}</p>
                          </div>
                        </div>
                      </div>
                    )}
                  </div>
                );
              })
            )}
          </div>
        </div>
      )}

      {/* Empty State */}
      {!currentRun && (
        <div className="bg-[#1a1a2e] rounded-xl border border-gray-800 p-12 text-center">
          <Radar className="w-16 h-16 text-gray-600 mx-auto mb-4" />
          <h3 className="text-xl font-medium text-white mb-2">Ready to Detect</h3>
          <p className="text-gray-400 max-w-md mx-auto">
            Enter a target IP address or hostname and click "Start Detection" to scan for vulnerabilities using our custom signature engine.
          </p>
        </div>
      )}
    </div>
  );
}
