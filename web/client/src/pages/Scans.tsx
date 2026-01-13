import { useState, useEffect } from 'react';
import { 
  Target, Clock, AlertTriangle, CheckCircle, 
  ChevronDown, ChevronRight, GitCompare, TrendingUp, TrendingDown,
  Shield, Search, ArrowRight, Minus
} from 'lucide-react';
import { scansApi } from '../services/api';

interface Scan {
  id: number;
  scan_id: string;
  target: string;
  port_range: string;
  scan_type: string;
  status: string;
  started_at: string;
  completed_at: string | null;
  vuln_count: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  fixed_count: number;
}

interface ComparisonResult {
  scan_before: Scan;
  scan_after: Scan;
  summary: {
    vulns_before: number;
    vulns_after: number;
    fixed_count: number;
    new_count: number;
    unchanged_count: number;
    improvement: string;
  };
  fixed: any[];
  new: any[];
  unchanged: any[];
}

function StatusBadge({ status }: { status: string }) {
  const colors: Record<string, string> = {
    completed: 'bg-green-500/20 text-green-400',
    running: 'bg-blue-500/20 text-blue-400',
    failed: 'bg-red-500/20 text-red-400',
    pending: 'bg-yellow-500/20 text-yellow-400',
  };
  return (
    <span className={`px-2 py-1 rounded text-xs font-medium ${colors[status?.toLowerCase()] || colors.pending}`}>
      {status?.toUpperCase()}
    </span>
  );
}

function SeverityBar({ critical, high, medium, low }: { critical: number; high: number; medium: number; low: number }) {
  const total = critical + high + medium + low;
  if (total === 0) return <span className="text-gray-500 text-xs">No vulnerabilities</span>;
  
  return (
    <div className="flex items-center gap-2">
      <div className="flex h-2 w-32 rounded-full overflow-hidden bg-gray-800">
        {critical > 0 && <div className="bg-red-500" style={{ width: `${(critical/total)*100}%` }} />}
        {high > 0 && <div className="bg-orange-500" style={{ width: `${(high/total)*100}%` }} />}
        {medium > 0 && <div className="bg-yellow-500" style={{ width: `${(medium/total)*100}%` }} />}
        {low > 0 && <div className="bg-green-500" style={{ width: `${(low/total)*100}%` }} />}
      </div>
      <span className="text-xs text-gray-400">{total}</span>
    </div>
  );
}

// Scan Comparison Component
function ScanComparison({ comparison, onClose }: { comparison: ComparisonResult; onClose: () => void }) {
  const { scan_before, scan_after, summary, fixed, new: newVulns } = comparison;
  const improvement = parseFloat(summary.improvement);
  
  return (
    <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4">
      <div className="bg-[#0d1f3c] rounded-2xl border border-gray-800 w-full max-w-5xl max-h-[90vh] overflow-hidden">
        {/* Header */}
        <div className="bg-gradient-to-r from-red-500/20 to-blue-500/20 p-6 border-b border-gray-800">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <GitCompare className="w-8 h-8 text-red-400" />
              <div>
                <h2 className="text-xl font-bold text-white">Scan Comparison</h2>
                <p className="text-gray-400 text-sm">Analyzing remediation progress</p>
              </div>
            </div>
            <button onClick={onClose} className="text-gray-400 hover:text-white text-2xl">×</button>
          </div>
        </div>

        <div className="p-6 overflow-y-auto max-h-[calc(90vh-100px)]">
          {/* Summary Cards */}
          <div className="grid grid-cols-2 gap-6 mb-6">
            {/* Before Scan */}
            <div className="bg-[#081225] rounded-xl p-4 border border-gray-800">
              <p className="text-gray-400 text-xs mb-2">BEFORE</p>
              <p className="text-white font-medium">{scan_before.scan_id}</p>
              <p className="text-gray-500 text-sm">{scan_before.target}</p>
              <p className="text-gray-500 text-xs mt-1">
                {new Date(scan_before.started_at).toLocaleString()}
              </p>
              <div className="mt-3 flex items-center gap-2">
                <span className="text-2xl font-bold text-red-400">{summary.vulns_before}</span>
                <span className="text-gray-500 text-sm">vulnerabilities</span>
              </div>
            </div>

            {/* After Scan */}
            <div className="bg-[#081225] rounded-xl p-4 border border-gray-800">
              <p className="text-gray-400 text-xs mb-2">AFTER</p>
              <p className="text-white font-medium">{scan_after.scan_id}</p>
              <p className="text-gray-500 text-sm">{scan_after.target}</p>
              <p className="text-gray-500 text-xs mt-1">
                {new Date(scan_after.started_at).toLocaleString()}
              </p>
              <div className="mt-3 flex items-center gap-2">
                <span className="text-2xl font-bold text-green-400">{summary.vulns_after}</span>
                <span className="text-gray-500 text-sm">vulnerabilities</span>
              </div>
            </div>
          </div>

          {/* Progress Indicator */}
          <div className={`rounded-xl p-6 mb-6 ${
            improvement > 0 ? 'bg-green-500/10 border border-green-500/30' : 
            improvement < 0 ? 'bg-red-500/10 border border-red-500/30' :
            'bg-gray-500/10 border border-gray-500/30'
          }`}>
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-4">
                {improvement > 0 ? (
                  <TrendingDown className="w-10 h-10 text-green-400" />
                ) : improvement < 0 ? (
                  <TrendingUp className="w-10 h-10 text-red-400" />
                ) : (
                  <Minus className="w-10 h-10 text-gray-400" />
                )}
                <div>
                  <p className={`text-3xl font-bold ${
                    improvement > 0 ? 'text-green-400' : improvement < 0 ? 'text-red-400' : 'text-gray-400'
                  }`}>
                    {improvement > 0 ? '+' : ''}{summary.improvement}%
                  </p>
                  <p className="text-gray-400">
                    {improvement > 0 ? 'Improvement' : improvement < 0 ? 'Regression' : 'No change'}
                  </p>
                </div>
              </div>
              <div className="grid grid-cols-3 gap-6 text-center">
                <div>
                  <p className="text-2xl font-bold text-green-400">{summary.fixed_count}</p>
                  <p className="text-gray-500 text-sm">Fixed</p>
                </div>
                <div>
                  <p className="text-2xl font-bold text-red-400">{summary.new_count}</p>
                  <p className="text-gray-500 text-sm">New</p>
                </div>
                <div>
                  <p className="text-2xl font-bold text-gray-400">{summary.unchanged_count}</p>
                  <p className="text-gray-500 text-sm">Unchanged</p>
                </div>
              </div>
            </div>
          </div>

          {/* Fixed Vulnerabilities */}
          {fixed.length > 0 && (
            <div className="mb-6">
              <h3 className="text-green-400 font-medium mb-3 flex items-center gap-2">
                <CheckCircle className="w-5 h-5" /> Fixed Vulnerabilities ({fixed.length})
              </h3>
              <div className="space-y-2">
                {fixed.map((v, i) => (
                  <div key={i} className="bg-green-500/10 border border-green-500/30 rounded-lg p-3 flex items-center justify-between">
                    <div>
                      <p className="text-white font-medium">{v.vuln_type}</p>
                      <p className="text-gray-500 text-sm">{v.service}:{v.port}</p>
                    </div>
                    <span className={`px-2 py-1 rounded text-xs ${
                      v.severity?.toUpperCase() === 'CRITICAL' ? 'bg-red-500/20 text-red-400' :
                      v.severity?.toUpperCase() === 'HIGH' ? 'bg-orange-500/20 text-orange-400' :
                      v.severity?.toUpperCase() === 'MEDIUM' ? 'bg-yellow-500/20 text-yellow-400' :
                      'bg-green-500/20 text-green-400'
                    }`}>
                      {v.severity}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* New Vulnerabilities */}
          {newVulns.length > 0 && (
            <div>
              <h3 className="text-red-400 font-medium mb-3 flex items-center gap-2">
                <AlertTriangle className="w-5 h-5" /> New Vulnerabilities ({newVulns.length})
              </h3>
              <div className="space-y-2">
                {newVulns.map((v, i) => (
                  <div key={i} className="bg-red-500/10 border border-red-500/30 rounded-lg p-3 flex items-center justify-between">
                    <div>
                      <p className="text-white font-medium">{v.vuln_type}</p>
                      <p className="text-gray-500 text-sm">{v.service}:{v.port}</p>
                    </div>
                    <span className={`px-2 py-1 rounded text-xs ${
                      v.severity?.toUpperCase() === 'CRITICAL' ? 'bg-red-500/20 text-red-400' :
                      v.severity?.toUpperCase() === 'HIGH' ? 'bg-orange-500/20 text-orange-400' :
                      v.severity?.toUpperCase() === 'MEDIUM' ? 'bg-yellow-500/20 text-yellow-400' :
                      'bg-green-500/20 text-green-400'
                    }`}>
                      {v.severity}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// Scan Card Component
function ScanCard({ scan, onSelect, isSelected, compareMode }: { 
  scan: Scan; 
  onSelect: () => void; 
  isSelected: boolean; 
  compareMode: boolean 
}) {
  const [expanded, setExpanded] = useState(false);

  return (
    <div className={`bg-[#0d1f3c] rounded-xl border ${isSelected ? 'border-red-500' : 'border-gray-800'} overflow-hidden`}>
      <div className="p-4">
        <div className="flex items-center gap-4">
          {compareMode && (
            <input
              type="checkbox"
              checked={isSelected}
              onChange={onSelect}
              className="w-5 h-5 rounded border-gray-600 text-red-500 focus:ring-red-500 bg-[#081225]"
            />
          )}
          
          <button 
            className="text-gray-400"
            onClick={() => setExpanded(!expanded)}
          >
            {expanded ? <ChevronDown className="w-5 h-5" /> : <ChevronRight className="w-5 h-5" />}
          </button>

          <div className="flex-1">
            <div className="flex items-center gap-3">
              <Target className="w-5 h-5 text-red-400" />
              <span className="text-white font-medium">{scan.target}</span>
              <StatusBadge status={scan.status} />
            </div>
            <div className="flex items-center gap-4 mt-1 text-sm text-gray-400">
              <span>{scan.scan_id}</span>
              <span className="flex items-center gap-1">
                <Clock className="w-3 h-3" />
                {new Date(scan.started_at).toLocaleString()}
              </span>
            </div>
          </div>

          <SeverityBar 
            critical={scan.critical_count || 0} 
            high={scan.high_count || 0} 
            medium={scan.medium_count || 0} 
            low={scan.low_count || 0} 
          />

          <div className="text-right">
            <p className="text-lg font-bold text-white">{scan.vuln_count || 0}</p>
            <p className="text-xs text-gray-500">vulnerabilities</p>
          </div>
        </div>
      </div>

      {expanded && (
        <div className="border-t border-gray-800 p-4 bg-[#081225]">
          <div className="grid grid-cols-4 gap-4">
            <div className="text-center">
              <p className="text-2xl font-bold text-red-400">{scan.critical_count || 0}</p>
              <p className="text-xs text-gray-500">Critical</p>
            </div>
            <div className="text-center">
              <p className="text-2xl font-bold text-orange-400">{scan.high_count || 0}</p>
              <p className="text-xs text-gray-500">High</p>
            </div>
            <div className="text-center">
              <p className="text-2xl font-bold text-yellow-400">{scan.medium_count || 0}</p>
              <p className="text-xs text-gray-500">Medium</p>
            </div>
            <div className="text-center">
              <p className="text-2xl font-bold text-green-400">{scan.low_count || 0}</p>
              <p className="text-xs text-gray-500">Low</p>
            </div>
          </div>
          
          <div className="mt-4 grid grid-cols-2 gap-4 text-sm">
            <div>
              <span className="text-gray-500">Scan Type:</span>
              <span className="text-white ml-2">{scan.scan_type}</span>
            </div>
            <div>
              <span className="text-gray-500">Port Range:</span>
              <span className="text-white ml-2">{scan.port_range}</span>
            </div>
            <div>
              <span className="text-gray-500">Started:</span>
              <span className="text-white ml-2">{new Date(scan.started_at).toLocaleString()}</span>
            </div>
            <div>
              <span className="text-gray-500">Completed:</span>
              <span className="text-white ml-2">
                {scan.completed_at ? new Date(scan.completed_at).toLocaleString() : 'In progress'}
              </span>
            </div>
          </div>

          {scan.fixed_count > 0 && (
            <div className="mt-4 bg-green-500/10 border border-green-500/30 rounded-lg p-3">
              <p className="text-green-400 flex items-center gap-2">
                <CheckCircle className="w-4 h-4" />
                {scan.fixed_count} vulnerabilities have been fixed
              </p>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export default function Scans() {
  const [scans, setScans] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [compareMode, setCompareMode] = useState(false);
  const [selectedScans, setSelectedScans] = useState<string[]>([]);
  const [comparison, setComparison] = useState<ComparisonResult | null>(null);
  const [comparing, setComparing] = useState(false);

  useEffect(() => {
    const fetchScans = async () => {
      try {
        const res = await scansApi.getAll();
        setScans(res.data || []);
      } catch (error) {
        console.error('Error fetching scans:', error);
      } finally {
        setLoading(false);
      }
    };
    fetchScans();
  }, []);

  const handleSelectScan = (scanId: string) => {
    setSelectedScans(prev => {
      if (prev.includes(scanId)) {
        return prev.filter(id => id !== scanId);
      }
      if (prev.length >= 2) {
        return [prev[1], scanId];
      }
      return [...prev, scanId];
    });
  };

  const handleCompare = async () => {
    if (selectedScans.length !== 2) return;
    
    setComparing(true);
    try {
      const res = await scansApi.compare(selectedScans[0], selectedScans[1]);
      setComparison(res.data);
    } catch (error) {
      console.error('Error comparing scans:', error);
    } finally {
      setComparing(false);
    }
  };

  const filteredScans = scans.filter(scan =>
    scan.target?.toLowerCase().includes(searchTerm.toLowerCase()) ||
    scan.scan_id?.toLowerCase().includes(searchTerm.toLowerCase())
  );

  // Group scans by target
  const scansByTarget = filteredScans.reduce((acc, scan) => {
    const target = scan.target;
    if (!acc[target]) acc[target] = [];
    acc[target].push(scan);
    return acc;
  }, {} as Record<string, Scan[]>);

  const stats = {
    total: scans.length,
    completed: scans.filter(s => s.status === 'completed').length,
    totalVulns: scans.reduce((sum, s) => sum + (s.vuln_count || 0), 0),
    totalFixed: scans.reduce((sum, s) => sum + (s.fixed_count || 0), 0),
  };

  if (loading) {
    return (
      <div className="p-6 flex items-center justify-center h-screen">
        <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-red-500"></div>
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Scans</h1>
          <p className="text-gray-400 text-sm mt-1">View and compare security scans</p>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={() => {
              setCompareMode(!compareMode);
              setSelectedScans([]);
            }}
            className={`px-4 py-2 rounded-lg flex items-center gap-2 transition-colors ${
              compareMode 
                ? 'bg-red-500 text-white' 
                : 'bg-[#0d1f3c] text-gray-400 hover:text-white border border-gray-700'
            }`}
          >
            <GitCompare className="w-4 h-4" />
            {compareMode ? 'Cancel' : 'Compare Scans'}
          </button>
          {compareMode && selectedScans.length === 2 && (
            <button
              onClick={handleCompare}
              disabled={comparing}
              className="px-4 py-2 bg-green-500 hover:bg-green-600 text-white rounded-lg flex items-center gap-2"
            >
              {comparing ? (
                <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
              ) : (
                <ArrowRight className="w-4 h-4" />
              )}
              Compare Selected
            </button>
          )}
        </div>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-4 gap-4">
        <div className="bg-[#0d1f3c] rounded-xl p-4 border border-gray-800">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-blue-500/20 rounded-lg">
              <Target className="w-5 h-5 text-blue-400" />
            </div>
            <div>
              <p className="text-gray-400 text-xs">Total Scans</p>
              <p className="text-2xl font-bold text-white">{stats.total}</p>
            </div>
          </div>
        </div>
        <div className="bg-[#0d1f3c] rounded-xl p-4 border border-gray-800">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-green-500/20 rounded-lg">
              <CheckCircle className="w-5 h-5 text-green-400" />
            </div>
            <div>
              <p className="text-gray-400 text-xs">Completed</p>
              <p className="text-2xl font-bold text-white">{stats.completed}</p>
            </div>
          </div>
        </div>
        <div className="bg-[#0d1f3c] rounded-xl p-4 border border-gray-800">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-red-500/20 rounded-lg">
              <AlertTriangle className="w-5 h-5 text-red-400" />
            </div>
            <div>
              <p className="text-gray-400 text-xs">Total Vulns</p>
              <p className="text-2xl font-bold text-white">{stats.totalVulns}</p>
            </div>
          </div>
        </div>
        <div className="bg-[#0d1f3c] rounded-xl p-4 border border-gray-800">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-green-500/20 rounded-lg">
              <Shield className="w-5 h-5 text-green-400" />
            </div>
            <div>
              <p className="text-gray-400 text-xs">Fixed</p>
              <p className="text-2xl font-bold text-white">{stats.totalFixed}</p>
            </div>
          </div>
        </div>
      </div>

      {/* Compare Mode Instructions */}
      {compareMode && (
        <div className="bg-blue-500/10 border border-blue-500/30 rounded-xl p-4">
          <p className="text-blue-400 flex items-center gap-2">
            <GitCompare className="w-5 h-5" />
            Select 2 scans to compare. Selected: {selectedScans.length}/2
            {selectedScans.length === 2 && ' - Ready to compare!'}
          </p>
        </div>
      )}

      {/* Search */}
      <div className="relative">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
        <input
          type="text"
          placeholder="Search by target or scan ID..."
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
          className="w-full bg-[#0d1f3c] border border-gray-700 rounded-xl pl-10 pr-4 py-3 text-white placeholder-gray-500 focus:outline-none focus:border-red-500"
        />
      </div>

      {/* Scans grouped by target */}
      <div className="space-y-6">
        {Object.entries(scansByTarget).map(([target, targetScans]) => (
          <div key={target}>
            <div className="flex items-center gap-2 mb-3">
              <Globe className="w-4 h-4 text-gray-500" />
              <h3 className="text-gray-400 font-medium">{target}</h3>
              <span className="text-gray-600 text-sm">({targetScans.length} scans)</span>
            </div>
            <div className="space-y-3">
              {targetScans.map(scan => (
                <ScanCard
                  key={scan.scan_id}
                  scan={scan}
                  compareMode={compareMode}
                  isSelected={selectedScans.includes(scan.scan_id)}
                  onSelect={() => handleSelectScan(scan.scan_id)}
                />
              ))}
            </div>
          </div>
        ))}
      </div>

      {filteredScans.length === 0 && (
        <div className="bg-[#0d1f3c] rounded-xl p-8 border border-gray-800 text-center">
          <Target className="w-12 h-12 text-gray-600 mx-auto mb-3" />
          <p className="text-gray-400">No scans found</p>
          <p className="text-gray-500 text-sm mt-1">Run a scan using: redshield scan &lt;target&gt;</p>
        </div>
      )}

      {/* Comparison Modal */}
      {comparison && (
        <ScanComparison 
          comparison={comparison} 
          onClose={() => setComparison(null)} 
        />
      )}
    </div>
  );
}

function Globe(props: any) {
  return (
    <svg {...props} xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="12" r="10"/>
      <line x1="2" y1="12" x2="22" y2="12"/>
      <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>
    </svg>
  );
}
