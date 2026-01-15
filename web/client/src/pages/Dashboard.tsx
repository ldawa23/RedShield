import { useState, useEffect, useContext } from 'react';
import { useNavigate } from 'react-router-dom';
import { AuthContext } from '../App';
import {
  Shield,
  Target,
  AlertTriangle,
  CheckCircle,
  Clock,
  Scan,
  Bug,
  Wrench,
  FileText,
  ChevronRight,
  Zap,
  Play,
  HelpCircle,
  ArrowRight,
  BookOpen
} from 'lucide-react';
import api from '../services/api';

interface DashboardStats {
  total_scans: number;
  total_vulns: number;
  fixed_vulns: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
}

interface RecentScan {
  id: number;
  scan_id: string;
  target: string;
  scan_type: string;
  status: string;
  started_at: string;
}

interface RecentVuln {
  id: number;
  vuln_type: string;
  severity: string;
  target: string;
  status: string;
  service: string;
  port: number;
}

// Plain English explanations for non-tech users
const SEVERITY_INFO = {
  critical: {
    meaning: "Extremely Dangerous",
    action: "Fix immediately - hackers could take over your entire system",
    color: "red"
  },
  high: {
    meaning: "Very Serious",
    action: "Fix within 24 hours - significant security risk",
    color: "orange"
  },
  medium: {
    meaning: "Moderate Risk",
    action: "Fix this week - could be exploited with some effort",
    color: "yellow"
  },
  low: {
    meaning: "Minor Issue",
    action: "Fix when you have time - low risk but worth addressing",
    color: "green"
  }
};

export default function Dashboard() {
  const navigate = useNavigate();
  const auth = useContext(AuthContext);
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [recentScans, setRecentScans] = useState<RecentScan[]>([]);
  const [recentVulns, setRecentVulns] = useState<RecentVuln[]>([]);
  const [loading, setLoading] = useState(true);
  const [showHelp, setShowHelp] = useState(false);

  useEffect(() => {
    loadDashboardData();
  }, []);

  const loadDashboardData = async () => {
    try {
      const [statsRes, scansRes, vulnsRes] = await Promise.all([
        api.get('/stats'),
        api.get('/scans'),
        api.get('/vulnerabilities?limit=6')
      ]);
      
      // Map API response to expected format
      const apiStats = statsRes.data;
      const mappedStats: DashboardStats = {
        total_scans: apiStats.totalScans || apiStats.total_scans || 0,
        total_vulns: apiStats.totalVulnerabilities || apiStats.total_vulns || 0,
        fixed_vulns: apiStats.fixedVulnerabilities || apiStats.fixed_vulns || 0,
        critical: apiStats.severityCounts?.critical || apiStats.critical || 0,
        high: apiStats.severityCounts?.high || apiStats.high || 0,
        medium: apiStats.severityCounts?.medium || apiStats.medium || 0,
        low: apiStats.severityCounts?.low || apiStats.low || 0
      };
      
      setStats(mappedStats);
      
      // Handle scans - API returns array directly or object with scans property
      const scansData = Array.isArray(scansRes.data) ? scansRes.data : (scansRes.data.scans || []);
      setRecentScans(scansData.slice(0, 5));
      
      // Handle vulnerabilities
      const vulnsData = Array.isArray(vulnsRes.data) ? vulnsRes.data : (vulnsRes.data.vulnerabilities || []);
      setRecentVulns(vulnsData.slice(0, 6));
    } catch (err) {
      console.error('Failed to load dashboard:', err);
    } finally {
      setLoading(false);
    }
  };

  const getSecurityScore = () => {
    if (!stats) return 100;
    const totalVulns = stats.total_vulns || 0;
    const fixedVulns = stats.fixed_vulns || 0;
    const critical = stats.critical || 0;
    const high = stats.high || 0;
    const medium = stats.medium || 0;
    const low = stats.low || 0;
    
    if (totalVulns === 0) return 100;
    
    const severityWeight = (critical * 40 + high * 25 + medium * 10 + low * 5);
    const maxPossibleWeight = totalVulns * 40;
    
    if (maxPossibleWeight === 0) return 100;
    
    const rawScore = 100 - (severityWeight / maxPossibleWeight * 100);
    const fixBonus = totalVulns > 0 ? (fixedVulns / totalVulns) * 20 : 0;
    const finalScore = Math.max(0, Math.min(100, Math.round(rawScore + fixBonus)));
    
    return isNaN(finalScore) ? 100 : finalScore;
  };

  const getScoreStatus = (score: number) => {
    if (score >= 80) return { label: "Good", sublabel: "Your systems are well protected", color: "green" };
    if (score >= 60) return { label: "Fair", sublabel: "Some issues need attention", color: "yellow" };
    if (score >= 40) return { label: "At Risk", sublabel: "Several vulnerabilities found", color: "orange" };
    return { label: "Critical", sublabel: "Immediate action required!", color: "red" };
  };

  const score = getSecurityScore();
  const scoreStatus = getScoreStatus(score);
  const openVulns = (stats?.total_vulns || 0) - (stats?.fixed_vulns || 0);

  if (loading) {
    return (
      <div className="p-8 flex items-center justify-center min-h-screen">
        <div className="text-center">
          <div className="relative w-20 h-20 mx-auto mb-4">
            <div className="absolute inset-0 border-4 border-blue-500/30 rounded-full"></div>
            <div className="absolute inset-0 border-4 border-blue-500 rounded-full border-t-transparent animate-spin"></div>
            <Shield className="absolute inset-0 m-auto w-8 h-8 text-blue-400" />
          </div>
          <p className="text-gray-400 text-lg">Loading your security dashboard...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="p-6 lg:p-8 min-h-screen bg-gradient-to-br from-[#0a0f1a] via-[#0d1525] to-[#0a1628]">
      {/* Welcome Header */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between mb-8 gap-4">
        <div>
          <h1 className="text-2xl lg:text-3xl font-bold text-white mb-2">
            Welcome back, {auth?.user?.username}!
          </h1>
          <p className="text-gray-400 text-lg">
            Here's an overview of your security status
          </p>
        </div>
        <div className="flex gap-3">
          <button
            onClick={() => setShowHelp(!showHelp)}
            className="px-4 py-2 bg-gray-800 hover:bg-gray-700 text-gray-300 rounded-xl flex items-center gap-2 transition-colors"
          >
            <HelpCircle className="w-5 h-5" />
            Need Help?
          </button>
          <button
            onClick={() => navigate('/new-scan')}
            className="px-6 py-3 bg-gradient-to-r from-blue-600 to-blue-700 hover:from-blue-500 hover:to-blue-600 text-white rounded-xl font-semibold flex items-center gap-2 transition-all shadow-lg shadow-blue-500/20"
          >
            <Play className="w-5 h-5" />
            Start New Scan
          </button>
        </div>
      </div>

      {/* Help Panel - Simple Explanation */}
      {showHelp && (
        <div className="mb-8 bg-blue-500/10 border border-blue-500/30 rounded-2xl p-6">
          <h3 className="text-white font-semibold text-lg mb-4 flex items-center gap-2">
            <BookOpen className="w-5 h-5 text-blue-400" />
            How RedShield Works (Simple Guide)
          </h3>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            {[
              { step: 1, title: "Scan", desc: "Enter your website address and we check for security problems", icon: Scan },
              { step: 2, title: "Review", desc: "See what we found - explained in plain English", icon: Bug },
              { step: 3, title: "Fix", desc: "Click to fix problems automatically", icon: Wrench },
              { step: 4, title: "Report", desc: "Get a detailed report to share with your team", icon: FileText },
            ].map((item) => (
              <div key={item.step} className="bg-[#0a0f1a] rounded-xl p-4">
                <div className="flex items-center gap-3 mb-2">
                  <div className="w-8 h-8 rounded-full bg-blue-500 flex items-center justify-center text-white font-bold text-sm">
                    {item.step}
                  </div>
                  <item.icon className="w-5 h-5 text-blue-400" />
                </div>
                <h4 className="text-white font-medium mb-1">{item.title}</h4>
                <p className="text-gray-400 text-sm">{item.desc}</p>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Security Score Card */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-8">
        <div className="lg:col-span-2 bg-gradient-to-br from-[#111827] to-[#0d1525] rounded-2xl p-6 border border-gray-800">
          <div className="flex items-start justify-between mb-6">
            <div>
              <h2 className="text-gray-400 text-sm font-medium mb-1">Your Security Score</h2>
              <div className="flex items-center gap-3">
                <div>
                  <p className={`text-2xl font-bold ${
                    scoreStatus.color === 'green' ? 'text-green-400' :
                    scoreStatus.color === 'yellow' ? 'text-yellow-400' :
                    scoreStatus.color === 'orange' ? 'text-orange-400' : 'text-red-400'
                  }`}>{scoreStatus.label}</p>
                  <p className="text-gray-500">{scoreStatus.sublabel}</p>
                </div>
              </div>
            </div>
            <div className="text-right">
              <div className={`text-5xl font-bold ${
                scoreStatus.color === 'green' ? 'text-green-400' :
                scoreStatus.color === 'yellow' ? 'text-yellow-400' :
                scoreStatus.color === 'orange' ? 'text-orange-400' : 'text-red-400'
              }`}>{score}</div>
              <div className="text-gray-500">out of 100</div>
            </div>
          </div>

          {/* Visual Score Bar */}
          <div className="mb-6">
            <div className="h-4 bg-gray-700 rounded-full overflow-hidden">
              <div 
                className={`h-full rounded-full transition-all duration-1000 ${
                  score >= 80 ? 'bg-gradient-to-r from-green-600 to-green-400' :
                  score >= 60 ? 'bg-gradient-to-r from-yellow-600 to-yellow-400' :
                  score >= 40 ? 'bg-gradient-to-r from-orange-600 to-orange-400' :
                  'bg-gradient-to-r from-red-600 to-red-400'
                }`}
                style={{ width: `${score}%` }}
              />
            </div>
          </div>

          {/* Quick Stats */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div className="bg-[#0a0f1a] rounded-xl p-4 text-center">
              <Scan className="w-6 h-6 text-blue-400 mx-auto mb-2" />
              <p className="text-2xl font-bold text-white">{stats?.total_scans || 0}</p>
              <p className="text-gray-400 text-sm">Scans Run</p>
            </div>
            <div className="bg-[#0a0f1a] rounded-xl p-4 text-center">
              <Bug className="w-6 h-6 text-red-400 mx-auto mb-2" />
              <p className="text-2xl font-bold text-white">{stats?.total_vulns || 0}</p>
              <p className="text-gray-400 text-sm">Issues Found</p>
            </div>
            <div className="bg-[#0a0f1a] rounded-xl p-4 text-center">
              <CheckCircle className="w-6 h-6 text-green-400 mx-auto mb-2" />
              <p className="text-2xl font-bold text-green-400">{stats?.fixed_vulns || 0}</p>
              <p className="text-gray-400 text-sm">Fixed</p>
            </div>
            <div className="bg-[#0a0f1a] rounded-xl p-4 text-center">
              <AlertTriangle className="w-6 h-6 text-orange-400 mx-auto mb-2" />
              <p className="text-2xl font-bold text-orange-400">{openVulns}</p>
              <p className="text-gray-400 text-sm">Need Fixing</p>
            </div>
          </div>
        </div>

        {/* Severity Breakdown */}
        <div className="bg-gradient-to-br from-[#111827] to-[#0d1525] rounded-2xl p-6 border border-gray-800">
          <h3 className="text-white font-semibold mb-4 flex items-center gap-2">
            <AlertTriangle className="w-5 h-5 text-orange-400" />
            Issues by Severity
          </h3>
          <div className="space-y-3">
            {(['critical', 'high', 'medium', 'low'] as const).map((level) => {
              const count = stats?.[level] || 0;
              const info = SEVERITY_INFO[level];
              return (
                <button
                  key={level}
                  onClick={() => navigate('/vulnerabilities')}
                  className={`w-full p-4 rounded-xl border transition-all hover:scale-[1.02] ${
                    level === 'critical' ? 'bg-red-500/10 border-red-500/30 hover:border-red-500/60' :
                    level === 'high' ? 'bg-orange-500/10 border-orange-500/30 hover:border-orange-500/60' :
                    level === 'medium' ? 'bg-yellow-500/10 border-yellow-500/30 hover:border-yellow-500/60' :
                    'bg-green-500/10 border-green-500/30 hover:border-green-500/60'
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      <div className="text-left">
                        <p className={`font-semibold capitalize ${
                          level === 'critical' ? 'text-red-400' :
                          level === 'high' ? 'text-orange-400' :
                          level === 'medium' ? 'text-yellow-400' : 'text-green-400'
                        }`}>{level}</p>
                        <p className="text-gray-500 text-xs">{info.meaning}</p>
                      </div>
                    </div>
                    <div className={`text-3xl font-bold ${
                      level === 'critical' ? 'text-red-400' :
                      level === 'high' ? 'text-orange-400' :
                      level === 'medium' ? 'text-yellow-400' : 'text-green-400'
                    }`}>{count}</div>
                  </div>
                </button>
              );
            })}
          </div>
        </div>
      </div>

      {/* Action Required Banner */}
      {openVulns > 0 && (
        <div className="mb-8 bg-gradient-to-r from-orange-500/10 via-red-500/10 to-orange-500/10 border border-orange-500/30 rounded-2xl p-6">
          <h3 className="text-white font-semibold text-lg mb-2 flex items-center gap-2">
            <Zap className="w-5 h-5 text-orange-400" />
            Action Required
          </h3>
          <p className="text-gray-400 mb-4">
            You have <span className="text-orange-400 font-bold">{openVulns} security issues</span> that need attention.
          </p>
          <div className="flex flex-wrap gap-3">
            <button
              onClick={() => navigate('/vulnerabilities')}
              className="px-4 py-2 bg-orange-600 hover:bg-orange-500 text-white rounded-lg font-medium flex items-center gap-2"
            >
              View All Issues <ArrowRight className="w-4 h-4" />
            </button>
            <button
              onClick={() => navigate('/fix')}
              className="px-4 py-2 bg-green-600 hover:bg-green-500 text-white rounded-lg font-medium flex items-center gap-2"
            >
              Fix Issues Now <Wrench className="w-4 h-4" />
            </button>
          </div>
        </div>
      )}

      {/* Recent Activity */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Recent Scans */}
        <div className="bg-gradient-to-br from-[#111827] to-[#0d1525] rounded-2xl border border-gray-800 overflow-hidden">
          <div className="p-4 border-b border-gray-800 flex items-center justify-between">
            <h3 className="text-white font-semibold flex items-center gap-2">
              <Scan className="w-5 h-5 text-blue-400" />
              Recent Scans
            </h3>
            <button onClick={() => navigate('/scans')} className="text-blue-400 text-sm hover:text-blue-300 flex items-center gap-1">
              View All <ChevronRight className="w-4 h-4" />
            </button>
          </div>
          <div className="p-4">
            {recentScans.length === 0 ? (
              <div className="text-center py-8">
                <Scan className="w-12 h-12 text-gray-700 mx-auto mb-3" />
                <p className="text-gray-400 font-medium">No scans yet</p>
                <p className="text-gray-600 text-sm mb-4">Run your first security scan</p>
                <button onClick={() => navigate('/new-scan')} className="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-lg text-sm">
                  Start First Scan
                </button>
              </div>
            ) : (
              <div className="space-y-3">
                {recentScans.map((scan) => (
                  <button
                    key={scan.id}
                    onClick={() => navigate(`/scans/${scan.scan_id}`)}
                    className="w-full flex items-center gap-3 p-3 rounded-lg bg-[#0a0f1a] hover:bg-[#111827] transition-colors text-left"
                  >
                    <div className={`w-10 h-10 rounded-lg flex items-center justify-center ${
                      scan.status === 'completed' ? 'bg-green-500/20' : 'bg-blue-500/20'
                    }`}>
                      {scan.status === 'completed' ? (
                        <CheckCircle className="w-5 h-5 text-green-400" />
                      ) : (
                        <Clock className="w-5 h-5 text-blue-400" />
                      )}
                    </div>
                    <div className="flex-1 min-w-0">
                      <p className="text-white font-medium truncate">{scan.target}</p>
                      <p className="text-gray-500 text-sm">{new Date(scan.started_at).toLocaleDateString()}</p>
                    </div>
                    <ChevronRight className="w-4 h-4 text-gray-600" />
                  </button>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* Recent Vulnerabilities */}
        <div className="bg-gradient-to-br from-[#111827] to-[#0d1525] rounded-2xl border border-gray-800 overflow-hidden">
          <div className="p-4 border-b border-gray-800 flex items-center justify-between">
            <h3 className="text-white font-semibold flex items-center gap-2">
              <Bug className="w-5 h-5 text-red-400" />
              Recent Issues Found
            </h3>
            <button onClick={() => navigate('/vulnerabilities')} className="text-red-400 text-sm hover:text-red-300 flex items-center gap-1">
              View All <ChevronRight className="w-4 h-4" />
            </button>
          </div>
          <div className="p-4">
            {recentVulns.length === 0 ? (
              <div className="text-center py-8">
                <Shield className="w-12 h-12 text-green-500/30 mx-auto mb-3" />
                <p className="text-green-400 font-medium">All Clear!</p>
                <p className="text-gray-600 text-sm">No security issues found</p>
              </div>
            ) : (
              <div className="space-y-2">
                {recentVulns.slice(0, 5).map((vuln) => (
                  <button
                    key={vuln.id}
                    onClick={() => navigate('/vulnerabilities')}
                    className="w-full flex items-center gap-3 p-3 rounded-lg bg-[#0a0f1a] hover:bg-[#111827] transition-colors text-left"
                  >
                    <div className={`w-1.5 h-10 rounded-full ${
                      vuln.severity?.toUpperCase() === 'CRITICAL' ? 'bg-red-500' :
                      vuln.severity?.toUpperCase() === 'HIGH' ? 'bg-orange-500' :
                      vuln.severity?.toUpperCase() === 'MEDIUM' ? 'bg-yellow-500' : 'bg-green-500'
                    }`} />
                    <div className="flex-1 min-w-0">
                      <p className="text-white font-medium truncate">{vuln.vuln_type}</p>
                      <p className="text-gray-500 text-sm truncate">{vuln.target}</p>
                    </div>
                    <span className={`px-2 py-1 rounded text-xs font-medium ${
                      vuln.status === 'fixed' ? 'bg-green-500/20 text-green-400' : 'bg-red-500/20 text-red-400'
                    }`}>
                      {vuln.status === 'fixed' ? 'Fixed' : 'Open'}
                    </span>
                  </button>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Getting Started Guide */}
      {stats?.total_scans === 0 && (
        <div className="mt-8 bg-gradient-to-r from-blue-500/10 to-purple-500/10 border border-blue-500/30 rounded-2xl p-6">
          <h3 className="text-white font-semibold text-lg mb-4 flex items-center gap-2">
            <Target className="w-5 h-5 text-blue-400" />
            Getting Started - Your First Security Check
          </h3>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
            <div className="bg-[#0a0f1a] rounded-xl p-4">
              <h4 className="text-white font-medium mb-1">Step 1: Choose a Target</h4>
              <p className="text-gray-500 text-sm">
                Enter the website or IP address you want to check. For testing, try: <code className="bg-gray-800 px-1 rounded">testphp.vulnweb.com</code>
              </p>
            </div>
            <div className="bg-[#0a0f1a] rounded-xl p-4">
              <h4 className="text-white font-medium mb-1">Step 2: Run the Scan</h4>
              <p className="text-gray-500 text-sm">
                Click "Start Scan" and wait. We'll check for common security problems.
              </p>
            </div>
            <div className="bg-[#0a0f1a] rounded-xl p-4">
              <h4 className="text-white font-medium mb-1">Step 3: Review & Fix</h4>
              <p className="text-gray-500 text-sm">
                We'll show what we found with simple explanations and fixes.
              </p>
            </div>
          </div>
          <div className="text-center">
            <button onClick={() => navigate('/new-scan')} className="px-8 py-3 bg-blue-600 hover:bg-blue-500 text-white rounded-xl font-semibold text-lg">
              Start Your First Scan →
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
