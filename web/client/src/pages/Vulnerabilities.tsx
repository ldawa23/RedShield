import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { 
  AlertTriangle, Search, ChevronRight, 
  CheckCircle, Info, Bug, HelpCircle, Wrench, Shield,
  Code, FileText
} from 'lucide-react';
import api from '../services/api';

// Plain English explanations for each vulnerability type - COMPREHENSIVE
const VULN_EXPLANATIONS: Record<string, {
  whatItIs: string;
  whyItMatters: string;
  realWorldExample: string;
  howToFix: string;
}> = {
  'SQL Injection': {
    whatItIs: "A security hole that lets hackers send commands to your database through your website's forms or URLs.",
    whyItMatters: "Hackers could steal all your customer data, delete your entire database, or take control of your server.",
    realWorldExample: "Imagine someone typing a 'magic password' that makes your website show them everyone's private information.",
    howToFix: "We need to add special filters to your website that check all user input before sending it to the database."
  },
  'Cross-Site Scripting': {
    whatItIs: "A vulnerability that lets attackers inject malicious code into pages that other users see.",
    whyItMatters: "Attackers can steal login sessions, redirect users to fake websites, or deface your site.",
    realWorldExample: "Like someone putting a fake 'Click here for a prize' sign in your store that actually steals wallets.",
    howToFix: "We sanitize (clean) all user input before displaying it on your pages."
  },
  'XSS': {
    whatItIs: "A vulnerability that lets attackers inject malicious code into pages that other users see.",
    whyItMatters: "Attackers can steal login sessions, redirect users to fake websites, or deface your site.",
    realWorldExample: "Like someone putting a fake 'Click here for a prize' sign in your store that actually steals wallets.",
    howToFix: "We sanitize (clean) all user input before displaying it on your pages."
  },
  'Command Injection': {
    whatItIs: "A hole that lets attackers run system commands on your server through your website.",
    whyItMatters: "Complete server takeover - attackers could read all files, install malware, or destroy everything.",
    realWorldExample: "Like leaving your server's keyboard accessible to anyone on the internet.",
    howToFix: "We restrict what commands can be run and never pass user input directly to system commands."
  },
  'Default Credentials': {
    whatItIs: "Your system is using factory-default usernames and passwords that everyone knows.",
    whyItMatters: "Anyone can look up the default password online and log into your system.",
    realWorldExample: "Like never changing the '1234' PIN code that came with your new safe.",
    howToFix: "Change all default passwords to strong, unique ones immediately."
  },
  'Exposed Database': {
    whatItIs: "Your database is accessible directly from the internet without protection.",
    whyItMatters: "Anyone can connect to your database and see, modify, or delete all your data.",
    realWorldExample: "Like leaving your filing cabinet on the sidewalk with no lock.",
    howToFix: "Configure firewall rules to block external access and require authentication."
  },
  'Outdated Software': {
    whatItIs: "You're running old software with known security vulnerabilities that have been publicly disclosed.",
    whyItMatters: "Hackers have tools that automatically exploit these known vulnerabilities.",
    realWorldExample: "Like using a lock that was on the news for being easy to pick, and never replacing it.",
    howToFix: "Update to the latest version of the software which has these issues fixed."
  },
  'Open SSH Port': {
    whatItIs: "SSH (remote access) is open to the internet, allowing connection attempts from anywhere.",
    whyItMatters: "Hackers constantly scan for open SSH ports and try to guess passwords.",
    realWorldExample: "Like having a door to your server room that faces the public street.",
    howToFix: "Restrict SSH access to specific IP addresses or use a VPN."
  },
  'Weak SSL/TLS': {
    whatItIs: "Your website's encryption is outdated or misconfigured.",
    whyItMatters: "Attackers could intercept and read data sent between users and your website.",
    realWorldExample: "Like sending sensitive letters through a glass envelope.",
    howToFix: "Update SSL/TLS configuration to use modern, strong encryption."
  },
  'Information Disclosure': {
    whatItIs: "Your system is revealing sensitive information it shouldn't (error messages, version numbers, etc.).",
    whyItMatters: "This information helps attackers plan targeted attacks against your specific setup.",
    realWorldExample: "Like posting your alarm system model and schedule on your front door.",
    howToFix: "Configure error handling to show generic messages and hide system details."
  }
};

const getVulnExplanation = (vulnType: string) => {
  const key = Object.keys(VULN_EXPLANATIONS).find(k => 
    vulnType.toLowerCase().includes(k.toLowerCase())
  );
  return VULN_EXPLANATIONS[key || ''] || {
    whatItIs: "A security weakness that could allow unauthorized access.",
    whyItMatters: "This could lead to data breach or system compromise.",
    realWorldExample: "A gap in your security that hackers could exploit.",
    howToFix: "Apply the recommended security patches and configurations."
  };
};

interface Vulnerability {
  id: number;
  vuln_type: string;
  severity: string;
  status: string;
  service: string;
  port: number;
  description: string;
  discovered_at: string;
  fixed_at: string | null;
  cve_id: string | null;
  fix_description: string | null;
  scan_id: string;
  target: string;
}

function SeverityBadge({ severity }: { severity: string }) {
  const config: Record<string, { bg: string; label: string }> = {
    critical: { bg: 'bg-red-500/20 text-red-400 border-red-500/50', label: 'CRITICAL' },
    high: { bg: 'bg-orange-500/20 text-orange-400 border-orange-500/50', label: 'HIGH' },
    medium: { bg: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/50', label: 'MEDIUM' },
    low: { bg: 'bg-green-500/20 text-green-400 border-green-500/50', label: 'LOW' },
  };
  const style = config[severity?.toLowerCase()] || config.low;
  return (
    <span className={`px-3 py-1 rounded-lg text-sm font-semibold border ${style.bg}`}>
      {style.label}
    </span>
  );
}

function VulnerabilityCard({ vuln, onSelect }: { vuln: Vulnerability; onSelect: () => void }) {
  const explanation = getVulnExplanation(vuln.vuln_type);
  const isFixed = vuln.status === 'fixed';

  return (
    <div 
      onClick={onSelect}
      className={`bg-gradient-to-br from-[#111827] to-[#0d1525] rounded-xl border cursor-pointer transition-all hover:scale-[1.01] ${
        isFixed ? 'border-green-500/30' : 
        vuln.severity?.toLowerCase() === 'critical' ? 'border-red-500/30' :
        vuln.severity?.toLowerCase() === 'high' ? 'border-orange-500/30' : 'border-gray-700'
      }`}
    >
      <div className="p-5">
        {/* Header */}
        <div className="flex items-start justify-between mb-4">
          <div className="flex items-center gap-3">
            <div>
              <h3 className="text-white font-semibold text-lg">{vuln.vuln_type}</h3>
              <p className="text-gray-500 text-sm">{vuln.target}:{vuln.port}</p>
            </div>
          </div>
          <div className="flex flex-col items-end gap-2">
            <SeverityBadge severity={vuln.severity} />
            {isFixed ? (
              <span className="text-green-400 text-sm flex items-center gap-1">
                <CheckCircle className="w-4 h-4" /> Fixed
              </span>
            ) : (
              <span className="text-red-400 text-sm flex items-center gap-1">
                <AlertTriangle className="w-4 h-4" /> Open
              </span>
            )}
          </div>
        </div>

        {/* Simple Explanation */}
        <div className="bg-[#0a0f1a] rounded-lg p-4 mb-4">
          <h4 className="text-blue-400 font-medium mb-2 flex items-center gap-2">
            <Info className="w-4 h-4" /> What This Means (Simple Explanation)
          </h4>
          <p className="text-gray-300 text-sm">{explanation.whatItIs}</p>
        </div>

        {/* Why It Matters */}
        <div className="bg-red-500/5 border border-red-500/20 rounded-lg p-4 mb-4">
          <h4 className="text-red-400 font-medium mb-2 flex items-center gap-2">
            <AlertTriangle className="w-4 h-4" /> Why You Should Care
          </h4>
          <p className="text-gray-300 text-sm">{explanation.whyItMatters}</p>
        </div>

        {/* Real World Example */}
        <div className="bg-purple-500/5 border border-purple-500/20 rounded-lg p-4 mb-4">
          <h4 className="text-purple-400 font-medium mb-2 flex items-center gap-2">
            <HelpCircle className="w-4 h-4" /> Think of it Like...
          </h4>
          <p className="text-gray-300 text-sm italic">"{explanation.realWorldExample}"</p>
        </div>

        {/* Fix Info */}
        <div className="flex items-center justify-between pt-3 border-t border-gray-800">
          <div className="text-gray-500 text-sm">
            Found: {new Date(vuln.discovered_at).toLocaleDateString()}
          </div>
          <button className="text-blue-400 text-sm flex items-center gap-1 hover:text-blue-300">
            View Details <ChevronRight className="w-4 h-4" />
          </button>
        </div>
      </div>
    </div>
  );
}

function VulnerabilityDetailModal({ vuln, onClose }: { vuln: Vulnerability; onClose: () => void }) {
  const navigate = useNavigate();
  const explanation = getVulnExplanation(vuln.vuln_type);
  const isFixed = vuln.status === 'fixed';

  return (
    <div className="fixed inset-0 bg-black/80 flex items-center justify-center z-50 p-4" onClick={onClose}>
      <div 
        className="bg-[#0d1525] rounded-2xl max-w-3xl w-full max-h-[90vh] overflow-y-auto border border-gray-700"
        onClick={e => e.stopPropagation()}
      >
        {/* Header */}
        <div className="p-6 border-b border-gray-800">
          <div className="flex items-start justify-between">
            <div className="flex items-center gap-4">
              <div>
                <h2 className="text-2xl font-bold text-white">{vuln.vuln_type}</h2>
                <p className="text-gray-400">{vuln.target}:{vuln.port} • {vuln.service}</p>
              </div>
            </div>
            <button onClick={onClose} className="text-gray-400 hover:text-white text-2xl">&times;</button>
          </div>
        </div>

        {/* Content */}
        <div className="p-6 space-y-6">
          {/* Status & Severity */}
          <div className="flex items-center gap-4">
            <SeverityBadge severity={vuln.severity} />
            {isFixed ? (
              <span className="px-3 py-1 rounded-lg bg-green-500/20 text-green-400 border border-green-500/30 flex items-center gap-2">
                <CheckCircle className="w-4 h-4" /> Issue Has Been Fixed
              </span>
            ) : (
              <span className="px-3 py-1 rounded-lg bg-red-500/20 text-red-400 border border-red-500/30 flex items-center gap-2">
                <AlertTriangle className="w-4 h-4" /> Needs Immediate Attention
              </span>
            )}
          </div>

          {/* Sections */}
          <div className="space-y-4">
            <div className="bg-blue-500/10 border border-blue-500/30 rounded-xl p-5">
              <h3 className="text-blue-400 font-semibold mb-3 flex items-center gap-2 text-lg">
                <Info className="w-5 h-5" /> What Is This Problem?
              </h3>
              <p className="text-gray-200">{explanation.whatItIs}</p>
            </div>

            <div className="bg-red-500/10 border border-red-500/30 rounded-xl p-5">
              <h3 className="text-red-400 font-semibold mb-3 flex items-center gap-2 text-lg">
                <AlertTriangle className="w-5 h-5" /> What Could Happen If Not Fixed?
              </h3>
              <p className="text-gray-200">{explanation.whyItMatters}</p>
            </div>

            <div className="bg-purple-500/10 border border-purple-500/30 rounded-xl p-5">
              <h3 className="text-purple-400 font-semibold mb-3 flex items-center gap-2 text-lg">
                <HelpCircle className="w-5 h-5" /> Simple Analogy
              </h3>
              <p className="text-gray-200 italic text-lg">"{explanation.realWorldExample}"</p>
            </div>

            <div className="bg-green-500/10 border border-green-500/30 rounded-xl p-5">
              <h3 className="text-green-400 font-semibold mb-3 flex items-center gap-2 text-lg">
                <Wrench className="w-5 h-5" /> How We Fix This
              </h3>
              <p className="text-gray-200">{explanation.howToFix}</p>
            </div>
          </div>

          {/* Technical Details */}
          {vuln.description && (
            <div className="bg-[#0a0f1a] rounded-xl p-5">
              <h3 className="text-gray-400 font-semibold mb-3 flex items-center gap-2">
                <Code className="w-5 h-5" /> Technical Details
              </h3>
              <p className="text-gray-300 font-mono text-sm">{vuln.description}</p>
              {vuln.cve_id && (
                <div className="mt-3">
                  <span className="text-orange-400 font-mono text-sm">{vuln.cve_id}</span>
                </div>
              )}
            </div>
          )}

          {/* Actions */}
          <div className="flex gap-3 pt-4">
            {!isFixed && (
              <button
                onClick={() => { onClose(); navigate('/fix'); }}
                className="flex-1 px-6 py-3 bg-green-600 hover:bg-green-500 text-white rounded-xl font-semibold flex items-center justify-center gap-2"
              >
                <Wrench className="w-5 h-5" /> Fix This Issue Now
              </button>
            )}
            <button
              onClick={() => { onClose(); navigate('/report-generator'); }}
              className="flex-1 px-6 py-3 bg-blue-600 hover:bg-blue-500 text-white rounded-xl font-semibold flex items-center justify-center gap-2"
            >
              <FileText className="w-5 h-5" /> Generate Report
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

export default function Vulnerabilities() {
  const navigate = useNavigate();
  const [vulnerabilities, setVulnerabilities] = useState<Vulnerability[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  const [filterSeverity, setFilterSeverity] = useState<string>('all');
  const [filterStatus, setFilterStatus] = useState<string>('all');
  const [selectedVuln, setSelectedVuln] = useState<Vulnerability | null>(null);

  useEffect(() => {
    loadVulnerabilities();
  }, []);

  const loadVulnerabilities = async () => {
    try {
      const response = await api.get('/vulnerabilities');
      setVulnerabilities(response.data.vulnerabilities || response.data || []);
    } catch (err) {
      console.error('Failed to load vulnerabilities:', err);
    } finally {
      setLoading(false);
    }
  };

  const filteredVulns = vulnerabilities.filter(v => {
    const matchesSearch = v.vuln_type.toLowerCase().includes(searchQuery.toLowerCase()) ||
                          v.target.toLowerCase().includes(searchQuery.toLowerCase());
    const matchesSeverity = filterSeverity === 'all' || v.severity?.toLowerCase() === filterSeverity;
    const matchesStatus = filterStatus === 'all' || v.status === filterStatus;
    return matchesSearch && matchesSeverity && matchesStatus;
  });

  const stats = {
    total: vulnerabilities.length,
    critical: vulnerabilities.filter(v => v.severity?.toLowerCase() === 'critical').length,
    high: vulnerabilities.filter(v => v.severity?.toLowerCase() === 'high').length,
    medium: vulnerabilities.filter(v => v.severity?.toLowerCase() === 'medium').length,
    low: vulnerabilities.filter(v => v.severity?.toLowerCase() === 'low').length,
    fixed: vulnerabilities.filter(v => v.status === 'fixed').length,
    open: vulnerabilities.filter(v => v.status !== 'fixed').length,
  };

  if (loading) {
    return (
      <div className="p-8 flex items-center justify-center min-h-screen">
        <div className="text-center">
          <Bug className="w-12 h-12 text-red-400 mx-auto mb-4 animate-pulse" />
          <p className="text-gray-400">Loading security issues...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="p-6 lg:p-8 min-h-screen bg-gradient-to-br from-[#0a0f1a] via-[#0d1525] to-[#0a1628]">
      {/* Header */}
      <div className="mb-8">
        <h1 className="text-2xl lg:text-3xl font-bold text-white mb-2 flex items-center gap-3">
          <Bug className="w-8 h-8 text-red-400" />
          Security Issues Found
        </h1>
        <p className="text-gray-400">
          Below are all the security problems we discovered. Click any issue to learn more about it.
        </p>
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-4 mb-8">
        <div className="bg-[#111827] rounded-xl p-4 border border-gray-800">
          <p className="text-gray-400 text-sm">Total Issues</p>
          <p className="text-2xl font-bold text-white">{stats.total}</p>
        </div>
        <div className="bg-red-500/10 rounded-xl p-4 border border-red-500/30">
          <p className="text-red-400 text-sm">Critical</p>
          <p className="text-2xl font-bold text-red-400">{stats.critical}</p>
        </div>
        <div className="bg-orange-500/10 rounded-xl p-4 border border-orange-500/30">
          <p className="text-orange-400 text-sm">High</p>
          <p className="text-2xl font-bold text-orange-400">{stats.high}</p>
        </div>
        <div className="bg-yellow-500/10 rounded-xl p-4 border border-yellow-500/30">
          <p className="text-yellow-400 text-sm">Medium</p>
          <p className="text-2xl font-bold text-yellow-400">{stats.medium}</p>
        </div>
        <div className="bg-green-500/10 rounded-xl p-4 border border-green-500/30">
          <p className="text-green-400 text-sm">Fixed</p>
          <p className="text-2xl font-bold text-green-400">{stats.fixed}</p>
        </div>
        <div className="bg-gray-700/30 rounded-xl p-4 border border-gray-600">
          <p className="text-gray-400 text-sm">Open</p>
          <p className="text-2xl font-bold text-gray-300">{stats.open}</p>
        </div>
      </div>

      {/* Filters */}
      <div className="flex flex-wrap gap-4 mb-8">
        <div className="relative flex-1 min-w-[200px]">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-500" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search issues..."
            className="w-full pl-10 pr-4 py-3 bg-[#111827] border border-gray-700 rounded-xl text-white placeholder-gray-500 focus:outline-none focus:border-blue-500"
          />
        </div>
        <select
          value={filterSeverity}
          onChange={(e) => setFilterSeverity(e.target.value)}
          className="px-4 py-3 bg-[#111827] border border-gray-700 rounded-xl text-white focus:outline-none focus:border-blue-500"
        >
          <option value="all">All Severities</option>
          <option value="critical">Critical Only</option>
          <option value="high">High Only</option>
          <option value="medium">Medium Only</option>
          <option value="low">Low Only</option>
        </select>
        <select
          value={filterStatus}
          onChange={(e) => setFilterStatus(e.target.value)}
          className="px-4 py-3 bg-[#111827] border border-gray-700 rounded-xl text-white focus:outline-none focus:border-blue-500"
        >
          <option value="all">All Status</option>
          <option value="open">Open Only</option>
          <option value="fixed">Fixed Only</option>
        </select>
        {stats.open > 0 && (
          <button
            onClick={() => navigate('/fix')}
            className="px-6 py-3 bg-green-600 hover:bg-green-500 text-white rounded-xl font-semibold flex items-center gap-2"
          >
            <Wrench className="w-5 h-5" /> Fix All Issues
          </button>
        )}
      </div>

      {/* Vulnerability List */}
      {filteredVulns.length === 0 ? (
        <div className="text-center py-16">
          <Shield className="w-20 h-20 text-green-500/30 mx-auto mb-4" />
          <h2 className="text-2xl font-bold text-green-400 mb-2">All Clear!</h2>
          <p className="text-gray-400 mb-6">
            {vulnerabilities.length === 0 
              ? "No security issues found. Run a scan to check your systems."
              : "No issues match your current filters."}
          </p>
          {vulnerabilities.length === 0 && (
            <button
              onClick={() => navigate('/new-scan')}
              className="px-6 py-3 bg-blue-600 hover:bg-blue-500 text-white rounded-xl font-semibold"
            >
              Start a Security Scan
            </button>
          )}
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {filteredVulns.map((vuln) => (
            <VulnerabilityCard 
              key={vuln.id} 
              vuln={vuln} 
              onSelect={() => setSelectedVuln(vuln)} 
            />
          ))}
        </div>
      )}

      {/* Detail Modal */}
      {selectedVuln && (
        <VulnerabilityDetailModal 
          vuln={selectedVuln} 
          onClose={() => setSelectedVuln(null)} 
        />
      )}
    </div>
  );
}
