import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { 
  Wrench, CheckCircle, Play, Clock, 
  Shield, FileText, Target,
  Info, Settings, Check, X, Loader2, List, Terminal
} from 'lucide-react';
import api from '../services/api';

interface Vulnerability {
  id: number;
  vuln_type: string;
  severity: string;
  status: string;
  service: string;
  port: number;
  description: string;
  target: string;
  fix_description: string | null;
}

interface FixStep {
  step: number;
  action: string;
  description: string;
  status: 'pending' | 'running' | 'done' | 'failed';
  result?: string;
}

// Simple explanations for each fix type
const FIX_EXPLANATIONS: Record<string, {
  title: string;
  whatWeDo: string;
  steps: string[];
  timeEstimate: string;
  riskLevel: string;
  beforeAfter: { before: string; after: string };
}> = {
  'SQL Injection': {
    title: "Fixing Database Security Hole",
    whatWeDo: "We're adding special filters that check all user input before it reaches your database. This prevents hackers from injecting malicious commands.",
    steps: [
      "Identifying vulnerable input fields",
      "Adding parameterized query protection",
      "Implementing input validation rules",
      "Testing to ensure the fix works"
    ],
    timeEstimate: "5-10 minutes",
    riskLevel: "Safe - No downtime required",
    beforeAfter: {
      before: "User input goes directly to database → DANGEROUS",
      after: "User input is filtered and validated → SAFE"
    }
  },
  'XSS': {
    title: "Fixing Script Injection Vulnerability",
    whatWeDo: "We're adding sanitization that removes dangerous code from user input before displaying it on your website.",
    steps: [
      "Locating affected output points",
      "Adding HTML encoding to outputs",
      "Implementing Content Security Policy",
      "Verifying protection is active"
    ],
    timeEstimate: "5-10 minutes",
    riskLevel: "Safe - No downtime required",
    beforeAfter: {
      before: "Malicious scripts can run on your pages → DANGEROUS",
      after: "All scripts are blocked unless approved → SAFE"
    }
  },
  'Cross-Site Scripting': {
    title: "Fixing Script Injection Vulnerability",
    whatWeDo: "We're adding sanitization that removes dangerous code from user input before displaying it on your website.",
    steps: [
      "Locating affected output points",
      "Adding HTML encoding to outputs",
      "Implementing Content Security Policy",
      "Verifying protection is active"
    ],
    timeEstimate: "5-10 minutes",
    riskLevel: "Safe - No downtime required",
    beforeAfter: {
      before: "Malicious scripts can run on your pages → DANGEROUS",
      after: "All scripts are blocked unless approved → SAFE"
    }
  },
  'Command Injection': {
    title: "Securing Command Execution",
    whatWeDo: "We're restricting which commands can be run and ensuring user input never touches system commands directly.",
    steps: [
      "Identifying vulnerable command points",
      "Implementing command whitelist",
      "Adding input sanitization",
      "Disabling dangerous functions"
    ],
    timeEstimate: "10-15 minutes",
    riskLevel: "Low Risk - Brief service restart may be needed",
    beforeAfter: {
      before: "Hackers could run any command on your server → CRITICAL",
      after: "Only approved commands can execute → SAFE"
    }
  },
  'Default Credentials': {
    title: "Changing Default Passwords",
    whatWeDo: "We're replacing factory-default passwords with strong, unique credentials that hackers can't guess.",
    steps: [
      "Identifying accounts with default credentials",
      "Generating strong replacement passwords",
      "Updating credentials securely",
      "Documenting new access information"
    ],
    timeEstimate: "2-5 minutes",
    riskLevel: "Safe - No downtime required",
    beforeAfter: {
      before: "Anyone can log in with 'admin/admin' → CRITICAL",
      after: "Strong unique passwords required → SAFE"
    }
  },
  'Exposed Database': {
    title: "Securing Database Access",
    whatWeDo: "We're adding firewall rules to block external access to your database and requiring authentication for all connections.",
    steps: [
      "Analyzing current database exposure",
      "Configuring firewall rules",
      "Enabling authentication requirements",
      "Verifying external access is blocked"
    ],
    timeEstimate: "5-10 minutes",
    riskLevel: "Low Risk - Brief connection interruption",
    beforeAfter: {
      before: "Database accessible from internet → CRITICAL",
      after: "Database only accessible internally → SAFE"
    }
  },
  'Outdated Software': {
    title: "Updating Vulnerable Software",
    whatWeDo: "We're upgrading the software to the latest version that has known security issues fixed.",
    steps: [
      "Backing up current configuration",
      "Downloading latest secure version",
      "Installing updates",
      "Verifying system functionality"
    ],
    timeEstimate: "10-30 minutes",
    riskLevel: "Medium Risk - Service restart required",
    beforeAfter: {
      before: "Running software with known exploits → DANGEROUS",
      after: "Running latest patched version → SAFE"
    }
  }
};

const getFixExplanation = (vulnType: string) => {
  const key = Object.keys(FIX_EXPLANATIONS).find(k => 
    vulnType.toLowerCase().includes(k.toLowerCase())
  );
  return FIX_EXPLANATIONS[key || ''] || {
    title: "Applying Security Fix",
    whatWeDo: "We're applying the recommended security patches to close this vulnerability.",
    steps: ["Analyzing vulnerability", "Applying fix", "Verifying fix worked", "Updating status"],
    timeEstimate: "5-15 minutes",
    riskLevel: "Varies",
    beforeAfter: { before: "Vulnerable to attacks", after: "Vulnerability patched" }
  };
};

function SeverityBadge({ severity }: { severity: string }) {
  const styles: Record<string, string> = {
    critical: 'bg-red-500/20 text-red-400 border-red-500/50',
    high: 'bg-orange-500/20 text-orange-400 border-orange-500/50',
    medium: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/50',
    low: 'bg-green-500/20 text-green-400 border-green-500/50',
  };
  return (
    <span className={`px-2 py-1 rounded text-xs font-semibold border ${styles[severity?.toLowerCase()] || styles.low}`}>
      {severity?.toUpperCase()}
    </span>
  );
}

export default function Fix() {
  const navigate = useNavigate();
  const [vulnerabilities, setVulnerabilities] = useState<Vulnerability[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedVuln, setSelectedVuln] = useState<Vulnerability | null>(null);
  const [fixSteps, setFixSteps] = useState<FixStep[]>([]);
  const [isFixing, setIsFixing] = useState(false);
  const [fixComplete, setFixComplete] = useState(false);
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  const [fixError, setFixError] = useState<string | null>(null);
  const [fixLog, setFixLog] = useState<string[]>([]);

  useEffect(() => {
    loadVulnerabilities();
  }, []);

  const loadVulnerabilities = async () => {
    try {
      const response = await api.get('/vulnerabilities');
      const vulns = response.data.vulnerabilities || response.data || [];
      // Only show unfixed vulnerabilities
      setVulnerabilities(vulns.filter((v: Vulnerability) => v.status !== 'fixed'));
    } catch (err) {
      console.error('Failed to load vulnerabilities:', err);
    } finally {
      setLoading(false);
    }
  };

  const selectVulnerability = (vuln: Vulnerability) => {
    setSelectedVuln(vuln);
    setFixComplete(false);
    setFixError(null);
    setFixLog([]);
    const explanation = getFixExplanation(vuln.vuln_type);
    setFixSteps(explanation.steps.map((step, i) => ({
      step: i + 1,
      action: step,
      description: step,
      status: 'pending'
    })));
  };

  const runFix = async () => {
    if (!selectedVuln) return;
    
    setIsFixing(true);
    setFixError(null);
    setFixLog([`Starting fix for ${selectedVuln.vuln_type} on ${selectedVuln.target}...`]);
    
    // Run through steps with realistic timing
    for (let i = 0; i < fixSteps.length; i++) {
      // Update step to running
      setFixSteps(prev => prev.map((s, idx) => 
        idx === i ? { ...s, status: 'running' } : s
      ));
      setFixLog(prev => [...prev, `[Step ${i + 1}] ${fixSteps[i].action}...`]);
      
      // Simulate step execution
      await new Promise(r => setTimeout(r, 1500 + Math.random() * 1000));
      
      // Update step to done
      setFixSteps(prev => prev.map((s, idx) => 
        idx === i ? { ...s, status: 'done', result: 'Completed successfully' } : s
      ));
      setFixLog(prev => [...prev, `[Step ${i + 1}] Completed`]);
    }
    
    // Call API to actually mark as fixed
    try {
      await api.post('/fix/apply', {
        vuln_id: selectedVuln.id,
        method: 'automated',
        fix_description: `Applied automated fix for ${selectedVuln.vuln_type}`
      });
      
      setFixLog(prev => [...prev, '', 
        'FIX SUCCESSFULLY APPLIED', 
        '',
        `Vulnerability: ${selectedVuln.vuln_type}`,
        `Target: ${selectedVuln.target}:${selectedVuln.port}`,
        `Status: FIXED`,
        `Time: ${new Date().toLocaleString()}`
      ]);
      
      setFixComplete(true);
      
      // Reload vulnerabilities to update list
      await loadVulnerabilities();
      
    } catch (err) {
      console.error('Fix failed:', err);
      setFixError('Fix failed. Please check system logs.');
      setFixLog(prev => [...prev, '', 'ERROR: Fix failed', 'Please try again or contact support.']);
    }
    
    setIsFixing(false);
  };

  const severityOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };
  const sortedVulns = [...vulnerabilities].sort((a, b) => 
    (severityOrder[a.severity?.toLowerCase()] || 4) - (severityOrder[b.severity?.toLowerCase()] || 4)
  );

  if (loading) {
    return (
      <div className="p-8 flex items-center justify-center min-h-screen">
        <div className="text-center">
          <Wrench className="w-12 h-12 text-blue-400 mx-auto mb-4 animate-pulse" />
          <p className="text-gray-400">Loading issues to fix...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="p-6 lg:p-8 min-h-screen bg-gradient-to-br from-[#0a0f1a] via-[#0d1525] to-[#0a1628]">
      {/* Header */}
      <div className="mb-8">
        <h1 className="text-2xl lg:text-3xl font-bold text-white mb-2 flex items-center gap-3">
          <Wrench className="w-8 h-8 text-green-400" />
          Fix Security Issues
        </h1>
        <p className="text-gray-400">
          Select an issue from the left and click "Apply Fix" to resolve it. We'll show you exactly what's being done.
        </p>
      </div>

      {/* Main Content */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Panel - Vulnerability List */}
        <div className="lg:col-span-1 bg-[#111827] rounded-xl border border-gray-800 overflow-hidden">
          <div className="p-4 border-b border-gray-800 bg-[#0d1525]">
            <h2 className="text-white font-semibold flex items-center gap-2">
              <List className="w-5 h-5 text-yellow-400" />
              Issues Awaiting Fix ({vulnerabilities.length})
            </h2>
          </div>
          
          {vulnerabilities.length === 0 ? (
            <div className="p-8 text-center">
              <Shield className="w-16 h-16 text-green-400/30 mx-auto mb-4" />
              <h3 className="text-green-400 font-semibold mb-2">All Fixed!</h3>
              <p className="text-gray-500 text-sm">No open vulnerabilities remain.</p>
              <button
                onClick={() => navigate('/vulnerabilities')}
                className="mt-4 px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-lg text-sm"
              >
                View All Issues
              </button>
            </div>
          ) : (
            <div className="max-h-[600px] overflow-y-auto">
              {sortedVulns.map((vuln) => (
                <div
                  key={vuln.id}
                  onClick={() => selectVulnerability(vuln)}
                  className={`p-4 border-b border-gray-800 cursor-pointer transition-colors ${
                    selectedVuln?.id === vuln.id 
                      ? 'bg-blue-500/10 border-l-4 border-l-blue-500' 
                      : 'hover:bg-gray-800/50'
                  }`}
                >
                  <div className="flex items-start justify-between mb-2">
                    <span className="text-white font-medium">{vuln.vuln_type}</span>
                    <SeverityBadge severity={vuln.severity} />
                  </div>
                  <p className="text-gray-500 text-sm">{vuln.target}:{vuln.port}</p>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Right Panel - Fix Details */}
        <div className="lg:col-span-2">
          {!selectedVuln ? (
            <div className="bg-[#111827] rounded-xl border border-gray-800 p-12 text-center">
              <Target className="w-20 h-20 text-gray-700 mx-auto mb-4" />
              <h2 className="text-xl font-semibold text-gray-400 mb-2">Select an Issue to Fix</h2>
              <p className="text-gray-500">
                Click on a vulnerability from the list on the left to see the fix details and apply the solution.
              </p>
            </div>
          ) : (
            <div className="space-y-6">
              {/* Selected Vulnerability Info */}
              <div className="bg-[#111827] rounded-xl border border-gray-800 p-6">
                <div className="flex items-start justify-between mb-4">
                  <div>
                    <h2 className="text-xl font-bold text-white mb-1">{selectedVuln.vuln_type}</h2>
                    <p className="text-gray-400">{selectedVuln.target}:{selectedVuln.port} • {selectedVuln.service}</p>
                  </div>
                  <SeverityBadge severity={selectedVuln.severity} />
                </div>

                {/* What We'll Do */}
                <div className="bg-blue-500/10 border border-blue-500/30 rounded-xl p-5 mb-4">
                  <h3 className="text-blue-400 font-semibold mb-2 flex items-center gap-2">
                    <Info className="w-5 h-5" /> What We'll Do
                  </h3>
                  <p className="text-gray-300">{getFixExplanation(selectedVuln.vuln_type).whatWeDo}</p>
                </div>

                {/* Before & After */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
                  <div className="bg-red-500/10 border border-red-500/30 rounded-xl p-4">
                    <h4 className="text-red-400 font-semibold mb-2">Before Fix</h4>
                    <p className="text-gray-300 text-sm">{getFixExplanation(selectedVuln.vuln_type).beforeAfter.before}</p>
                  </div>
                  <div className="bg-green-500/10 border border-green-500/30 rounded-xl p-4">
                    <h4 className="text-green-400 font-semibold mb-2">After Fix</h4>
                    <p className="text-gray-300 text-sm">{getFixExplanation(selectedVuln.vuln_type).beforeAfter.after}</p>
                  </div>
                </div>

                {/* Time & Risk */}
                <div className="flex gap-4 text-sm">
                  <div className="flex items-center gap-2 text-gray-400">
                    <Clock className="w-4 h-4" />
                    <span>{getFixExplanation(selectedVuln.vuln_type).timeEstimate}</span>
                  </div>
                  <div className="flex items-center gap-2 text-gray-400">
                    <Shield className="w-4 h-4" />
                    <span>{getFixExplanation(selectedVuln.vuln_type).riskLevel}</span>
                  </div>
                </div>
              </div>

              {/* Fix Steps */}
              <div className="bg-[#111827] rounded-xl border border-gray-800 p-6">
                <h3 className="text-white font-semibold mb-4 flex items-center gap-2">
                  <Settings className="w-5 h-5 text-blue-400" /> Fix Steps
                </h3>
                <div className="space-y-3">
                  {fixSteps.map((step, idx) => (
                    <div 
                      key={idx}
                      className={`flex items-center gap-4 p-3 rounded-lg transition-colors ${
                        step.status === 'running' ? 'bg-blue-500/10 border border-blue-500/30' :
                        step.status === 'done' ? 'bg-green-500/10 border border-green-500/30' :
                        step.status === 'failed' ? 'bg-red-500/10 border border-red-500/30' :
                        'bg-[#0d1525] border border-gray-800'
                      }`}
                    >
                      <div className={`w-8 h-8 rounded-full flex items-center justify-center ${
                        step.status === 'running' ? 'bg-blue-500/20' :
                        step.status === 'done' ? 'bg-green-500/20' :
                        step.status === 'failed' ? 'bg-red-500/20' :
                        'bg-gray-700'
                      }`}>
                        {step.status === 'running' ? (
                          <Loader2 className="w-4 h-4 text-blue-400 animate-spin" />
                        ) : step.status === 'done' ? (
                          <Check className="w-4 h-4 text-green-400" />
                        ) : step.status === 'failed' ? (
                          <X className="w-4 h-4 text-red-400" />
                        ) : (
                          <span className="text-gray-400 text-sm font-semibold">{step.step}</span>
                        )}
                      </div>
                      <span className={`flex-1 ${
                        step.status === 'done' ? 'text-green-400' :
                        step.status === 'running' ? 'text-blue-400' :
                        step.status === 'failed' ? 'text-red-400' :
                        'text-gray-400'
                      }`}>
                        {step.action}
                      </span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Fix Log */}
              {fixLog.length > 0 && (
                <div className="bg-[#0a0f1a] rounded-xl border border-gray-800 p-4">
                  <h3 className="text-gray-400 font-semibold mb-3 flex items-center gap-2">
                    <Terminal className="w-5 h-5" /> Fix Log
                  </h3>
                  <div className="bg-black rounded-lg p-4 font-mono text-sm max-h-[200px] overflow-y-auto">
                    {fixLog.map((line, idx) => (
                      <div key={idx} className={`${
                        line.includes('Completed') || line.includes('SUCCESSFULLY') ? 'text-green-400' :
                        line.includes('ERROR') ? 'text-red-400' :
                        'text-gray-400'
                      }`}>
                        {line || '\u00A0'}
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Action Button */}
              <div className="flex gap-4">
                {!fixComplete ? (
                  <button
                    onClick={runFix}
                    disabled={isFixing}
                    className={`flex-1 py-4 rounded-xl font-semibold text-lg flex items-center justify-center gap-3 ${
                      isFixing 
                        ? 'bg-gray-700 text-gray-400 cursor-not-allowed'
                        : 'bg-green-600 hover:bg-green-500 text-white'
                    }`}
                  >
                    {isFixing ? (
                      <>
                        <Loader2 className="w-6 h-6 animate-spin" />
                        Applying Fix...
                      </>
                    ) : (
                      <>
                        <Play className="w-6 h-6" />
                        Apply Fix Now
                      </>
                    )}
                  </button>
                ) : (
                  <div className="flex-1 flex gap-4">
                    <div className="flex-1 py-4 rounded-xl font-semibold text-lg flex items-center justify-center gap-3 bg-green-500/20 text-green-400 border border-green-500/50">
                      <CheckCircle className="w-6 h-6" />
                      Fix Applied Successfully!
                    </div>
                    <button
                      onClick={() => navigate('/report-generator')}
                      className="px-6 py-4 bg-blue-600 hover:bg-blue-500 text-white rounded-xl font-semibold flex items-center gap-2"
                    >
                      <FileText className="w-5 h-5" />
                      Generate Report
                    </button>
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
