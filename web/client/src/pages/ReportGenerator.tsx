import { useState, useEffect } from 'react';
import { 
  FileText, Download, 
  CheckCircle, Activity,
  Eye, FileCheck, Building
} from 'lucide-react';
import api from '../services/api';

interface Vulnerability {
  id: number;
  vuln_type: string;
  severity: string;
  status: string;
  service: string;
  port: number;
  target: string;
  discovered_at: string;
  fixed_at: string | null;
  fix_description: string | null;
}

interface Scan {
  id: string;
  target: string;
  status: string;
  scan_type: string;
  created_at: string;
}

interface ActivityLog {
  id: number;
  action: string;
  details: string;
  created_at: string;
}

// Non-technical severity explanations
const SEVERITY_EXPLAIN: Record<string, { meaning: string; action: string; color: string }> = {
  critical: {
    meaning: "Extremely dangerous - hackers could take complete control",
    action: "Must be fixed immediately",
    color: "red"
  },
  high: {
    meaning: "Very dangerous - significant damage possible",
    action: "Should be fixed within 24-48 hours",
    color: "orange"
  },
  medium: {
    meaning: "Moderately dangerous - could cause problems",
    action: "Should be fixed within a week",
    color: "yellow"
  },
  low: {
    meaning: "Minor issue - limited risk",
    action: "Fix when convenient",
    color: "green"
  }
};

export default function ReportGenerator() {
  const [vulnerabilities, setVulnerabilities] = useState<Vulnerability[]>([]);
  const [scans, setScans] = useState<Scan[]>([]);
  const [activities, setActivities] = useState<ActivityLog[]>([]);
  const [loading, setLoading] = useState(true);
  const [reportType, setReportType] = useState<'executive' | 'technical' | 'changes'>('executive');

  useEffect(() => {
    loadData();
  }, []);

  const loadData = async () => {
    try {
      const [vulnRes, scanRes, actRes] = await Promise.all([
        api.get('/vulnerabilities'),
        api.get('/scans'),
        api.get('/activity')
      ]);
      setVulnerabilities(vulnRes.data.vulnerabilities || vulnRes.data || []);
      setScans(scanRes.data.scans || scanRes.data || []);
      setActivities(actRes.data.activities || actRes.data || []);
    } catch (err) {
      console.error('Failed to load data:', err);
    } finally {
      setLoading(false);
    }
  };

  // Calculate stats
  const stats = {
    total: vulnerabilities.length,
    fixed: vulnerabilities.filter(v => v.status === 'fixed').length,
    open: vulnerabilities.filter(v => v.status !== 'fixed').length,
    critical: vulnerabilities.filter(v => v.severity?.toLowerCase() === 'critical').length,
    high: vulnerabilities.filter(v => v.severity?.toLowerCase() === 'high').length,
    medium: vulnerabilities.filter(v => v.severity?.toLowerCase() === 'medium').length,
    low: vulnerabilities.filter(v => v.severity?.toLowerCase() === 'low').length,
    fixedCritical: vulnerabilities.filter(v => v.severity?.toLowerCase() === 'critical' && v.status === 'fixed').length,
    fixedHigh: vulnerabilities.filter(v => v.severity?.toLowerCase() === 'high' && v.status === 'fixed').length,
  };

  const securityScore = stats.total > 0 
    ? Math.round(((stats.total - (stats.critical * 4 + stats.high * 2 + stats.medium - stats.fixed * 3)) / stats.total) * 100)
    : 100;
  const normalizedScore = Math.max(0, Math.min(100, securityScore));

  const generateReport = () => {
    const now = new Date().toLocaleString();
    let content = '';

    if (reportType === 'executive') {
      content = `
SECURITY ASSESSMENT REPORT
Executive Summary (Non-Technical)

Generated: ${now}
Report Type: Executive Summary for Management
Prepared by: RedShield Security Scanner


WHAT THIS REPORT TELLS YOU

This report shows you the security health of your systems in simple terms:
- What security problems were found
- How dangerous each problem is  
- Which problems have been fixed
- What still needs attention


OVERALL SECURITY STATUS

YOUR SECURITY SCORE: ${normalizedScore}/100

What this means:
${normalizedScore >= 80 ? 'GOOD - Your systems are reasonably secure. Keep up the good work!' :
  normalizedScore >= 60 ? 'FAIR - Some issues need attention. Not urgent, but important.' :
  normalizedScore >= 40 ? 'AT RISK - Several problems found. Should be addressed soon.' :
  'CRITICAL - Serious security issues. Immediate action required!'}


THE NUMBERS AT A GLANCE

Total Issues Found:        ${stats.total}
Issues Fixed:              ${stats.fixed}
Issues Remaining:          ${stats.open}

BREAKDOWN BY DANGER LEVEL:

Critical (Most Dangerous):    ${stats.critical} found, ${stats.fixedCritical} fixed
   ${SEVERITY_EXPLAIN.critical.meaning}
   
High (Very Dangerous):        ${stats.high} found, ${stats.fixedHigh} fixed
   ${SEVERITY_EXPLAIN.high.meaning}
   
Medium (Moderate Risk):       ${stats.medium} found
   ${SEVERITY_EXPLAIN.medium.meaning}
   
Low (Minor Risk):             ${stats.low} found
   ${SEVERITY_EXPLAIN.low.meaning}


WHAT WAS FOUND

${vulnerabilities.length === 0 ? 'No security issues were found. Your systems appear secure.' :
vulnerabilities.map(v => `
* ${v.vuln_type}
   Location: ${v.target}:${v.port} (${v.service || 'service'})
   Danger Level: ${v.severity?.toUpperCase()}
   Status: ${v.status === 'fixed' ? 'FIXED' : 'NEEDS ATTENTION'}
   ${v.status === 'fixed' && v.fix_description ? `What we did: ${v.fix_description}` : ''}
`).join('')}


WHAT SHOULD YOU DO NOW?

${stats.open === 0 ? `
GREAT NEWS! All identified issues have been fixed.

Recommendations:
1. Schedule regular security scans (monthly recommended)
2. Keep all software updated
3. Train staff on security best practices
4. Consider a professional penetration test annually
` : `
There are ${stats.open} issues that still need attention.

Priority Actions:
${stats.critical - stats.fixedCritical > 0 ? `1. FIX CRITICAL ISSUES IMMEDIATELY - You have ${stats.critical - stats.fixedCritical} critical vulnerabilities` : ''}
${stats.high - stats.fixedHigh > 0 ? `2. Address high-severity issues within 48 hours - You have ${stats.high - stats.fixedHigh} high vulnerabilities` : ''}
3. Use the "Fix" page in RedShield to resolve these issues
4. Generate a new report after fixes are applied
`}


END OF REPORT
`;
    } else if (reportType === 'changes') {
      content = `
SECURITY CHANGES REPORT
What Changed and Why

Generated: ${now}
Report Type: Changes & Activity Log
Prepared by: RedShield Security Scanner


WHAT THIS REPORT SHOWS

This report documents all security changes made to your systems:
- What issues were fixed
- When they were fixed
- What was done to fix them
- Before and after status


FIXES APPLIED

${vulnerabilities.filter(v => v.status === 'fixed').length === 0 ? 
'No fixes have been applied yet.\n' :
vulnerabilities.filter(v => v.status === 'fixed').map(v => `
FIXED: ${v.vuln_type}
  Target:     ${v.target}:${v.port}
  Severity:   ${v.severity?.toUpperCase()}
  Found:      ${new Date(v.discovered_at).toLocaleString()}
  Fixed:      ${v.fixed_at ? new Date(v.fixed_at).toLocaleString() : 'Unknown'}

  WHAT WAS DONE:
  ${v.fix_description || 'Applied automated security fix'}

  BEFORE: System was vulnerable to ${v.vuln_type.toLowerCase()}
  AFTER:  Vulnerability has been patched and secured

`).join('')}


ISSUES STILL OPEN

${vulnerabilities.filter(v => v.status !== 'fixed').length === 0 ?
'All issues have been resolved!\n' :
vulnerabilities.filter(v => v.status !== 'fixed').map(v => `
OPEN: ${v.vuln_type}
   Location: ${v.target}:${v.port}
   Severity: ${v.severity?.toUpperCase()}
   Found: ${new Date(v.discovered_at).toLocaleString()}
   Action Required: Go to Fix page to resolve this issue
`).join('\n')}


ACTIVITY LOG

All security-related activities in chronological order:

${activities.length === 0 ? 'No activities recorded yet.\n' :
activities.slice(0, 20).map(a => `
[${new Date(a.created_at).toLocaleString()}] ${a.action}
   ${a.details}
`).join('')}


SUMMARY OF CHANGES

Total Scans Performed:     ${scans.length}
Total Issues Discovered:   ${stats.total}
Total Issues Fixed:        ${stats.fixed}
Total Issues Remaining:    ${stats.open}

Security Improvement:      ${stats.total > 0 ? Math.round((stats.fixed / stats.total) * 100) : 0}% of issues resolved


END OF REPORT
`;
    } else {
      // Technical report
      content = `
TECHNICAL SECURITY REPORT
For IT Professionals

Generated: ${now}
Report Type: Technical Details
Prepared by: RedShield Security Scanner


VULNERABILITY DETAILS

${vulnerabilities.map(v => `
VULNERABILITY: ${v.vuln_type}
ID:          ${v.id}
Target:      ${v.target}
Port:        ${v.port}
Service:     ${v.service || 'N/A'}
Severity:    ${v.severity?.toUpperCase()}
Status:      ${v.status?.toUpperCase()}
Discovered:  ${v.discovered_at}
Fixed:       ${v.fixed_at || 'N/A'}

Fix Applied: ${v.fix_description || 'Pending'}

`).join('')}


SCAN HISTORY

${scans.map(s => `
Scan ID: ${s.id}
Target: ${s.target}
Type: ${s.scan_type}
Status: ${s.status}
Date: ${s.created_at}
`).join('\n')}

`;
    }

    // Download as text file
    const blob = new Blob([content], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `security-report-${reportType}-${new Date().toISOString().split('T')[0]}.txt`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  if (loading) {
    return (
      <div className="p-8 flex items-center justify-center min-h-screen">
        <div className="text-center">
          <FileText className="w-12 h-12 text-blue-400 mx-auto mb-4 animate-pulse" />
          <p className="text-gray-400">Preparing report data...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="p-6 lg:p-8 min-h-screen bg-gradient-to-br from-[#0a0f1a] via-[#0d1525] to-[#0a1628]">
      {/* Header */}
      <div className="mb-8">
        <h1 className="text-2xl lg:text-3xl font-bold text-white mb-2 flex items-center gap-3">
          <FileText className="w-8 h-8 text-blue-400" />
          Generate Security Report
        </h1>
        <p className="text-gray-400">
          Create detailed reports that explain security findings in plain English.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Report Options */}
        <div className="lg:col-span-1 space-y-6">
          {/* Report Type Selection */}
          <div className="bg-[#111827] rounded-xl border border-gray-800 p-6">
            <h2 className="text-white font-semibold mb-4">Choose Report Type</h2>
            
            <div className="space-y-3">
              <button
                onClick={() => setReportType('executive')}
                className={`w-full p-4 rounded-xl border text-left transition-all ${
                  reportType === 'executive'
                    ? 'bg-blue-500/20 border-blue-500/50 text-blue-400'
                    : 'bg-[#0d1525] border-gray-700 text-gray-400 hover:border-gray-600'
                }`}
              >
                <div className="flex items-center gap-3 mb-2">
                  <Building className="w-5 h-5" />
                  <span className="font-semibold">Executive Summary</span>
                </div>
                <p className="text-sm opacity-80">
                  Simple, non-technical report for management. Explains everything in plain English.
                </p>
              </button>

              <button
                onClick={() => setReportType('changes')}
                className={`w-full p-4 rounded-xl border text-left transition-all ${
                  reportType === 'changes'
                    ? 'bg-green-500/20 border-green-500/50 text-green-400'
                    : 'bg-[#0d1525] border-gray-700 text-gray-400 hover:border-gray-600'
                }`}
              >
                <div className="flex items-center gap-3 mb-2">
                  <Activity className="w-5 h-5" />
                  <span className="font-semibold">Changes Report</span>
                </div>
                <p className="text-sm opacity-80">
                  Details what was fixed and when. Shows before/after status for every change.
                </p>
              </button>

              <button
                onClick={() => setReportType('technical')}
                className={`w-full p-4 rounded-xl border text-left transition-all ${
                  reportType === 'technical'
                    ? 'bg-purple-500/20 border-purple-500/50 text-purple-400'
                    : 'bg-[#0d1525] border-gray-700 text-gray-400 hover:border-gray-600'
                }`}
              >
                <div className="flex items-center gap-3 mb-2">
                  <FileCheck className="w-5 h-5" />
                  <span className="font-semibold">Technical Report</span>
                </div>
                <p className="text-sm opacity-80">
                  Detailed technical data for IT teams. Includes all scan details and configurations.
                </p>
              </button>
            </div>
          </div>

          {/* Quick Stats */}
          <div className="bg-[#111827] rounded-xl border border-gray-800 p-6">
            <h2 className="text-white font-semibold mb-4">Report Will Include</h2>
            <div className="space-y-3">
              <div className="flex items-center justify-between text-sm">
                <span className="text-gray-400">Total Issues</span>
                <span className="text-white font-semibold">{stats.total}</span>
              </div>
              <div className="flex items-center justify-between text-sm">
                <span className="text-gray-400">Fixed Issues</span>
                <span className="text-green-400 font-semibold">{stats.fixed}</span>
              </div>
              <div className="flex items-center justify-between text-sm">
                <span className="text-gray-400">Open Issues</span>
                <span className="text-red-400 font-semibold">{stats.open}</span>
              </div>
              <div className="flex items-center justify-between text-sm">
                <span className="text-gray-400">Scans Performed</span>
                <span className="text-white font-semibold">{scans.length}</span>
              </div>
              <div className="flex items-center justify-between text-sm">
                <span className="text-gray-400">Activity Records</span>
                <span className="text-white font-semibold">{activities.length}</span>
              </div>
            </div>
          </div>

          {/* Generate Button */}
          <button
            onClick={generateReport}
            className="w-full py-4 bg-blue-600 hover:bg-blue-500 text-white rounded-xl font-semibold flex items-center justify-center gap-3"
          >
            <Download className="w-6 h-6" />
            Download Report
          </button>
        </div>

        {/* Report Preview */}
        <div className="lg:col-span-2 bg-[#111827] rounded-xl border border-gray-800 overflow-hidden">
          <div className="p-4 border-b border-gray-800 bg-[#0d1525] flex items-center justify-between">
            <h2 className="text-white font-semibold flex items-center gap-2">
              <Eye className="w-5 h-5 text-blue-400" />
              Report Preview
            </h2>
            <span className="text-xs text-gray-500 bg-gray-800 px-2 py-1 rounded">
              {reportType === 'executive' ? 'Executive Summary' : 
               reportType === 'changes' ? 'Changes Report' : 'Technical Report'}
            </span>
          </div>
          
          <div className="p-6 max-h-[700px] overflow-y-auto">
            {reportType === 'executive' && (
              <div className="space-y-6">
                <div className="text-center pb-6 border-b border-gray-800">
                  <h3 className="text-2xl font-bold text-white mb-2">Security Assessment Report</h3>
                  <p className="text-gray-400">Executive Summary for Management</p>
                </div>

                {/* Security Score */}
                <div className={`p-6 rounded-xl border ${
                  normalizedScore >= 80 ? 'bg-green-500/10 border-green-500/30' :
                  normalizedScore >= 60 ? 'bg-yellow-500/10 border-yellow-500/30' :
                  normalizedScore >= 40 ? 'bg-orange-500/10 border-orange-500/30' :
                  'bg-red-500/10 border-red-500/30'
                }`}>
                  <div className="text-center">
                    <p className="text-gray-400 mb-2">Overall Security Score</p>
                    <p className={`text-5xl font-bold ${
                      normalizedScore >= 80 ? 'text-green-400' :
                      normalizedScore >= 60 ? 'text-yellow-400' :
                      normalizedScore >= 40 ? 'text-orange-400' :
                      'text-red-400'
                    }`}>{normalizedScore}/100</p>
                    <p className="mt-2 text-gray-300">
                      {normalizedScore >= 80 ? 'Your systems are reasonably secure' :
                       normalizedScore >= 60 ? 'Some issues need attention' :
                       normalizedScore >= 40 ? 'Several problems need addressing' :
                       'Critical issues require immediate action'}
                    </p>
                  </div>
                </div>

                {/* Summary Stats */}
                <div className="grid grid-cols-2 gap-4">
                  <div className="bg-[#0d1525] p-4 rounded-xl border border-gray-800">
                    <p className="text-gray-400 text-sm">Total Issues Found</p>
                    <p className="text-2xl font-bold text-white">{stats.total}</p>
                  </div>
                  <div className="bg-green-500/10 p-4 rounded-xl border border-green-500/30">
                    <p className="text-green-400 text-sm">Issues Fixed</p>
                    <p className="text-2xl font-bold text-green-400">{stats.fixed}</p>
                  </div>
                  <div className="bg-red-500/10 p-4 rounded-xl border border-red-500/30">
                    <p className="text-red-400 text-sm">Critical Issues</p>
                    <p className="text-2xl font-bold text-red-400">{stats.critical}</p>
                  </div>
                  <div className="bg-orange-500/10 p-4 rounded-xl border border-orange-500/30">
                    <p className="text-orange-400 text-sm">High Priority</p>
                    <p className="text-2xl font-bold text-orange-400">{stats.high}</p>
                  </div>
                </div>

                {/* What the report contains */}
                <div className="bg-blue-500/10 border border-blue-500/30 rounded-xl p-5">
                  <h4 className="text-blue-400 font-semibold mb-3">What's In This Report?</h4>
                  <ul className="text-gray-300 space-y-2">
                    <li>• Clear explanation of all security issues found</li>
                    <li>• What each issue means in plain English</li>
                    <li>• Which issues have been fixed</li>
                    <li>• Recommendations for next steps</li>
                  </ul>
                </div>
              </div>
            )}

            {reportType === 'changes' && (
              <div className="space-y-6">
                <div className="text-center pb-6 border-b border-gray-800">
                  <h3 className="text-2xl font-bold text-white mb-2">Security Changes Report</h3>
                  <p className="text-gray-400">What Changed and Why</p>
                </div>

                {/* Changes Summary */}
                <div className="grid grid-cols-2 gap-4">
                  <div className="bg-green-500/10 p-4 rounded-xl border border-green-500/30">
                    <p className="text-green-400 text-sm">Fixes Applied</p>
                    <p className="text-2xl font-bold text-green-400">{stats.fixed}</p>
                  </div>
                  <div className="bg-yellow-500/10 p-4 rounded-xl border border-yellow-500/30">
                    <p className="text-yellow-400 text-sm">Still Open</p>
                    <p className="text-2xl font-bold text-yellow-400">{stats.open}</p>
                  </div>
                </div>

                {/* Recent Fixes */}
                <div>
                  <h4 className="text-white font-semibold mb-3">Recent Fixes Applied</h4>
                  {vulnerabilities.filter(v => v.status === 'fixed').length === 0 ? (
                    <p className="text-gray-400 bg-[#0d1525] p-4 rounded-xl">No fixes applied yet.</p>
                  ) : (
                    <div className="space-y-3">
                      {vulnerabilities.filter(v => v.status === 'fixed').slice(0, 5).map(v => (
                        <div key={v.id} className="bg-[#0d1525] p-4 rounded-xl border border-gray-800">
                          <div className="flex items-center gap-2 mb-2">
                            <CheckCircle className="w-5 h-5 text-green-400" />
                            <span className="text-white font-medium">{v.vuln_type}</span>
                          </div>
                          <p className="text-gray-400 text-sm">{v.target}:{v.port}</p>
                          <p className="text-green-400 text-sm mt-2">{v.fix_description || 'Fix applied'}</p>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            )}

            {reportType === 'technical' && (
              <div className="space-y-6">
                <div className="text-center pb-6 border-b border-gray-800">
                  <h3 className="text-2xl font-bold text-white mb-2">Technical Security Report</h3>
                  <p className="text-gray-400">Detailed Information for IT Teams</p>
                </div>

                {/* Vulnerability List */}
                <div>
                  <h4 className="text-white font-semibold mb-3">All Vulnerabilities</h4>
                  <div className="space-y-3">
                    {vulnerabilities.slice(0, 5).map(v => (
                      <div key={v.id} className="bg-[#0d1525] p-4 rounded-xl border border-gray-800 font-mono text-sm">
                        <div className="grid grid-cols-2 gap-2">
                          <span className="text-gray-500">Type:</span>
                          <span className="text-white">{v.vuln_type}</span>
                          <span className="text-gray-500">Target:</span>
                          <span className="text-white">{v.target}:{v.port}</span>
                          <span className="text-gray-500">Service:</span>
                          <span className="text-white">{v.service || 'N/A'}</span>
                          <span className="text-gray-500">Severity:</span>
                          <span className={
                            v.severity?.toLowerCase() === 'critical' ? 'text-red-400' :
                            v.severity?.toLowerCase() === 'high' ? 'text-orange-400' :
                            v.severity?.toLowerCase() === 'medium' ? 'text-yellow-400' :
                            'text-green-400'
                          }>{v.severity?.toUpperCase()}</span>
                          <span className="text-gray-500">Status:</span>
                          <span className={v.status === 'fixed' ? 'text-green-400' : 'text-red-400'}>
                            {v.status?.toUpperCase()}
                          </span>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
