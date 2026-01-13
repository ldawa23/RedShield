import { useState, useEffect } from 'react';
import { 
  FileText, Download, AlertTriangle, 
  CheckCircle, Shield, ExternalLink,
  FileCheck, Award, BookOpen
} from 'lucide-react';
import { scansApi, vulnerabilitiesApi } from '../services/api';

interface Scan {
  id: number;
  scan_id: string;
  target: string;
  status: string;
  started_at: string;
  completed_at: string;
  vuln_count: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  fixed_count: number;
}

interface Vulnerability {
  id: number;
  vuln_type: string;
  severity: string;
  status: string;
  service: string;
  port: number;
  description: string;
  discovered_at: string;
  http_method: string;
  vulnerable_url: string;
  vulnerable_parameter: string;
  request_body: string;
  proof_of_concept: string;
  cve_id: string;
  owasp_category: string;
  fix_description: string;
  fix_method: string;
  fix_command: string;
  before_state: string;
  after_state: string;
  verification_result: string;
}

// Executive Summary Helper
const getVulnExplanation = (vulnType: string): { summary: string; businessImpact: string; recommendation: string } => {
  const explanations: Record<string, { summary: string; businessImpact: string; recommendation: string }> = {
    'SQL Injection': {
      summary: 'Attackers can access, modify, or delete your database information by entering malicious commands.',
      businessImpact: 'Customer data theft, financial loss, regulatory fines (GDPR, PCI-DSS), reputation damage.',
      recommendation: 'Use parameterized queries, implement input validation, and conduct regular security audits.'
    },
    'Cross-Site Scripting': {
      summary: 'Attackers can inject malicious scripts that run in visitors\' browsers to steal their information.',
      businessImpact: 'User session hijacking, credential theft, malware distribution, loss of customer trust.',
      recommendation: 'Sanitize all user inputs, use Content Security Policy headers, encode output properly.'
    },
    'XSS': {
      summary: 'Attackers can inject malicious scripts that run in visitors\' browsers to steal their information.',
      businessImpact: 'User session hijacking, credential theft, malware distribution, loss of customer trust.',
      recommendation: 'Sanitize all user inputs, use Content Security Policy headers, encode output properly.'
    },
    'Command Injection': {
      summary: 'Attackers can execute operating system commands on your server to take complete control.',
      businessImpact: 'Complete system compromise, data exfiltration, ransomware attacks, service disruption.',
      recommendation: 'Never pass user input to system commands, use secure APIs, implement strict input validation.'
    },
    'Default Credentials': {
      summary: 'Systems are using factory-default passwords that attackers can easily guess.',
      businessImpact: 'Unauthorized access, data breaches, compliance violations, administrative takeover.',
      recommendation: 'Change all default passwords immediately, implement strong password policies.'
    },
    'Exposed Database': {
      summary: 'Database is accessible from the internet without proper security controls.',
      businessImpact: 'Massive data breach potential, regulatory penalties, complete loss of sensitive data.',
      recommendation: 'Restrict database access to internal networks, implement firewall rules, use VPN for remote access.'
    },
    'Outdated Software': {
      summary: 'Software versions with known security vulnerabilities that attackers actively exploit.',
      businessImpact: 'Known exploits available, easy target for automated attacks, compliance issues.',
      recommendation: 'Establish regular patching schedule, subscribe to security advisories, automate updates where possible.'
    },
    'File Inclusion': {
      summary: 'Attackers can include malicious files to execute unauthorized code on your server.',
      businessImpact: 'Code execution, sensitive file disclosure, complete server compromise.',
      recommendation: 'Validate and sanitize file paths, use whitelists for allowed files, disable dangerous PHP settings.'
    }
  };
  
  return explanations[vulnType] || {
    summary: 'A security vulnerability that could allow unauthorized access or data manipulation.',
    businessImpact: 'Potential data breach, unauthorized access, or service disruption.',
    recommendation: 'Review and remediate according to security best practices.'
  };
};

const getRiskScore = (scan: Scan): { score: number; grade: string; color: string; message: string } => {
  const critical = scan.critical_count || 0;
  const high = scan.high_count || 0;
  const medium = scan.medium_count || 0;
  const low = scan.low_count || 0;
  const fixed = scan.fixed_count || 0;
  
  // Calculate weighted score (0-100, lower is better)
  const totalWeight = critical * 40 + high * 25 + medium * 10 + low * 5;
  const fixedBonus = fixed * 15;
  const rawScore = Math.max(0, 100 - totalWeight + fixedBonus);
  const score = Math.min(100, Math.max(0, rawScore));
  
  if (score >= 90) return { score, grade: 'A', color: 'text-green-400', message: 'Excellent security posture' };
  if (score >= 80) return { score, grade: 'B', color: 'text-green-500', message: 'Good security with minor issues' };
  if (score >= 70) return { score, grade: 'C', color: 'text-yellow-400', message: 'Moderate risk - needs attention' };
  if (score >= 50) return { score, grade: 'D', color: 'text-orange-400', message: 'High risk - immediate action needed' };
  return { score, grade: 'F', color: 'text-red-400', message: 'Critical risk - urgent remediation required' };
};

function generateHTMLReport(scan: Scan, vulnerabilities: Vulnerability[]): string {
  const fixedVulns = vulnerabilities.filter(v => v.status === 'fixed');
  const openVulns = vulnerabilities.filter(v => v.status !== 'fixed');
  
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>RedShield Security Report - ${scan.target}</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { 
      font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
      background: #0a1628; 
      color: #e5e7eb; 
      line-height: 1.6;
    }
    .container { max-width: 1200px; margin: 0 auto; padding: 40px 20px; }
    .header { 
      background: linear-gradient(135deg, #1e3a5f 0%, #0d1f3c 100%); 
      padding: 40px; 
      border-radius: 16px; 
      margin-bottom: 30px;
      border: 1px solid #374151;
    }
    .header h1 { 
      color: #ef4444; 
      font-size: 32px; 
      margin-bottom: 10px;
      display: flex;
      align-items: center;
      gap: 12px;
    }
    .header h1::before { content: "🛡️"; }
    .header p { color: #9ca3af; }
    .meta { 
      display: grid; 
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); 
      gap: 20px; 
      margin-top: 20px; 
    }
    .meta-item { 
      background: #081225; 
      padding: 15px; 
      border-radius: 8px;
      border: 1px solid #1e3a5f;
    }
    .meta-item label { color: #6b7280; font-size: 12px; text-transform: uppercase; }
    .meta-item value { color: #fff; font-size: 18px; font-weight: 600; display: block; margin-top: 5px; }
    .section { 
      background: #0d1f3c; 
      border-radius: 16px; 
      padding: 30px; 
      margin-bottom: 30px;
      border: 1px solid #1e3a5f;
    }
    .section-title { 
      color: #fff; 
      font-size: 20px; 
      margin-bottom: 20px;
      padding-bottom: 10px;
      border-bottom: 1px solid #1e3a5f;
    }
    .stats-grid { 
      display: grid; 
      grid-template-columns: repeat(5, 1fr); 
      gap: 15px; 
      margin-bottom: 30px; 
    }
    .stat-card { 
      background: #081225; 
      padding: 20px; 
      border-radius: 12px; 
      text-align: center;
      border: 1px solid #1e3a5f;
    }
    .stat-card.critical { border-color: #ef4444; }
    .stat-card.high { border-color: #f97316; }
    .stat-card.medium { border-color: #eab308; }
    .stat-card.low { border-color: #22c55e; }
    .stat-card.fixed { border-color: #22c55e; background: rgba(34, 197, 94, 0.1); }
    .stat-card .value { font-size: 36px; font-weight: 700; }
    .stat-card .label { color: #6b7280; font-size: 12px; text-transform: uppercase; }
    .critical .value { color: #ef4444; }
    .high .value { color: #f97316; }
    .medium .value { color: #eab308; }
    .low .value { color: #22c55e; }
    .fixed .value { color: #22c55e; }
    .vuln-card { 
      background: #081225; 
      border-radius: 12px; 
      margin-bottom: 20px;
      border: 1px solid #1e3a5f;
      overflow: hidden;
    }
    .vuln-header { 
      padding: 20px; 
      display: flex; 
      justify-content: space-between; 
      align-items: center;
      border-bottom: 1px solid #1e3a5f;
    }
    .vuln-header h3 { color: #fff; font-size: 16px; }
    .badge { 
      padding: 4px 12px; 
      border-radius: 20px; 
      font-size: 11px; 
      font-weight: 600; 
      text-transform: uppercase;
    }
    .badge.critical { background: rgba(239, 68, 68, 0.2); color: #ef4444; }
    .badge.high { background: rgba(249, 115, 22, 0.2); color: #f97316; }
    .badge.medium { background: rgba(234, 179, 8, 0.2); color: #eab308; }
    .badge.low { background: rgba(34, 197, 94, 0.2); color: #22c55e; }
    .badge.fixed { background: rgba(34, 197, 94, 0.2); color: #22c55e; }
    .badge.open { background: rgba(239, 68, 68, 0.2); color: #ef4444; }
    .vuln-body { padding: 20px; }
    .vuln-meta { 
      display: flex; 
      gap: 20px; 
      margin-bottom: 15px; 
      color: #9ca3af; 
      font-size: 14px; 
    }
    .http-panel { 
      background: #0a1628; 
      border-radius: 8px; 
      padding: 15px; 
      margin: 15px 0;
      font-family: 'Consolas', monospace;
      font-size: 13px;
    }
    .http-method { 
      display: inline-block;
      padding: 2px 8px;
      border-radius: 4px;
      font-weight: bold;
      margin-right: 10px;
    }
    .http-method.get { background: rgba(34, 197, 94, 0.2); color: #22c55e; }
    .http-method.post { background: rgba(59, 130, 246, 0.2); color: #3b82f6; }
    .vuln-param { 
      background: rgba(239, 68, 68, 0.1); 
      border: 1px solid rgba(239, 68, 68, 0.3);
      padding: 10px;
      border-radius: 6px;
      margin: 10px 0;
    }
    .vuln-param label { color: #ef4444; font-size: 12px; }
    .fix-evidence { 
      background: rgba(34, 197, 94, 0.1); 
      border: 1px solid rgba(34, 197, 94, 0.3);
      border-radius: 8px;
      padding: 20px;
      margin-top: 20px;
    }
    .fix-evidence h4 { color: #22c55e; margin-bottom: 15px; }
    .code-block { 
      background: #0a1628; 
      padding: 15px; 
      border-radius: 6px; 
      margin: 10px 0;
      overflow-x: auto;
      font-family: 'Consolas', monospace;
      font-size: 12px;
    }
    .before-after { display: grid; grid-template-columns: 1fr 1fr; gap: 15px; }
    .before { border-left: 3px solid #ef4444; padding-left: 15px; }
    .after { border-left: 3px solid #22c55e; padding-left: 15px; }
    .security-refs { display: flex; gap: 10px; margin-top: 15px; }
    .security-ref { 
      padding: 4px 10px; 
      border-radius: 4px; 
      font-size: 12px;
      text-decoration: none;
    }
    .security-ref.cve { background: rgba(168, 85, 247, 0.2); color: #a855f7; }
    .security-ref.owasp { background: rgba(59, 130, 246, 0.2); color: #3b82f6; }
    .footer { 
      text-align: center; 
      padding: 30px; 
      color: #6b7280; 
      font-size: 14px;
    }
    @media print {
      body { background: #fff; color: #000; }
      .container { max-width: 100%; }
      .header, .section, .stat-card, .vuln-card { 
        border: 1px solid #ddd; 
        background: #fff;
      }
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>RedShield Security Report</h1>
      <p>Comprehensive vulnerability assessment and remediation report</p>
      <div class="meta">
        <div class="meta-item">
          <label>Target</label>
          <value>${scan.target}</value>
        </div>
        <div class="meta-item">
          <label>Scan ID</label>
          <value>${scan.scan_id}</value>
        </div>
        <div class="meta-item">
          <label>Scan Date</label>
          <value>${new Date(scan.started_at).toLocaleString()}</value>
        </div>
        <div class="meta-item">
          <label>Report Generated</label>
          <value>${new Date().toLocaleString()}</value>
        </div>
      </div>
    </div>

    <div class="section">
      <h2 class="section-title">Executive Summary</h2>
      <div class="stats-grid">
        <div class="stat-card critical">
          <div class="value">${scan.critical_count || 0}</div>
          <div class="label">Critical</div>
        </div>
        <div class="stat-card high">
          <div class="value">${scan.high_count || 0}</div>
          <div class="label">High</div>
        </div>
        <div class="stat-card medium">
          <div class="value">${scan.medium_count || 0}</div>
          <div class="label">Medium</div>
        </div>
        <div class="stat-card low">
          <div class="value">${scan.low_count || 0}</div>
          <div class="label">Low</div>
        </div>
        <div class="stat-card fixed">
          <div class="value">${fixedVulns.length}</div>
          <div class="label">Fixed</div>
        </div>
      </div>
    </div>

    ${fixedVulns.length > 0 ? `
    <div class="section">
      <h2 class="section-title">✅ Fixed Vulnerabilities (${fixedVulns.length})</h2>
      ${fixedVulns.map(v => `
        <div class="vuln-card">
          <div class="vuln-header">
            <h3>${v.vuln_type}</h3>
            <div>
              <span class="badge ${v.severity?.toLowerCase()}">${v.severity}</span>
              <span class="badge fixed">FIXED</span>
            </div>
          </div>
          <div class="vuln-body">
            <div class="vuln-meta">
              <span>🌐 ${v.service}:${v.port}</span>
              <span>📅 Found: ${new Date(v.discovered_at).toLocaleDateString()}</span>
              ${v.cve_id ? `<span>🔗 ${v.cve_id}</span>` : ''}
            </div>
            
            ${v.description ? `<p style="margin-bottom: 15px;">${v.description}</p>` : ''}
            
            ${v.http_method || v.vulnerable_url ? `
            <div class="http-panel">
              <span class="http-method ${v.http_method?.toLowerCase()}">${v.http_method || 'GET'}</span>
              <span style="color: #9ca3af;">${v.vulnerable_url || `http://${scan.target}:${v.port}/`}</span>
            </div>
            ` : ''}
            
            ${v.vulnerable_parameter ? `
            <div class="vuln-param">
              <label>Vulnerable Parameter:</label>
              <code style="display: block; margin-top: 5px; color: #ef4444;">${v.vulnerable_parameter}</code>
            </div>
            ` : ''}
            
            ${v.fix_method || v.fix_command || v.before_state || v.after_state ? `
            <div class="fix-evidence">
              <h4>🔧 How It Was Fixed</h4>
              ${v.fix_method ? `<p><strong>Method:</strong> ${v.fix_method}</p>` : ''}
              ${v.fix_command ? `
                <p><strong>Fix Command:</strong></p>
                <div class="code-block">${v.fix_command}</div>
              ` : ''}
              ${v.before_state || v.after_state ? `
                <div class="before-after">
                  <div class="before">
                    <p style="color: #ef4444; font-weight: bold;">Before:</p>
                    <div class="code-block">${v.before_state || 'N/A'}</div>
                  </div>
                  <div class="after">
                    <p style="color: #22c55e; font-weight: bold;">After:</p>
                    <div class="code-block">${v.after_state || 'N/A'}</div>
                  </div>
                </div>
              ` : ''}
              ${v.verification_result ? `
                <p style="margin-top: 15px; color: #22c55e;"><strong>✓ Verification:</strong> ${v.verification_result}</p>
              ` : ''}
            </div>
            ` : ''}
            
            <div class="security-refs">
              ${v.cve_id ? `<a href="https://nvd.nist.gov/vuln/detail/${v.cve_id}" class="security-ref cve" target="_blank">${v.cve_id}</a>` : ''}
              ${v.owasp_category ? `<span class="security-ref owasp">${v.owasp_category}</span>` : ''}
            </div>
          </div>
        </div>
      `).join('')}
    </div>
    ` : ''}

    ${openVulns.length > 0 ? `
    <div class="section">
      <h2 class="section-title">⚠️ Open Vulnerabilities (${openVulns.length})</h2>
      ${openVulns.map(v => `
        <div class="vuln-card">
          <div class="vuln-header">
            <h3>${v.vuln_type}</h3>
            <div>
              <span class="badge ${v.severity?.toLowerCase()}">${v.severity}</span>
              <span class="badge open">OPEN</span>
            </div>
          </div>
          <div class="vuln-body">
            <div class="vuln-meta">
              <span>🌐 ${v.service}:${v.port}</span>
              <span>📅 Found: ${new Date(v.discovered_at).toLocaleDateString()}</span>
            </div>
            
            ${v.description ? `<p style="margin-bottom: 15px;">${v.description}</p>` : ''}
            
            ${v.http_method || v.vulnerable_url ? `
            <div class="http-panel">
              <span class="http-method ${v.http_method?.toLowerCase()}">${v.http_method || 'GET'}</span>
              <span style="color: #9ca3af;">${v.vulnerable_url || `http://${scan.target}:${v.port}/`}</span>
            </div>
            ` : ''}
            
            ${v.vulnerable_parameter ? `
            <div class="vuln-param">
              <label>Vulnerable Parameter:</label>
              <code style="display: block; margin-top: 5px; color: #ef4444;">${v.vulnerable_parameter}</code>
            </div>
            ` : ''}
            
            ${v.proof_of_concept ? `
            <div style="margin-top: 15px;">
              <p style="color: #ef4444; font-weight: bold;">Proof of Concept:</p>
              <div class="code-block" style="color: #ef4444;">${v.proof_of_concept}</div>
            </div>
            ` : ''}
            
            ${v.fix_description ? `
            <div style="background: rgba(59, 130, 246, 0.1); border: 1px solid rgba(59, 130, 246, 0.3); border-radius: 8px; padding: 15px; margin-top: 15px;">
              <h4 style="color: #3b82f6; margin-bottom: 10px;">💡 Recommended Fix</h4>
              <p>${v.fix_description}</p>
            </div>
            ` : ''}
            
            <div class="security-refs">
              ${v.cve_id ? `<a href="https://nvd.nist.gov/vuln/detail/${v.cve_id}" class="security-ref cve" target="_blank">${v.cve_id}</a>` : ''}
              ${v.owasp_category ? `<span class="security-ref owasp">${v.owasp_category}</span>` : ''}
            </div>
          </div>
        </div>
      `).join('')}
    </div>
    ` : ''}

    <div class="footer">
      <p>Generated by RedShield Security Scanner</p>
      <p>© ${new Date().getFullYear()} RedShield - Professional Security Operations</p>
    </div>
  </div>
</body>
</html>`;
}

export default function Reports() {
  const [scans, setScans] = useState<Scan[]>([]);
  const [selectedScan, setSelectedScan] = useState<string>('');
  const [vulnerabilities, setVulnerabilities] = useState<Vulnerability[]>([]);
  const [loading, setLoading] = useState(true);
  const [generating, setGenerating] = useState(false);

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

  useEffect(() => {
    if (selectedScan) {
      const fetchVulns = async () => {
        try {
          const res = await vulnerabilitiesApi.getByScan(selectedScan);
          setVulnerabilities(res.data || []);
        } catch (error) {
          console.error('Error fetching vulnerabilities:', error);
        }
      };
      fetchVulns();
    }
  }, [selectedScan]);

  const handleGenerateHTML = () => {
    const scan = scans.find(s => s.scan_id === selectedScan);
    if (!scan) return;

    setGenerating(true);
    
    const html = generateHTMLReport(scan, vulnerabilities);
    const blob = new Blob([html], { type: 'text/html' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `RedShield-Report-${scan.target}-${new Date().toISOString().split('T')[0]}.html`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    
    setGenerating(false);
  };

  const handlePreviewHTML = () => {
    const scan = scans.find(s => s.scan_id === selectedScan);
    if (!scan) return;

    const html = generateHTMLReport(scan, vulnerabilities);
    const blob = new Blob([html], { type: 'text/html' });
    const url = URL.createObjectURL(blob);
    window.open(url, '_blank');
  };

  const currentScan = scans.find(s => s.scan_id === selectedScan);
  const fixedVulns = vulnerabilities.filter(v => v.status === 'fixed');
  const openVulns = vulnerabilities.filter(v => v.status !== 'fixed');

  if (loading) {
    return (
      <div className="p-6 flex items-center justify-center h-screen">
        <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-red-500"></div>
      </div>
    );
  }

  const riskInfo = currentScan ? getRiskScore(currentScan) : null;

  return (
    <div className="p-6 space-y-6 min-h-full">
      {/* Header */}
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-white flex items-center gap-3 mb-2">
          <div className="w-12 h-12 rounded-xl bg-gradient-to-br from-purple-500 to-purple-700 flex items-center justify-center">
            <FileText className="w-7 h-7 text-white" />
          </div>
          Security Reports
        </h1>
        <p className="text-gray-400 text-lg">
          Generate professional security assessment reports with executive summaries
        </p>
      </div>

      {/* Report Generator */}
      <div className="bg-gradient-to-br from-[#0d1f3c] to-[#0a1628] rounded-2xl p-6 border border-gray-700">
        <h2 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
          <FileCheck className="w-5 h-5 text-purple-400" />
          Generate Report
        </h2>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {/* Scan Selection */}
          <div>
            <label className="block text-gray-400 text-sm mb-2">Select Completed Scan</label>
            <select
              value={selectedScan}
              onChange={(e) => setSelectedScan(e.target.value)}
              className="w-full bg-[#081225] border border-gray-700 rounded-xl px-4 py-3 text-white focus:outline-none focus:border-purple-500"
            >
              <option value="">Choose a scan...</option>
              {scans.map(scan => (
                <option key={scan.scan_id} value={scan.scan_id}>
                  {scan.target} - {scan.scan_id.substring(0, 8)} ({new Date(scan.started_at).toLocaleDateString()})
                </option>
              ))}
            </select>
          </div>

          {/* Actions */}
          <div className="flex items-end gap-3">
            <button
              onClick={handlePreviewHTML}
              disabled={!selectedScan}
              className="flex-1 px-4 py-3 bg-[#081225] border border-gray-700 text-white rounded-xl hover:border-purple-500 transition-colors disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2"
            >
              <ExternalLink className="w-4 h-4" />
              Preview Report
            </button>
            <button
              onClick={handleGenerateHTML}
              disabled={!selectedScan || generating}
              className="flex-1 px-4 py-3 bg-gradient-to-r from-purple-500 to-purple-700 text-white rounded-xl hover:from-purple-600 hover:to-purple-800 transition-colors disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2"
            >
              {generating ? (
                <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
              ) : (
                <Download className="w-4 h-4" />
              )}
              Download Report
            </button>
          </div>
        </div>
      </div>

      {/* Selected Scan Preview */}
      {currentScan && riskInfo && (
        <div className="space-y-6">
          {/* Risk Score Card */}
          <div className="bg-gradient-to-br from-[#0d1f3c] to-[#0a1628] rounded-2xl border border-gray-700 p-6">
            <div className="flex items-center justify-between mb-6">
              <div className="flex items-center gap-4">
                <div className="p-3 bg-purple-500/20 rounded-xl">
                  <Shield className="w-8 h-8 text-purple-400" />
                </div>
                <div>
                  <h3 className="text-xl font-bold text-white">{currentScan.target}</h3>
                  <p className="text-gray-400 text-sm">Scan ID: {currentScan.scan_id.substring(0, 12)}...</p>
                </div>
              </div>
              <div className="text-center">
                <div className={`text-5xl font-bold ${riskInfo.color}`}>{riskInfo.grade}</div>
                <p className="text-gray-400 text-xs mt-1">Security Grade</p>
              </div>
            </div>
            
            {/* Risk Score Bar */}
            <div className="mb-6">
              <div className="flex justify-between items-center mb-2">
                <span className="text-gray-400 text-sm">Security Score</span>
                <span className={`font-bold ${riskInfo.color}`}>{riskInfo.score}/100</span>
              </div>
              <div className="h-4 bg-gray-800 rounded-full overflow-hidden">
                <div 
                  className={`h-full rounded-full transition-all duration-1000 ${
                    riskInfo.score >= 80 ? 'bg-gradient-to-r from-green-500 to-green-400' :
                    riskInfo.score >= 60 ? 'bg-gradient-to-r from-yellow-500 to-yellow-400' :
                    riskInfo.score >= 40 ? 'bg-gradient-to-r from-orange-500 to-orange-400' :
                    'bg-gradient-to-r from-red-500 to-red-400'
                  }`}
                  style={{ width: `${riskInfo.score}%` }}
                ></div>
              </div>
              <p className={`text-sm mt-2 ${riskInfo.color}`}>{riskInfo.message}</p>
            </div>

            {/* Stats Grid */}
            <div className="grid grid-cols-6 gap-3">
              <div className="bg-[#081225] rounded-xl p-4 text-center">
                <p className="text-2xl font-bold text-white">{vulnerabilities.length}</p>
                <p className="text-gray-500 text-xs">Total Found</p>
              </div>
              <div className="bg-[#081225] rounded-xl p-4 text-center border-l-4 border-red-500">
                <p className="text-2xl font-bold text-red-400">{currentScan.critical_count || 0}</p>
                <p className="text-gray-500 text-xs">Critical</p>
              </div>
              <div className="bg-[#081225] rounded-xl p-4 text-center border-l-4 border-orange-500">
                <p className="text-2xl font-bold text-orange-400">{currentScan.high_count || 0}</p>
                <p className="text-gray-500 text-xs">High</p>
              </div>
              <div className="bg-[#081225] rounded-xl p-4 text-center border-l-4 border-yellow-500">
                <p className="text-2xl font-bold text-yellow-400">{currentScan.medium_count || 0}</p>
                <p className="text-gray-500 text-xs">Medium</p>
              </div>
              <div className="bg-[#081225] rounded-xl p-4 text-center border-l-4 border-blue-500">
                <p className="text-2xl font-bold text-blue-400">{currentScan.low_count || 0}</p>
                <p className="text-gray-500 text-xs">Low</p>
              </div>
              <div className="bg-[#081225] rounded-xl p-4 text-center border-l-4 border-green-500">
                <p className="text-2xl font-bold text-green-400">{fixedVulns.length}</p>
                <p className="text-gray-500 text-xs">Fixed</p>
              </div>
            </div>
          </div>

          {/* Executive Summary */}
          <div className="bg-gradient-to-br from-[#0d1f3c] to-[#0a1628] rounded-2xl border border-gray-700 p-6">
            <h2 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
              <BookOpen className="w-5 h-5 text-blue-400" />
              Executive Summary
            </h2>
            
            <div className="bg-[#081225] rounded-xl p-5 mb-6">
              <p className="text-gray-300 leading-relaxed">
                A security assessment was conducted on <span className="text-white font-medium">{currentScan.target}</span> on{' '}
                <span className="text-white font-medium">{new Date(currentScan.started_at).toLocaleDateString('en-US', { 
                  weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' 
                })}</span>.
                {' '}The scan identified <span className={`font-bold ${vulnerabilities.length > 0 ? 'text-red-400' : 'text-green-400'}`}>
                  {vulnerabilities.length} {vulnerabilities.length === 1 ? 'vulnerability' : 'vulnerabilities'}
                </span>
                {(currentScan.critical_count || 0) + (currentScan.high_count || 0) > 0 && 
                  <>, including <span className="text-red-400 font-bold">{currentScan.critical_count || 0} critical</span> and{' '}
                  <span className="text-orange-400 font-bold">{currentScan.high_count || 0} high severity</span> issues that require immediate attention</>
                }.
                {fixedVulns.length > 0 && 
                  <> Of these, <span className="text-green-400 font-bold">{fixedVulns.length}</span> have been successfully remediated.</>
                }
              </p>
            </div>

            {/* Key Findings */}
            {vulnerabilities.length > 0 && (
              <div className="space-y-4">
                <h3 className="text-white font-medium flex items-center gap-2">
                  <AlertTriangle className="w-4 h-4 text-yellow-400" />
                  Key Findings & Recommendations
                </h3>
                
                {/* Group by vulnerability type */}
                {Array.from(new Set(vulnerabilities.map(v => v.vuln_type))).slice(0, 4).map(vulnType => {
                  const vulnExplain = getVulnExplanation(vulnType);
                  const count = vulnerabilities.filter(v => v.vuln_type === vulnType).length;
                  const fixedCount = vulnerabilities.filter(v => v.vuln_type === vulnType && v.status === 'fixed').length;
                  
                  return (
                    <div key={vulnType} className="bg-[#081225] rounded-xl p-4 border border-gray-700/50">
                      <div className="flex items-start justify-between mb-2">
                        <h4 className="text-white font-medium">{vulnType}</h4>
                        <div className="flex items-center gap-2">
                          <span className="text-xs bg-red-500/20 text-red-400 px-2 py-0.5 rounded">{count} found</span>
                          {fixedCount > 0 && (
                            <span className="text-xs bg-green-500/20 text-green-400 px-2 py-0.5 rounded">{fixedCount} fixed</span>
                          )}
                        </div>
                      </div>
                      <p className="text-gray-400 text-sm mb-3">{vulnExplain.summary}</p>
                      <div className="grid grid-cols-2 gap-4 text-xs">
                        <div>
                          <span className="text-red-400 font-medium">Business Impact: </span>
                          <span className="text-gray-400">{vulnExplain.businessImpact}</span>
                        </div>
                        <div>
                          <span className="text-blue-400 font-medium">Recommendation: </span>
                          <span className="text-gray-400">{vulnExplain.recommendation}</span>
                        </div>
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>

          {/* Fixed vs Open Summary */}
          <div className="grid grid-cols-2 gap-4">
            <div className="bg-gradient-to-br from-green-900/20 to-[#0a1628] border border-green-500/30 rounded-2xl p-5">
              <h4 className="text-green-400 font-semibold mb-3 flex items-center gap-2">
                <CheckCircle className="w-5 h-5" />
                Remediated ({fixedVulns.length})
              </h4>
              {fixedVulns.length > 0 ? (
                <div className="space-y-2 max-h-48 overflow-y-auto">
                  {fixedVulns.slice(0, 5).map(v => (
                    <div key={v.id} className="flex items-center justify-between text-sm bg-[#081225] rounded-lg px-3 py-2">
                      <span className="text-gray-300">{v.vuln_type}</span>
                      <span className={`px-2 py-0.5 rounded text-xs ${
                        v.severity?.toUpperCase() === 'CRITICAL' ? 'bg-red-500/20 text-red-400' :
                        v.severity?.toUpperCase() === 'HIGH' ? 'bg-orange-500/20 text-orange-400' :
                        'bg-yellow-500/20 text-yellow-400'
                      }`}>{v.severity}</span>
                    </div>
                  ))}
                  {fixedVulns.length > 5 && (
                    <p className="text-gray-500 text-xs text-center">+{fixedVulns.length - 5} more fixed</p>
                  )}
                </div>
              ) : (
                <p className="text-gray-500 text-sm">No vulnerabilities fixed yet</p>
              )}
            </div>

            <div className="bg-gradient-to-br from-red-900/20 to-[#0a1628] border border-red-500/30 rounded-2xl p-5">
              <h4 className="text-red-400 font-semibold mb-3 flex items-center gap-2">
                <AlertTriangle className="w-5 h-5" />
                Needs Attention ({openVulns.length})
              </h4>
              {openVulns.length > 0 ? (
                <div className="space-y-2 max-h-48 overflow-y-auto">
                  {openVulns.slice(0, 5).map(v => (
                    <div key={v.id} className="flex items-center justify-between text-sm bg-[#081225] rounded-lg px-3 py-2">
                      <span className="text-gray-300">{v.vuln_type}</span>
                      <span className={`px-2 py-0.5 rounded text-xs ${
                        v.severity?.toUpperCase() === 'CRITICAL' ? 'bg-red-500/20 text-red-400' :
                        v.severity?.toUpperCase() === 'HIGH' ? 'bg-orange-500/20 text-orange-400' :
                        'bg-yellow-500/20 text-yellow-400'
                      }`}>{v.severity}</span>
                    </div>
                  ))}
                  {openVulns.length > 5 && (
                    <p className="text-gray-500 text-xs text-center">+{openVulns.length - 5} more pending</p>
                  )}
                </div>
              ) : (
                <div className="text-center py-4">
                  <Award className="w-10 h-10 text-green-400 mx-auto mb-2" />
                  <p className="text-green-400 text-sm font-medium">All vulnerabilities fixed! 🎉</p>
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* No Scan Selected */}
      {!selectedScan && (
        <div className="bg-gradient-to-br from-[#0d1f3c] to-[#0a1628] rounded-2xl p-12 border border-gray-700 text-center">
          <div className="w-20 h-20 rounded-full bg-purple-500/20 flex items-center justify-center mx-auto mb-4">
            <FileText className="w-10 h-10 text-purple-400" />
          </div>
          <h3 className="text-white text-xl font-medium mb-2">Select a Scan to Generate Report</h3>
          <p className="text-gray-500 max-w-md mx-auto">
            Choose a completed security scan from the dropdown above to generate a professional 
            assessment report with executive summary, findings, and recommendations.
          </p>
        </div>
      )}
    </div>
  );
}
