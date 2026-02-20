import { useState, useEffect } from 'react';
import {
  Target,
  Search,
  Scan,
  Bug,
  Skull,
  Shield,
  FileText,
  ChevronRight,
  CheckCircle,
  Crosshair,
  Globe
} from 'lucide-react';
import api from '../services/api';

// Red Team Kill Chain Phases
const KILL_CHAIN_PHASES = [
  {
    id: 'reconnaissance',
    name: 'Reconnaissance',
    icon: Search,
    color: 'blue',
    description: 'Gather information about the target',
    techniques: [
      { name: 'Port Scanning', tool: 'Nmap', mitre: 'T1046' },
      { name: 'Service Detection', tool: 'Nmap', mitre: 'T1046' },
      { name: 'OS Fingerprinting', tool: 'Nmap', mitre: 'T1082' },
      { name: 'Web Crawling', tool: 'Nuclei', mitre: 'T1595' },
      { name: 'DNS Enumeration', tool: 'Nmap', mitre: 'T1590' },
    ]
  },
  {
    id: 'scanning',
    name: 'Vulnerability Scanning',
    icon: Scan,
    color: 'cyan',
    description: 'Identify security weaknesses',
    techniques: [
      { name: 'Web Vulnerability Scan', tool: 'Nuclei/ZAP', mitre: 'T1595.002' },
      { name: 'CVE Detection', tool: 'Nuclei', mitre: 'T1595.002' },
      { name: 'Misconfiguration Check', tool: 'Nuclei', mitre: 'T1595.002' },
      { name: 'SSL/TLS Analysis', tool: 'Nmap', mitre: 'T1590.001' },
      { name: 'Authentication Testing', tool: 'ZAP', mitre: 'T1110' },
    ]
  },
  {
    id: 'exploitation',
    name: 'Exploitation',
    icon: Skull,
    color: 'red',
    description: 'Exploit discovered vulnerabilities',
    techniques: [
      { name: 'SQL Injection', tool: 'Metasploit', mitre: 'T1190' },
      { name: 'XSS Exploitation', tool: 'Manual/Burp', mitre: 'T1189' },
      { name: 'Command Injection', tool: 'Metasploit', mitre: 'T1059' },
      { name: 'Credential Attacks', tool: 'Metasploit', mitre: 'T1110' },
      { name: 'Known CVE Exploits', tool: 'Metasploit', mitre: 'T1190' },
    ]
  },
  {
    id: 'post-exploitation',
    name: 'Post-Exploitation',
    icon: Crosshair,
    color: 'purple',
    description: 'Assess impact and gather evidence',
    techniques: [
      { name: 'Privilege Escalation', tool: 'Metasploit', mitre: 'T1068' },
      { name: 'Data Exfiltration Test', tool: 'Manual', mitre: 'T1041' },
      { name: 'Lateral Movement', tool: 'Metasploit', mitre: 'T1021' },
      { name: 'Persistence Check', tool: 'Manual', mitre: 'T1547' },
      { name: 'Impact Assessment', tool: 'RedShield', mitre: 'T1486' },
    ]
  },
  {
    id: 'remediation',
    name: 'Remediation',
    icon: Shield,
    color: 'green',
    description: 'Fix and harden the system',
    techniques: [
      { name: 'Patch Vulnerabilities', tool: 'Ansible', mitre: 'M1051' },
      { name: 'Harden Configuration', tool: 'Ansible', mitre: 'M1028' },
      { name: 'Update Credentials', tool: 'Ansible', mitre: 'M1027' },
      { name: 'Firewall Rules', tool: 'Ansible', mitre: 'M1037' },
      { name: 'Verification Retest', tool: 'RedShield', mitre: 'M1016' },
    ]
  },
  {
    id: 'reporting',
    name: 'Reporting',
    icon: FileText,
    color: 'yellow',
    description: 'Generate comprehensive reports',
    techniques: [
      { name: 'Executive Summary', tool: 'RedShield', mitre: '-' },
      { name: 'Technical Details', tool: 'RedShield', mitre: '-' },
      { name: 'CVSS Scoring', tool: 'RedShield', mitre: '-' },
      { name: 'Remediation Guide', tool: 'RedShield', mitre: '-' },
      { name: 'PDF/HTML Export', tool: 'RedShield', mitre: '-' },
    ]
  }
];

// MITRE ATT&CK Tactics
const MITRE_TACTICS = [
  { id: 'TA0043', name: 'Reconnaissance', color: 'blue' },
  { id: 'TA0042', name: 'Resource Development', color: 'indigo' },
  { id: 'TA0001', name: 'Initial Access', color: 'red' },
  { id: 'TA0002', name: 'Execution', color: 'orange' },
  { id: 'TA0003', name: 'Persistence', color: 'yellow' },
  { id: 'TA0004', name: 'Privilege Escalation', color: 'amber' },
  { id: 'TA0005', name: 'Defense Evasion', color: 'lime' },
  { id: 'TA0006', name: 'Credential Access', color: 'green' },
  { id: 'TA0007', name: 'Discovery', color: 'teal' },
  { id: 'TA0008', name: 'Lateral Movement', color: 'cyan' },
  { id: 'TA0009', name: 'Collection', color: 'sky' },
  { id: 'TA0011', name: 'Command and Control', color: 'violet' },
  { id: 'TA0010', name: 'Exfiltration', color: 'purple' },
  { id: 'TA0040', name: 'Impact', color: 'pink' },
];

// OWASP Top 10 2021
const OWASP_TOP_10 = [
  { id: 'A01', name: 'Broken Access Control', severity: 'critical', description: 'Restrictions on authenticated users not properly enforced' },
  { id: 'A02', name: 'Cryptographic Failures', severity: 'critical', description: 'Failures related to cryptography leading to sensitive data exposure' },
  { id: 'A03', name: 'Injection', severity: 'critical', description: 'SQL, NoSQL, OS, LDAP injection vulnerabilities' },
  { id: 'A04', name: 'Insecure Design', severity: 'high', description: 'Missing or ineffective security controls' },
  { id: 'A05', name: 'Security Misconfiguration', severity: 'high', description: 'Insecure default configurations, incomplete setups' },
  { id: 'A06', name: 'Vulnerable Components', severity: 'high', description: 'Using components with known vulnerabilities' },
  { id: 'A07', name: 'Authentication Failures', severity: 'critical', description: 'Broken authentication and session management' },
  { id: 'A08', name: 'Software & Data Integrity', severity: 'high', description: 'Code and infrastructure without integrity verification' },
  { id: 'A09', name: 'Logging & Monitoring Failures', severity: 'medium', description: 'Insufficient logging, detection, and response' },
  { id: 'A10', name: 'Server-Side Request Forgery', severity: 'high', description: 'SSRF flaws when fetching remote resources' },
];

interface ScanStats {
  total_scans: number;
  total_vulns: number;
  fixed_vulns: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
}

export default function AttackFlow() {
  const [activePhase, setActivePhase] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<'killchain' | 'mitre' | 'owasp'>('killchain');
  const [stats, setStats] = useState<ScanStats | null>(null);
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  const [_recentScans, setRecentScans] = useState<any[]>([]);

  useEffect(() => {
    loadStats();
  }, []);

  const loadStats = async () => {
    try {
      const response = await api.get('/stats');
      setStats(response.data);
      const scansRes = await api.get('/scans');
      setRecentScans(scansRes.data.scans?.slice(0, 3) || []);
    } catch (err) {
      console.error('Failed to load stats:', err);
    }
  };

  const getPhaseStatus = (phaseId: string) => {
    if (!stats) return 'pending';
    switch (phaseId) {
      case 'reconnaissance':
      case 'scanning':
        return stats.total_scans > 0 ? 'complete' : 'pending';
      case 'exploitation':
        return stats.total_vulns > 0 ? 'complete' : 'pending';
      case 'post-exploitation':
        return stats.critical > 0 || stats.high > 0 ? 'complete' : 'pending';
      case 'remediation':
        return stats.fixed_vulns > 0 ? 'complete' : 'pending';
      case 'reporting':
        return stats.total_scans > 0 ? 'complete' : 'pending';
      default:
        return 'pending';
    }
  };

  const getColorClasses = (color: string) => {
    const colors: Record<string, string> = {
      blue: 'bg-blue-500/20 border-blue-500 text-blue-400',
      cyan: 'bg-cyan-500/20 border-cyan-500 text-cyan-400',
      red: 'bg-red-500/20 border-red-500 text-red-400',
      purple: 'bg-purple-500/20 border-purple-500 text-purple-400',
      green: 'bg-green-500/20 border-green-500 text-green-400',
      yellow: 'bg-yellow-500/20 border-yellow-500 text-yellow-400',
      orange: 'bg-orange-500/20 border-orange-500 text-orange-400',
      indigo: 'bg-indigo-500/20 border-indigo-500 text-indigo-400',
      amber: 'bg-amber-500/20 border-amber-500 text-amber-400',
      lime: 'bg-lime-500/20 border-lime-500 text-lime-400',
      teal: 'bg-teal-500/20 border-teal-500 text-teal-400',
      sky: 'bg-sky-500/20 border-sky-500 text-sky-400',
      violet: 'bg-violet-500/20 border-violet-500 text-violet-400',
      pink: 'bg-pink-500/20 border-pink-500 text-pink-400',
    };
    return colors[color] || colors.blue;
  };

  return (
    <div className="p-6 min-h-full">
      {/* Header */}
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-white flex items-center gap-3 mb-2">
          <div className="w-12 h-12 rounded-xl bg-gradient-to-br from-red-500 to-purple-600 flex items-center justify-center">
            <Target className="w-7 h-7 text-white" />
          </div>
          Red Team Attack Flow
        </h1>
        <p className="text-gray-400 text-lg">
          Visualize the complete red team methodology with MITRE ATT&CK and OWASP Top 10 mapping
        </p>
      </div>

      {/* Tab Navigation */}
      <div className="flex gap-2 mb-6">
        {[
          { id: 'killchain', label: 'Kill Chain', icon: Target },
          { id: 'mitre', label: 'MITRE ATT&CK', icon: Crosshair },
          { id: 'owasp', label: 'OWASP Top 10', icon: Globe },
        ].map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id as any)}
            className={`px-5 py-3 rounded-xl font-medium transition-all flex items-center gap-2 ${
              activeTab === tab.id
                ? 'bg-blue-500 text-white'
                : 'bg-[#0d1f3c] text-gray-400 hover:bg-[#142744] hover:text-white border border-gray-700'
            }`}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {/* Kill Chain View */}
      {activeTab === 'killchain' && (
        <div className="space-y-6">
          {/* Kill Chain Flow */}
          <div className="bg-gradient-to-br from-[#0d1f3c] to-[#0a1628] rounded-2xl p-6 border border-gray-700">
            <h2 className="text-xl font-bold text-white mb-6 flex items-center gap-2">
              <Target className="w-6 h-6 text-red-400" />
              Red Team Kill Chain
            </h2>
            
            <div className="flex items-center justify-between overflow-x-auto pb-4">
              {KILL_CHAIN_PHASES.map((phase, index) => {
                const status = getPhaseStatus(phase.id);
                const Icon = phase.icon;
                return (
                  <div key={phase.id} className="flex items-center">
                    <button
                      onClick={() => setActivePhase(activePhase === phase.id ? null : phase.id)}
                      className={`flex flex-col items-center p-4 rounded-xl border-2 transition-all min-w-[140px] ${
                        activePhase === phase.id
                          ? getColorClasses(phase.color)
                          : 'bg-[#081225] border-gray-700 hover:border-gray-500'
                      }`}
                    >
                      <div className={`w-12 h-12 rounded-xl flex items-center justify-center mb-2 ${
                        status === 'complete' ? 'bg-green-500/20' : 'bg-gray-700/50'
                      }`}>
                        {status === 'complete' ? (
                          <CheckCircle className="w-6 h-6 text-green-400" />
                        ) : (
                          <Icon className={`w-6 h-6 ${activePhase === phase.id ? '' : 'text-gray-400'}`} />
                        )}
                      </div>
                      <span className={`font-medium text-sm text-center ${
                        activePhase === phase.id ? '' : 'text-gray-300'
                      }`}>
                        {phase.name}
                      </span>
                      <span className={`text-xs mt-1 ${
                        status === 'complete' ? 'text-green-400' : 'text-gray-500'
                      }`}>
                        {status === 'complete' ? 'Completed' : 'Pending'}
                      </span>
                    </button>
                    {index < KILL_CHAIN_PHASES.length - 1 && (
                      <ChevronRight className="w-6 h-6 text-gray-600 mx-2 flex-shrink-0" />
                    )}
                  </div>
                );
              })}
            </div>
          </div>

          {/* Phase Details */}
          {activePhase && (
            <div className="bg-gradient-to-br from-[#0d1f3c] to-[#0a1628] rounded-2xl p-6 border border-gray-700">
              {(() => {
                const phase = KILL_CHAIN_PHASES.find(p => p.id === activePhase);
                if (!phase) return null;
                const Icon = phase.icon;
                return (
                  <>
                    <div className="flex items-center gap-3 mb-4">
                      <div className={`w-10 h-10 rounded-lg flex items-center justify-center ${getColorClasses(phase.color)}`}>
                        <Icon className="w-5 h-5" />
                      </div>
                      <div>
                        <h3 className="text-lg font-bold text-white">{phase.name}</h3>
                        <p className="text-gray-400 text-sm">{phase.description}</p>
                      </div>
                    </div>
                    
                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
                      {phase.techniques.map((tech, idx) => (
                        <div
                          key={idx}
                          className="bg-[#081225] rounded-xl p-4 border border-gray-700 hover:border-gray-600 transition-colors"
                        >
                          <div className="flex items-center justify-between mb-2">
                            <span className="text-white font-medium">{tech.name}</span>
                            <span className="text-xs px-2 py-1 bg-purple-500/20 text-purple-400 rounded">
                              {tech.mitre}
                            </span>
                          </div>
                          <p className="text-gray-500 text-sm">Tool: {tech.tool}</p>
                        </div>
                      ))}
                    </div>
                  </>
                );
              })()}
            </div>
          )}

          {/* Current Assessment Status */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="bg-gradient-to-br from-[#0d1f3c] to-[#0a1628] rounded-2xl p-5 border border-gray-700">
              <div className="flex items-center gap-3 mb-3">
                <Scan className="w-6 h-6 text-blue-400" />
                <h3 className="text-white font-semibold">Scans Completed</h3>
              </div>
              <p className="text-3xl font-bold text-blue-400">{stats?.total_scans || 0}</p>
              <p className="text-gray-500 text-sm mt-1">Total reconnaissance runs</p>
            </div>
            <div className="bg-gradient-to-br from-[#0d1f3c] to-[#0a1628] rounded-2xl p-5 border border-gray-700">
              <div className="flex items-center gap-3 mb-3">
                <Bug className="w-6 h-6 text-red-400" />
                <h3 className="text-white font-semibold">Vulnerabilities Found</h3>
              </div>
              <p className="text-3xl font-bold text-red-400">{stats?.total_vulns || 0}</p>
              <p className="text-gray-500 text-sm mt-1">Exploitable weaknesses</p>
            </div>
            <div className="bg-gradient-to-br from-[#0d1f3c] to-[#0a1628] rounded-2xl p-5 border border-gray-700">
              <div className="flex items-center gap-3 mb-3">
                <Shield className="w-6 h-6 text-green-400" />
                <h3 className="text-white font-semibold">Issues Remediated</h3>
              </div>
              <p className="text-3xl font-bold text-green-400">{stats?.fixed_vulns || 0}</p>
              <p className="text-gray-500 text-sm mt-1">Successfully fixed</p>
            </div>
          </div>
        </div>
      )}

      {/* MITRE ATT&CK View */}
      {activeTab === 'mitre' && (
        <div className="space-y-6">
          <div className="bg-gradient-to-br from-[#0d1f3c] to-[#0a1628] rounded-2xl p-6 border border-gray-700">
            <h2 className="text-xl font-bold text-white mb-2 flex items-center gap-2">
              <Crosshair className="w-6 h-6 text-red-400" />
              MITRE ATT&CK Framework Mapping
            </h2>
            <p className="text-gray-400 mb-6">
              Vulnerabilities mapped to MITRE ATT&CK tactics and techniques for threat intelligence
            </p>

            <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-7 gap-3">
              {MITRE_TACTICS.map((tactic) => (
                <div
                  key={tactic.id}
                  className={`rounded-xl p-4 border-2 transition-all hover:scale-105 cursor-pointer ${getColorClasses(tactic.color)}`}
                >
                  <p className="text-xs opacity-70 mb-1">{tactic.id}</p>
                  <p className="font-medium text-sm">{tactic.name}</p>
                </div>
              ))}
            </div>
          </div>

          {/* Technique Examples */}
          <div className="bg-gradient-to-br from-[#0d1f3c] to-[#0a1628] rounded-2xl p-6 border border-gray-700">
            <h3 className="text-lg font-bold text-white mb-4">Common Techniques Detected by RedShield</h3>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {[
                { id: 'T1190', name: 'Exploit Public-Facing Application', tactic: 'Initial Access', examples: 'SQL Injection, XSS, RCE' },
                { id: 'T1110', name: 'Brute Force', tactic: 'Credential Access', examples: 'SSH, FTP, Web Login' },
                { id: 'T1046', name: 'Network Service Discovery', tactic: 'Discovery', examples: 'Port Scanning, Service Detection' },
                { id: 'T1059', name: 'Command and Scripting Interpreter', tactic: 'Execution', examples: 'Command Injection, Shell Upload' },
                { id: 'T1068', name: 'Exploitation for Privilege Escalation', tactic: 'Privilege Escalation', examples: 'Kernel Exploits, Misconfigurations' },
                { id: 'T1021', name: 'Remote Services', tactic: 'Lateral Movement', examples: 'SSH, RDP, SMB' },
              ].map((tech) => (
                <div key={tech.id} className="bg-[#081225] rounded-xl p-4 border border-gray-700">
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-purple-400 font-mono text-sm">{tech.id}</span>
                    <span className="text-xs px-2 py-1 bg-blue-500/20 text-blue-400 rounded">{tech.tactic}</span>
                  </div>
                  <h4 className="text-white font-medium mb-1">{tech.name}</h4>
                  <p className="text-gray-500 text-sm">Examples: {tech.examples}</p>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* OWASP Top 10 View */}
      {activeTab === 'owasp' && (
        <div className="space-y-6">
          <div className="bg-gradient-to-br from-[#0d1f3c] to-[#0a1628] rounded-2xl p-6 border border-gray-700">
            <h2 className="text-xl font-bold text-white mb-2 flex items-center gap-2">
              <Globe className="w-6 h-6 text-orange-400" />
              OWASP Top 10 - 2021
            </h2>
            <p className="text-gray-400 mb-6">
              Web application security risks that RedShield detects and remediates
            </p>

            <div className="space-y-3">
              {OWASP_TOP_10.map((item) => (
                <div
                  key={item.id}
                  className="bg-[#081225] rounded-xl p-4 border border-gray-700 hover:border-gray-600 transition-colors"
                >
                  <div className="flex items-center gap-4">
                    <div className={`w-12 h-12 rounded-xl flex items-center justify-center font-bold text-lg ${
                      item.severity === 'critical' ? 'bg-red-500/20 text-red-400' :
                      item.severity === 'high' ? 'bg-orange-500/20 text-orange-400' :
                      'bg-yellow-500/20 text-yellow-400'
                    }`}>
                      {item.id}
                    </div>
                    <div className="flex-1">
                      <div className="flex items-center gap-3 mb-1">
                        <h3 className="text-white font-semibold">{item.name}</h3>
                        <span className={`text-xs px-2 py-0.5 rounded ${
                          item.severity === 'critical' ? 'bg-red-500/20 text-red-400' :
                          item.severity === 'high' ? 'bg-orange-500/20 text-orange-400' :
                          'bg-yellow-500/20 text-yellow-400'
                        }`}>
                          {item.severity.toUpperCase()}
                        </span>
                      </div>
                      <p className="text-gray-400 text-sm">{item.description}</p>
                    </div>
                    <div className="flex items-center gap-2">
                      <CheckCircle className="w-5 h-5 text-green-400" />
                      <span className="text-green-400 text-sm">Detectable</span>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
