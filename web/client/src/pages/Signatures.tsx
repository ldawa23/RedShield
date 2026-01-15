import { useState } from 'react';
import {
  FileCode,
  Search,
  Shield,
  AlertTriangle,
  ChevronDown,
  ChevronRight,
  CheckCircle,
  Info,
  Target,
  BookOpen
} from 'lucide-react';

interface Signature {
  id: string;
  name: string;
  description: string;
  severity: 'Critical' | 'High' | 'Medium' | 'Low';
  category: string;
  mitre_technique: string;
  tags: string[];
  enabled: boolean;
  detection_type: string;
  remediation: {
    description: string;
    playbook: string;
    manual_steps: string[];
  };
}

interface SignatureStats {
  total: number;
  by_severity: Record<string, number>;
  by_category: Record<string, number>;
  enabled: number;
  disabled: number;
}

// Mock data for signatures (matches CLI signatures)
const mockSignatures: Signature[] = [
  {
    id: 'RS-DB-001',
    name: 'Exposed MongoDB',
    description: 'MongoDB database exposed without authentication',
    severity: 'Critical',
    category: 'A01:2021-Broken Access Control',
    mitre_technique: 'T1190',
    tags: ['database', 'mongodb', 'nosql', 'exposure'],
    enabled: true,
    detection_type: 'port',
    remediation: {
      description: 'Enable authentication and bind to localhost',
      playbook: 'fix_exposed_database.yml',
      manual_steps: [
        'Enable authentication in mongod.conf',
        'Bind to 127.0.0.1 or internal network only',
        'Configure firewall rules'
      ]
    }
  },
  {
    id: 'RS-DB-002',
    name: 'Exposed MySQL',
    description: 'MySQL database exposed to external connections',
    severity: 'Critical',
    category: 'A01:2021-Broken Access Control',
    mitre_technique: 'T1190',
    tags: ['database', 'mysql', 'sql', 'exposure'],
    enabled: true,
    detection_type: 'port',
    remediation: {
      description: 'Restrict MySQL to localhost and use strong credentials',
      playbook: 'fix_exposed_database.yml',
      manual_steps: [
        'Set bind-address to 127.0.0.1',
        'Remove anonymous users',
        'Set strong root password'
      ]
    }
  },
  {
    id: 'RS-DB-003',
    name: 'Exposed PostgreSQL',
    description: 'PostgreSQL database exposed without proper access control',
    severity: 'Critical',
    category: 'A01:2021-Broken Access Control',
    mitre_technique: 'T1190',
    tags: ['database', 'postgresql', 'sql', 'exposure'],
    enabled: true,
    detection_type: 'port',
    remediation: {
      description: 'Configure pg_hba.conf and restrict network access',
      playbook: 'fix_exposed_database.yml',
      manual_steps: [
        'Edit pg_hba.conf to restrict connections',
        'Set listen_addresses in postgresql.conf',
        'Use SSL for connections'
      ]
    }
  },
  {
    id: 'RS-DB-004',
    name: 'Exposed Redis',
    description: 'Redis instance exposed without authentication',
    severity: 'Critical',
    category: 'A01:2021-Broken Access Control',
    mitre_technique: 'T1190',
    tags: ['database', 'redis', 'cache', 'exposure'],
    enabled: true,
    detection_type: 'port',
    remediation: {
      description: 'Enable Redis authentication and bind to localhost',
      playbook: 'fix_exposed_database.yml',
      manual_steps: [
        'Set requirepass in redis.conf',
        'Bind to 127.0.0.1',
        'Disable dangerous commands'
      ]
    }
  },
  {
    id: 'RS-SSH-001',
    name: 'SSH with Password Authentication',
    description: 'SSH server allows password authentication (prefer key-based)',
    severity: 'High',
    category: 'A07:2021-Identification and Authentication Failures',
    mitre_technique: 'T1110',
    tags: ['ssh', 'authentication', 'hardening'],
    enabled: true,
    detection_type: 'banner',
    remediation: {
      description: 'Disable password authentication, use SSH keys only',
      playbook: 'fix_ssh_hardening.yml',
      manual_steps: [
        'Set PasswordAuthentication no in sshd_config',
        'Set up SSH key authentication',
        'Restart SSH service'
      ]
    }
  },
  {
    id: 'RS-HTTP-001',
    name: 'Unencrypted HTTP Service',
    description: 'Web service running without HTTPS encryption',
    severity: 'Medium',
    category: 'A02:2021-Cryptographic Failures',
    mitre_technique: 'T1557',
    tags: ['http', 'encryption', 'ssl', 'tls'],
    enabled: true,
    detection_type: 'port',
    remediation: {
      description: 'Enable HTTPS with valid SSL/TLS certificate',
      playbook: 'fix_enable_https.yml',
      manual_steps: [
        'Obtain SSL certificate (Let\'s Encrypt)',
        'Configure web server for HTTPS',
        'Redirect HTTP to HTTPS'
      ]
    }
  },
  {
    id: 'RS-SQLI-001',
    name: 'SQL Injection',
    description: 'Application is vulnerable to SQL injection attacks',
    severity: 'Critical',
    category: 'A03:2021-Injection',
    mitre_technique: 'T1190',
    tags: ['injection', 'sql', 'database', 'owasp-top-10'],
    enabled: true,
    detection_type: 'http',
    remediation: {
      description: 'Use parameterized queries and input validation',
      playbook: 'fix_sql_injection.yml',
      manual_steps: [
        'Use prepared statements/parameterized queries',
        'Implement input validation',
        'Apply principle of least privilege to DB accounts'
      ]
    }
  },
  {
    id: 'RS-XSS-001',
    name: 'Cross-Site Scripting (XSS)',
    description: 'Application is vulnerable to XSS attacks',
    severity: 'High',
    category: 'A03:2021-Injection',
    mitre_technique: 'T1059.007',
    tags: ['xss', 'injection', 'javascript', 'owasp-top-10'],
    enabled: true,
    detection_type: 'http',
    remediation: {
      description: 'Implement output encoding and Content Security Policy',
      playbook: 'fix_xss.yml',
      manual_steps: [
        'Encode all user output',
        'Implement Content Security Policy headers',
        'Use HTTPOnly and Secure cookie flags'
      ]
    }
  },
  {
    id: 'RS-CMD-001',
    name: 'Command Injection',
    description: 'Application allows OS command injection',
    severity: 'Critical',
    category: 'A03:2021-Injection',
    mitre_technique: 'T1059',
    tags: ['injection', 'command', 'rce', 'owasp-top-10'],
    enabled: true,
    detection_type: 'http',
    remediation: {
      description: 'Avoid shell commands, use safe APIs',
      playbook: 'fix_command_injection.yml',
      manual_steps: [
        'Avoid using shell commands in application code',
        'Use language-specific safe APIs',
        'Implement strict input validation'
      ]
    }
  },
  {
    id: 'RS-CRED-001',
    name: 'Default Credentials',
    description: 'Service running with default or weak credentials',
    severity: 'Critical',
    category: 'A07:2021-Identification and Authentication Failures',
    mitre_technique: 'T1078.001',
    tags: ['credentials', 'authentication', 'default-password'],
    enabled: true,
    detection_type: 'credential',
    remediation: {
      description: 'Change all default credentials immediately',
      playbook: 'fix_default_credentials.yml',
      manual_steps: [
        'Change all default passwords',
        'Implement strong password policy',
        'Enable account lockout'
      ]
    }
  },
  {
    id: 'RS-VER-001',
    name: 'Outdated Software Version',
    description: 'Service running outdated version with known vulnerabilities',
    severity: 'High',
    category: 'A06:2021-Vulnerable and Outdated Components',
    mitre_technique: 'T1190',
    tags: ['outdated', 'version', 'patch', 'update'],
    enabled: true,
    detection_type: 'version',
    remediation: {
      description: 'Update to the latest stable version',
      playbook: 'fix_outdated_software.yml',
      manual_steps: [
        'Check vendor website for latest version',
        'Review changelog for security fixes',
        'Plan and execute update procedure'
      ]
    }
  }
];

export default function Signatures() {
  const [signatures, setSignatures] = useState<Signature[]>(mockSignatures);
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedSeverity, setSelectedSeverity] = useState<string>('all');
  const [selectedCategory, setSelectedCategory] = useState<string>('all');
  const [expandedSignature, setExpandedSignature] = useState<string | null>(null);
  const [viewMode, setViewMode] = useState<'list' | 'owasp' | 'mitre'>('list');

  // Calculate statistics
  const stats: SignatureStats = {
    total: signatures.length,
    by_severity: signatures.reduce((acc, sig) => {
      acc[sig.severity] = (acc[sig.severity] || 0) + 1;
      return acc;
    }, {} as Record<string, number>),
    by_category: signatures.reduce((acc, sig) => {
      const cat = sig.category.split('-')[0];
      acc[cat] = (acc[cat] || 0) + 1;
      return acc;
    }, {} as Record<string, number>),
    enabled: signatures.filter(s => s.enabled).length,
    disabled: signatures.filter(s => !s.enabled).length
  };

  // Get unique categories
  const categories = [...new Set(signatures.map(s => s.category))];

  // Filter signatures
  const filteredSignatures = signatures.filter(sig => {
    const matchesSearch = searchQuery === '' || 
      sig.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      sig.description.toLowerCase().includes(searchQuery.toLowerCase()) ||
      sig.tags.some(t => t.toLowerCase().includes(searchQuery.toLowerCase()));
    const matchesSeverity = selectedSeverity === 'all' || sig.severity === selectedSeverity;
    const matchesCategory = selectedCategory === 'all' || sig.category === selectedCategory;
    return matchesSearch && matchesSeverity && matchesCategory;
  });

  // Group by OWASP
  const owaspGroups = signatures.reduce((acc, sig) => {
    const category = sig.category;
    if (!acc[category]) acc[category] = [];
    acc[category].push(sig);
    return acc;
  }, {} as Record<string, Signature[]>);

  // Group by MITRE
  const mitreGroups = signatures.reduce((acc, sig) => {
    const technique = sig.mitre_technique;
    if (!acc[technique]) acc[technique] = [];
    acc[technique].push(sig);
    return acc;
  }, {} as Record<string, Signature[]>);

  const toggleSignature = async (id: string) => {
    setSignatures(prev => prev.map(sig => 
      sig.id === id ? { ...sig, enabled: !sig.enabled } : sig
    ));
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

  const getDetectionIcon = (type: string) => {
    switch (type) {
      case 'port': return Target;
      case 'banner': return FileCode;
      case 'http': return Shield;
      case 'credential': return AlertTriangle;
      case 'version': return Info;
      default: return FileCode;
    }
  };

  return (
    <div className="p-8">
      {/* Header */}
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-white mb-2">Vulnerability Signatures</h1>
        <p className="text-gray-400">Manage detection signatures for vulnerability scanning</p>
      </div>

      {/* Statistics Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-8">
        <div className="bg-[#1a1a2e] rounded-xl p-4 border border-gray-800">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 bg-blue-500/20 rounded-lg flex items-center justify-center">
              <FileCode className="w-5 h-5 text-blue-400" />
            </div>
            <div>
              <p className="text-2xl font-bold text-white">{stats.total}</p>
              <p className="text-gray-400 text-sm">Total Signatures</p>
            </div>
          </div>
        </div>
        <div className="bg-[#1a1a2e] rounded-xl p-4 border border-gray-800">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 bg-red-500/20 rounded-lg flex items-center justify-center">
              <AlertTriangle className="w-5 h-5 text-red-400" />
            </div>
            <div>
              <p className="text-2xl font-bold text-white">{stats.by_severity['Critical'] || 0}</p>
              <p className="text-gray-400 text-sm">Critical</p>
            </div>
          </div>
        </div>
        <div className="bg-[#1a1a2e] rounded-xl p-4 border border-gray-800">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 bg-green-500/20 rounded-lg flex items-center justify-center">
              <CheckCircle className="w-5 h-5 text-green-400" />
            </div>
            <div>
              <p className="text-2xl font-bold text-white">{stats.enabled}</p>
              <p className="text-gray-400 text-sm">Enabled</p>
            </div>
          </div>
        </div>
        <div className="bg-[#1a1a2e] rounded-xl p-4 border border-gray-800">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 bg-purple-500/20 rounded-lg flex items-center justify-center">
              <BookOpen className="w-5 h-5 text-purple-400" />
            </div>
            <div>
              <p className="text-2xl font-bold text-white">{Object.keys(owaspGroups).length}</p>
              <p className="text-gray-400 text-sm">OWASP Categories</p>
            </div>
          </div>
        </div>
      </div>

      {/* View Mode Tabs */}
      <div className="flex gap-2 mb-6">
        <button
          onClick={() => setViewMode('list')}
          className={`px-4 py-2 rounded-lg font-medium transition-colors ${
            viewMode === 'list' 
              ? 'bg-red-500 text-white' 
              : 'bg-gray-800 text-gray-400 hover:bg-gray-700'
          }`}
        >
          All Signatures
        </button>
        <button
          onClick={() => setViewMode('owasp')}
          className={`px-4 py-2 rounded-lg font-medium transition-colors ${
            viewMode === 'owasp' 
              ? 'bg-red-500 text-white' 
              : 'bg-gray-800 text-gray-400 hover:bg-gray-700'
          }`}
        >
          OWASP Top 10
        </button>
        <button
          onClick={() => setViewMode('mitre')}
          className={`px-4 py-2 rounded-lg font-medium transition-colors ${
            viewMode === 'mitre' 
              ? 'bg-red-500 text-white' 
              : 'bg-gray-800 text-gray-400 hover:bg-gray-700'
          }`}
        >
          MITRE ATT&CK
        </button>
      </div>

      {/* Filters */}
      {viewMode === 'list' && (
        <div className="flex flex-wrap gap-4 mb-6">
          <div className="relative flex-1 min-w-[200px]">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-500" />
            <input
              type="text"
              placeholder="Search signatures..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full bg-[#1a1a2e] border border-gray-700 rounded-lg pl-10 pr-4 py-2 text-white placeholder-gray-500 focus:border-red-500 focus:outline-none"
            />
          </div>
          <select
            value={selectedSeverity}
            onChange={(e) => setSelectedSeverity(e.target.value)}
            className="bg-[#1a1a2e] border border-gray-700 rounded-lg px-4 py-2 text-white focus:border-red-500 focus:outline-none"
          >
            <option value="all">All Severities</option>
            <option value="Critical">Critical</option>
            <option value="High">High</option>
            <option value="Medium">Medium</option>
            <option value="Low">Low</option>
          </select>
          <select
            value={selectedCategory}
            onChange={(e) => setSelectedCategory(e.target.value)}
            className="bg-[#1a1a2e] border border-gray-700 rounded-lg px-4 py-2 text-white focus:border-red-500 focus:outline-none"
          >
            <option value="all">All Categories</option>
            {categories.map(cat => (
              <option key={cat} value={cat}>{cat}</option>
            ))}
          </select>
        </div>
      )}

      {/* List View */}
      {viewMode === 'list' && (
        <div className="space-y-3">
          {filteredSignatures.map(sig => {
            const DetectionIcon = getDetectionIcon(sig.detection_type);
            const isExpanded = expandedSignature === sig.id;
            
            return (
              <div 
                key={sig.id}
                className={`bg-[#1a1a2e] rounded-xl border transition-all ${
                  sig.enabled ? 'border-gray-800' : 'border-gray-800/50 opacity-60'
                }`}
              >
                <div 
                  className="p-4 cursor-pointer"
                  onClick={() => setExpandedSignature(isExpanded ? null : sig.id)}
                >
                  <div className="flex items-center gap-4">
                    <div className={`w-10 h-10 rounded-lg flex items-center justify-center ${getSeverityColor(sig.severity)}`}>
                      <DetectionIcon className="w-5 h-5" />
                    </div>
                    <div className="flex-1">
                      <div className="flex items-center gap-2">
                        <span className="text-gray-500 font-mono text-sm">{sig.id}</span>
                        <h3 className="text-white font-medium">{sig.name}</h3>
                        <span className={`px-2 py-0.5 rounded text-xs font-medium ${getSeverityColor(sig.severity)}`}>
                          {sig.severity}
                        </span>
                      </div>
                      <p className="text-gray-400 text-sm mt-1">{sig.description}</p>
                    </div>
                    <div className="flex items-center gap-3">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          toggleSignature(sig.id);
                        }}
                        className={`px-3 py-1 rounded-lg text-sm font-medium transition-colors ${
                          sig.enabled 
                            ? 'bg-green-500/20 text-green-400 hover:bg-green-500/30' 
                            : 'bg-gray-700 text-gray-400 hover:bg-gray-600'
                        }`}
                      >
                        {sig.enabled ? 'Enabled' : 'Disabled'}
                      </button>
                      {isExpanded ? (
                        <ChevronDown className="w-5 h-5 text-gray-400" />
                      ) : (
                        <ChevronRight className="w-5 h-5 text-gray-400" />
                      )}
                    </div>
                  </div>
                </div>

                {isExpanded && (
                  <div className="px-4 pb-4 border-t border-gray-800 pt-4">
                    <div className="grid grid-cols-2 gap-6">
                      <div>
                        <h4 className="text-gray-400 text-sm font-medium mb-2">Detection Details</h4>
                        <div className="space-y-2 text-sm">
                          <p><span className="text-gray-500">Type:</span> <span className="text-white capitalize">{sig.detection_type}</span></p>
                          <p><span className="text-gray-500">OWASP:</span> <span className="text-white">{sig.category}</span></p>
                          <p><span className="text-gray-500">MITRE:</span> <span className="text-white">{sig.mitre_technique}</span></p>
                        </div>
                        <div className="flex flex-wrap gap-2 mt-3">
                          {sig.tags.map(tag => (
                            <span key={tag} className="px-2 py-1 bg-gray-800 text-gray-400 rounded text-xs">
                              {tag}
                            </span>
                          ))}
                        </div>
                      </div>
                      <div>
                        <h4 className="text-gray-400 text-sm font-medium mb-2">Remediation</h4>
                        <p className="text-white text-sm mb-2">{sig.remediation.description}</p>
                        <p className="text-sm"><span className="text-gray-500">Playbook:</span> <span className="text-cyan-400 font-mono">{sig.remediation.playbook}</span></p>
                        <div className="mt-3">
                          <p className="text-gray-500 text-xs mb-1">Manual Steps:</p>
                          <ol className="list-decimal list-inside text-sm text-gray-300 space-y-1">
                            {sig.remediation.manual_steps.map((step, i) => (
                              <li key={i}>{step}</li>
                            ))}
                          </ol>
                        </div>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}

      {/* OWASP View */}
      {viewMode === 'owasp' && (
        <div className="space-y-6">
          {Object.entries(owaspGroups).sort().map(([category, sigs]) => (
            <div key={category} className="bg-[#1a1a2e] rounded-xl border border-gray-800 overflow-hidden">
              <div className="p-4 bg-gradient-to-r from-purple-500/10 to-transparent border-b border-gray-800">
                <h3 className="text-white font-medium">{category}</h3>
                <p className="text-gray-400 text-sm">{sigs.length} signature(s)</p>
              </div>
              <div className="p-4 space-y-2">
                {sigs.map(sig => (
                  <div key={sig.id} className="flex items-center gap-3 p-3 bg-gray-800/30 rounded-lg">
                    <span className={`px-2 py-0.5 rounded text-xs font-medium ${getSeverityColor(sig.severity)}`}>
                      {sig.severity}
                    </span>
                    <span className="text-gray-500 font-mono text-sm">{sig.id}</span>
                    <span className="text-white">{sig.name}</span>
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
      )}

      {/* MITRE View */}
      {viewMode === 'mitre' && (
        <div className="space-y-6">
          {Object.entries(mitreGroups).sort().map(([technique, sigs]) => (
            <div key={technique} className="bg-[#1a1a2e] rounded-xl border border-gray-800 overflow-hidden">
              <div className="p-4 bg-gradient-to-r from-red-500/10 to-transparent border-b border-gray-800">
                <h3 className="text-white font-medium font-mono">{technique}</h3>
                <p className="text-gray-400 text-sm">{sigs.length} signature(s)</p>
              </div>
              <div className="p-4 space-y-2">
                {sigs.map(sig => (
                  <div key={sig.id} className="flex items-center gap-3 p-3 bg-gray-800/30 rounded-lg">
                    <span className={`px-2 py-0.5 rounded text-xs font-medium ${getSeverityColor(sig.severity)}`}>
                      {sig.severity}
                    </span>
                    <span className="text-gray-500 font-mono text-sm">{sig.id}</span>
                    <span className="text-white">{sig.name}</span>
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
