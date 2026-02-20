import { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import {
  ArrowLeft,
  Shield,
  AlertTriangle,
  CheckCircle,
  Clock,
  Target,
  Globe,
  Server,
  Bug,
  Wrench,
  FileText,
  ExternalLink,
  Copy,
  ChevronDown,
  ChevronRight,
  Loader2
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
  owasp_category?: string;
  mitre_id?: string;
  cve_id?: string;
  discovered_at: string;
  // Evidence fields
  vulnerable_url?: string;
  vulnerable_parameter?: string;
  http_method?: string;
  payload_used?: string;
  evidence?: string;
  request_example?: string;
  response_snippet?: string;
  affected_code?: string;
  remediation_code?: string;
}

interface Scan {
  id: number;
  scan_id: string;
  target: string;
  port_range: string;
  scan_type: string;
  status: string;
  started_at: string;
  completed_at: string;
}

interface ScanData {
  scan: Scan;
  vulnerabilities: Vulnerability[];
  stats: {
    total: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    fixed: number;
    open: number;
  };
}

export default function ScanDetails() {
  const { scanId } = useParams<{ scanId: string }>();
  const navigate = useNavigate();
  const [data, setData] = useState<ScanData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [expandedVuln, setExpandedVuln] = useState<number | null>(null);
  const [copiedId, setCopiedId] = useState<string | null>(null);

  useEffect(() => {
    fetchScanDetails();
  }, [scanId]);

  const fetchScanDetails = async () => {
    try {
      setLoading(true);
      const res = await api.get(`/scans/${scanId}`);
      setData(res.data);
    } catch (err: any) {
      setError(err.response?.data?.error || 'Failed to load scan details');
    } finally {
      setLoading(false);
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity?.toUpperCase()) {
      case 'CRITICAL': return { bg: 'bg-red-500/20', text: 'text-red-400', border: 'border-red-500' };
      case 'HIGH': return { bg: 'bg-orange-500/20', text: 'text-orange-400', border: 'border-orange-500' };
      case 'MEDIUM': return { bg: 'bg-yellow-500/20', text: 'text-yellow-400', border: 'border-yellow-500' };
      case 'LOW': return { bg: 'bg-blue-500/20', text: 'text-blue-400', border: 'border-blue-500' };
      default: return { bg: 'bg-gray-500/20', text: 'text-gray-400', border: 'border-gray-500' };
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'fixed': return 'bg-green-500/20 text-green-400';
      case 'in_progress': return 'bg-blue-500/20 text-blue-400';
      default: return 'bg-red-500/20 text-red-400';
    }
  };

  const formatDate = (dateStr: string) => {
    if (!dateStr) return 'N/A';
    try {
      return new Date(dateStr).toLocaleString();
    } catch {
      return dateStr;
    }
  };

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  if (loading) {
    return (
      <div className="p-6 flex items-center justify-center min-h-screen">
        <div className="text-center">
          <Loader2 className="w-12 h-12 text-blue-400 animate-spin mx-auto mb-4" />
          <p className="text-gray-400">Loading scan details...</p>
        </div>
      </div>
    );
  }

  if (error || !data) {
    return (
      <div className="p-6">
        <div className="bg-red-500/10 border border-red-500/30 rounded-xl p-8 text-center">
          <AlertTriangle className="w-12 h-12 text-red-400 mx-auto mb-4" />
          <h2 className="text-xl font-bold text-white mb-2">Scan Not Found</h2>
          <p className="text-gray-400 mb-4">{error || 'The requested scan could not be found.'}</p>
          <button
            onClick={() => navigate('/scans')}
            className="px-6 py-2 bg-blue-500 hover:bg-blue-600 text-white rounded-lg"
          >
            View All Scans
          </button>
        </div>
      </div>
    );
  }

  const { scan, vulnerabilities, stats } = data;

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          <button
            onClick={() => navigate('/scans')}
            className="p-2 hover:bg-gray-800 rounded-lg transition-colors"
          >
            <ArrowLeft className="w-5 h-5 text-gray-400" />
          </button>
          <div>
            <h1 className="text-2xl font-bold text-white flex items-center gap-3">
              <Shield className="w-8 h-8 text-blue-500" />
              Scan Results
            </h1>
            <p className="text-gray-400 mt-1">
              {scan.target} • {scan.scan_type} scan
            </p>
          </div>
        </div>
        <div className="flex items-center gap-3">
          <span className={`px-3 py-1 rounded-full text-sm font-medium ${
            scan.status === 'completed' ? 'bg-green-500/20 text-green-400' : 'bg-blue-500/20 text-blue-400'
          }`}>
            {scan.status}
          </span>
        </div>
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
        <div className="bg-[#0d1f3c] rounded-xl p-4 border border-gray-800">
          <p className="text-gray-400 text-sm">Total Found</p>
          <p className="text-3xl font-bold text-white">{stats.total}</p>
        </div>
        <div className="bg-red-500/10 rounded-xl p-4 border border-red-500/30">
          <p className="text-red-400 text-sm">Critical</p>
          <p className="text-3xl font-bold text-red-400">{stats.critical}</p>
        </div>
        <div className="bg-orange-500/10 rounded-xl p-4 border border-orange-500/30">
          <p className="text-orange-400 text-sm">High</p>
          <p className="text-3xl font-bold text-orange-400">{stats.high}</p>
        </div>
        <div className="bg-yellow-500/10 rounded-xl p-4 border border-yellow-500/30">
          <p className="text-yellow-400 text-sm">Medium</p>
          <p className="text-3xl font-bold text-yellow-400">{stats.medium}</p>
        </div>
        <div className="bg-blue-500/10 rounded-xl p-4 border border-blue-500/30">
          <p className="text-blue-400 text-sm">Low</p>
          <p className="text-3xl font-bold text-blue-400">{stats.low}</p>
        </div>
      </div>

      {/* Scan Info */}
      <div className="bg-[#0d1f3c] rounded-xl border border-gray-800 p-6">
        <h2 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
          <Target className="w-5 h-5 text-blue-400" />
          Scan Information
        </h2>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-6">
          <div>
            <p className="text-gray-500 text-sm">Target</p>
            <p className="text-white font-medium flex items-center gap-2">
              <Globe className="w-4 h-4 text-gray-400" />
              {scan.target}
            </p>
          </div>
          <div>
            <p className="text-gray-500 text-sm">Scan Type</p>
            <p className="text-white font-medium capitalize">{scan.scan_type}</p>
          </div>
          <div>
            <p className="text-gray-500 text-sm">Started</p>
            <p className="text-white font-medium flex items-center gap-2">
              <Clock className="w-4 h-4 text-gray-400" />
              {formatDate(scan.started_at)}
            </p>
          </div>
          <div>
            <p className="text-gray-500 text-sm">Completed</p>
            <p className="text-white font-medium">{formatDate(scan.completed_at)}</p>
          </div>
        </div>
      </div>

      {/* Vulnerabilities List */}
      <div className="bg-[#0d1f3c] rounded-xl border border-gray-800">
        <div className="p-4 border-b border-gray-800 flex items-center justify-between">
          <h2 className="text-lg font-semibold text-white flex items-center gap-2">
            <Bug className="w-5 h-5 text-red-400" />
            Vulnerabilities Found ({vulnerabilities.length})
          </h2>
          {stats.open > 0 && (
            <button
              onClick={() => navigate('/fix')}
              className="px-4 py-2 bg-red-500 hover:bg-red-600 text-white rounded-lg text-sm flex items-center gap-2"
            >
              <Wrench className="w-4 h-4" />
              Fix All Issues
            </button>
          )}
        </div>

        {vulnerabilities.length === 0 ? (
          <div className="p-12 text-center">
            <CheckCircle className="w-16 h-16 text-green-400 mx-auto mb-4" />
            <h3 className="text-xl font-semibold text-white mb-2">All Clear!</h3>
            <p className="text-gray-400">No vulnerabilities were found in this scan.</p>
          </div>
        ) : (
          <div className="divide-y divide-gray-800">
            {vulnerabilities.map((vuln) => {
              const colors = getSeverityColor(vuln.severity);
              const isExpanded = expandedVuln === vuln.id;
              
              return (
                <div key={vuln.id} className="hover:bg-gray-800/30 transition-colors">
                  {/* Vulnerability Header */}
                  <div
                    className="p-4 cursor-pointer"
                    onClick={() => setExpandedVuln(isExpanded ? null : vuln.id)}
                  >
                    <div className="flex items-start justify-between">
                      <div className="flex items-start gap-4">
                        <div className={`p-2 rounded-lg ${colors.bg}`}>
                          <AlertTriangle className={`w-5 h-5 ${colors.text}`} />
                        </div>
                        <div>
                          <div className="flex items-center gap-3 mb-1">
                            <h3 className="text-white font-semibold">
                              {vuln.vuln_type.replace(/_/g, ' ')}
                            </h3>
                            <span className={`px-2 py-0.5 rounded text-xs uppercase ${colors.bg} ${colors.text}`}>
                              {vuln.severity}
                            </span>
                            <span className={`px-2 py-0.5 rounded text-xs ${getStatusColor(vuln.status)}`}>
                              {vuln.status === 'discovered' ? 'Open' : vuln.status}
                            </span>
                          </div>
                          <p className="text-gray-400 text-sm">{vuln.description}</p>
                          <div className="flex items-center gap-4 mt-2 text-sm text-gray-500">
                            <span className="flex items-center gap-1">
                              <Server className="w-4 h-4" />
                              {vuln.service}:{vuln.port}
                            </span>
                            {vuln.cve_id && (
                              <a
                                href={`https://nvd.nist.gov/vuln/detail/${vuln.cve_id}`}
                                target="_blank"
                                rel="noopener noreferrer"
                                onClick={(e) => e.stopPropagation()}
                                className="flex items-center gap-1 text-blue-400 hover:underline"
                              >
                                {vuln.cve_id}
                                <ExternalLink className="w-3 h-3" />
                              </a>
                            )}
                          </div>
                        </div>
                      </div>
                      <div className="flex items-center gap-2">
                        {isExpanded ? (
                          <ChevronDown className="w-5 h-5 text-gray-500" />
                        ) : (
                          <ChevronRight className="w-5 h-5 text-gray-500" />
                        )}
                      </div>
                    </div>
                  </div>

                  {/* Expanded Details */}
                  {isExpanded && (
                    <div className="px-4 pb-4 pt-0 border-t border-gray-800/50">
                      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 mt-4">
                        
                        {/* Evidence - WHERE the vulnerability is */}
                        {(vuln.vulnerable_url || vuln.payload_used || vuln.evidence) && (
                          <div className="lg:col-span-2 space-y-3">
                            <h4 className="text-white font-medium flex items-center gap-2">
                              <Target className="w-4 h-4 text-red-400" />
                              Vulnerability Evidence (Where It Was Found)
                            </h4>
                            <div className="bg-red-500/10 border border-red-500/30 rounded-lg p-4 space-y-3">
                              {vuln.vulnerable_url && (
                                <div>
                                  <span className="text-gray-400 text-sm">Vulnerable URL:</span>
                                  <code className="block mt-1 text-red-400 bg-black/30 p-2 rounded font-mono text-sm break-all">
                                    {vuln.http_method || 'GET'} {vuln.vulnerable_url.startsWith('http') ? vuln.vulnerable_url : scan.target + vuln.vulnerable_url}
                                  </code>
                                </div>
                              )}
                              {vuln.vulnerable_parameter && (
                                <div>
                                  <span className="text-gray-400 text-sm">Vulnerable Parameter:</span>
                                  <code className="block mt-1 text-orange-400 bg-black/30 p-2 rounded font-mono text-sm">
                                    {vuln.vulnerable_parameter}
                                  </code>
                                </div>
                              )}
                              {vuln.payload_used && (
                                <div>
                                  <span className="text-gray-400 text-sm">Payload Used:</span>
                                  <code className="block mt-1 text-yellow-400 bg-black/30 p-2 rounded font-mono text-sm break-all">
                                    {vuln.payload_used}
                                  </code>
                                </div>
                              )}
                              {vuln.evidence && (
                                <div>
                                  <span className="text-gray-400 text-sm">Evidence (Proof of Exploitation):</span>
                                  <code className="block mt-1 text-green-400 bg-black/30 p-2 rounded font-mono text-sm">
                                    {vuln.evidence}
                                  </code>
                                </div>
                              )}
                            </div>
                          </div>
                        )}

                        {/* HTTP Request/Response */}
                        {(vuln.request_example || vuln.response_snippet) && (
                          <div className="lg:col-span-2 space-y-3">
                            <h4 className="text-white font-medium flex items-center gap-2">
                              <Globe className="w-4 h-4 text-blue-400" />
                              HTTP Request/Response
                            </h4>
                            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                              {vuln.request_example && (
                                <div className="bg-blue-500/10 border border-blue-500/30 rounded-lg p-3">
                                  <span className="text-blue-400 text-sm font-medium">Request:</span>
                                  <pre className="mt-2 text-gray-300 bg-black/30 p-2 rounded font-mono text-xs overflow-x-auto whitespace-pre-wrap">
                                    {vuln.request_example.replace(/\\n/g, '\n')}
                                  </pre>
                                </div>
                              )}
                              {vuln.response_snippet && (
                                <div className="bg-green-500/10 border border-green-500/30 rounded-lg p-3">
                                  <span className="text-green-400 text-sm font-medium">Response (Vulnerable):</span>
                                  <pre className="mt-2 text-gray-300 bg-black/30 p-2 rounded font-mono text-xs overflow-x-auto whitespace-pre-wrap">
                                    {vuln.response_snippet.replace(/\\n/g, '\n')}
                                  </pre>
                                </div>
                              )}
                            </div>
                          </div>
                        )}

                        {/* Affected Code */}
                        {vuln.affected_code && (
                          <div className="space-y-3">
                            <h4 className="text-white font-medium flex items-center gap-2">
                              <Bug className="w-4 h-4 text-red-400" />
                              Vulnerable Code
                            </h4>
                            <div className="bg-red-500/10 border border-red-500/30 rounded-lg p-3">
                              <pre className="text-red-400 bg-black/30 p-2 rounded font-mono text-xs overflow-x-auto whitespace-pre-wrap">
                                {vuln.affected_code}
                              </pre>
                            </div>
                          </div>
                        )}

                        {/* Remediation Code */}
                        {vuln.remediation_code && (
                          <div className="space-y-3">
                            <h4 className="text-white font-medium flex items-center gap-2">
                              <CheckCircle className="w-4 h-4 text-green-400" />
                              Fixed Code (How to Fix)
                            </h4>
                            <div className="bg-green-500/10 border border-green-500/30 rounded-lg p-3">
                              <pre className="text-green-400 bg-black/30 p-2 rounded font-mono text-xs overflow-x-auto whitespace-pre-wrap">
                                {vuln.remediation_code}
                              </pre>
                            </div>
                          </div>
                        )}

                        {/* Technical Details */}
                        <div className="space-y-3">
                          <h4 className="text-white font-medium flex items-center gap-2">
                            <FileText className="w-4 h-4 text-gray-400" />
                            Technical Details
                          </h4>
                          <div className="bg-black/30 rounded-lg p-3 space-y-2 text-sm">
                            <div className="flex justify-between">
                              <span className="text-gray-500">Service:</span>
                              <span className="text-white">{vuln.service}</span>
                            </div>
                            <div className="flex justify-between">
                              <span className="text-gray-500">Port:</span>
                              <span className="text-white">{vuln.port}</span>
                            </div>
                            {vuln.owasp_category && (
                              <div className="flex justify-between">
                                <span className="text-gray-500">OWASP:</span>
                                <span className="text-purple-400">{vuln.owasp_category}</span>
                              </div>
                            )}
                            {vuln.mitre_id && (
                              <div className="flex justify-between">
                                <span className="text-gray-500">MITRE:</span>
                                <span className="text-blue-400">{vuln.mitre_id}</span>
                              </div>
                            )}
                            <div className="flex justify-between">
                              <span className="text-gray-500">Discovered:</span>
                              <span className="text-white">{formatDate(vuln.discovered_at)}</span>
                            </div>
                          </div>
                        </div>

                        {/* Actions */}
                        <div className="space-y-3">
                          <h4 className="text-white font-medium flex items-center gap-2">
                            <Wrench className="w-4 h-4 text-gray-400" />
                            Actions
                          </h4>
                          <div className="space-y-2">
                            <button
                              onClick={(e) => {
                                e.stopPropagation();
                                navigate('/fix');
                              }}
                              className="w-full px-4 py-2 bg-red-500/20 text-red-400 hover:bg-red-500/30 rounded-lg text-sm flex items-center justify-center gap-2"
                            >
                              <Wrench className="w-4 h-4" />
                              Fix This Vulnerability
                            </button>
                            <button
                              onClick={(e) => {
                                e.stopPropagation();
                                copyToClipboard(JSON.stringify({
                                  type: vuln.vuln_type,
                                  url: vuln.vulnerable_url,
                                  parameter: vuln.vulnerable_parameter,
                                  payload: vuln.payload_used,
                                  evidence: vuln.evidence
                                }, null, 2), `evidence-${vuln.id}`);
                              }}
                              className="w-full px-4 py-2 bg-gray-700 text-gray-300 hover:bg-gray-600 rounded-lg text-sm flex items-center justify-center gap-2"
                            >
                              {copiedId === `evidence-${vuln.id}` ? (
                                <>
                                  <CheckCircle className="w-4 h-4 text-green-400" />
                                  Copied!
                                </>
                              ) : (
                                <>
                                  <Copy className="w-4 h-4" />
                                  Copy Evidence
                                </>
                              )}
                            </button>
                          </div>
                          
                          {/* Warning about Fix limitations */}
                          <div className="bg-yellow-500/10 border border-yellow-500/30 rounded-lg p-3 mt-3">
                            <p className="text-yellow-400 text-xs">
                              <strong>Note:</strong> "Fix" only works on servers YOU control with SSH access. 
                              External sites like DVWA/pentest-ground cannot be fixed remotely - 
                              that would require unauthorized access.
                            </p>
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
      </div>

      {/* Bottom Actions */}
      <div className="flex items-center justify-between">
        <button
          onClick={() => navigate('/scans')}
          className="px-6 py-2 bg-gray-700 hover:bg-gray-600 text-white rounded-lg flex items-center gap-2"
        >
          <ArrowLeft className="w-4 h-4" />
          Back to Scans
        </button>
        <div className="flex items-center gap-3">
          <button
            onClick={() => navigate('/new-scan')}
            className="px-6 py-2 bg-blue-500 hover:bg-blue-600 text-white rounded-lg"
          >
            New Scan
          </button>
          {stats.open > 0 && (
            <button
              onClick={() => navigate('/fix')}
              className="px-6 py-2 bg-red-500 hover:bg-red-600 text-white rounded-lg flex items-center gap-2"
            >
              <Wrench className="w-4 h-4" />
              Fix Issues
            </button>
          )}
        </div>
      </div>
    </div>
  );
}
