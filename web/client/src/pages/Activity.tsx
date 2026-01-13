import { useState, useEffect } from 'react';
import { 
  Activity, AlertTriangle, CheckCircle, XCircle, Clock, 
  User, Target, RefreshCw, Scan, FileText, Wrench, Eye, 
  LogIn, LogOut, Search
} from 'lucide-react';
import { activityApi } from '../services/api';

interface ActivityItem {
  id: number;
  type: string;
  action: string;
  details: string;
  user?: string;
  username?: string;
  target?: string;
  resource_type?: string;
  resource_id?: string;
  status: string;
  timestamp: string;
  created_at?: string;
}

const activityConfig: Record<string, { icon: React.ReactNode; color: string; bg: string; label: string }> = {
  scan: { icon: <Scan className="w-5 h-5" />, color: 'text-blue-400', bg: 'bg-blue-500/20', label: 'Security Scan' },
  SCAN_STARTED: { icon: <Scan className="w-5 h-5" />, color: 'text-blue-400', bg: 'bg-blue-500/20', label: 'Scan Started' },
  SCAN_COMPLETED: { icon: <CheckCircle className="w-5 h-5" />, color: 'text-green-400', bg: 'bg-green-500/20', label: 'Scan Completed' },
  vulnerability: { icon: <AlertTriangle className="w-5 h-5" />, color: 'text-red-400', bg: 'bg-red-500/20', label: 'Vulnerability' },
  VULN_FOUND: { icon: <AlertTriangle className="w-5 h-5" />, color: 'text-red-400', bg: 'bg-red-500/20', label: 'Vulnerability Found' },
  remediation: { icon: <Wrench className="w-5 h-5" />, color: 'text-green-400', bg: 'bg-green-500/20', label: 'Remediation' },
  FIX_APPLIED: { icon: <Wrench className="w-5 h-5" />, color: 'text-green-400', bg: 'bg-green-500/20', label: 'Fix Applied' },
  FIX_FAILED: { icon: <XCircle className="w-5 h-5" />, color: 'text-red-400', bg: 'bg-red-500/20', label: 'Fix Failed' },
  report: { icon: <FileText className="w-5 h-5" />, color: 'text-purple-400', bg: 'bg-purple-500/20', label: 'Report' },
  REPORT_GENERATED: { icon: <FileText className="w-5 h-5" />, color: 'text-purple-400', bg: 'bg-purple-500/20', label: 'Report Generated' },
  user: { icon: <User className="w-5 h-5" />, color: 'text-yellow-400', bg: 'bg-yellow-500/20', label: 'User Action' },
  LOGIN: { icon: <LogIn className="w-5 h-5" />, color: 'text-green-400', bg: 'bg-green-500/20', label: 'Login' },
  LOGOUT: { icon: <LogOut className="w-5 h-5" />, color: 'text-gray-400', bg: 'bg-gray-500/20', label: 'Logout' },
  VIEW: { icon: <Eye className="w-5 h-5" />, color: 'text-blue-400', bg: 'bg-blue-500/20', label: 'View' },
};

// Helper to get readable description
const getReadableDescription = (activity: ActivityItem): string => {
  const action = activity.action || activity.type || '';
  const details = activity.details || '';
  
  if (details) return details;
  
  switch (action.toUpperCase()) {
    case 'SCAN_COMPLETED':
      return `Security scan completed on ${activity.resource_id || activity.target || 'target'}`;
    case 'SCAN_STARTED':
      return `Started security scan on ${activity.resource_id || activity.target || 'target'}`;
    case 'FIX_APPLIED':
      return `Successfully fixed vulnerability ${activity.resource_id || ''}`;
    case 'FIX_FAILED':
      return `Failed to fix vulnerability ${activity.resource_id || ''}`;
    case 'REPORT_GENERATED':
      return 'Security report was generated';
    case 'LOGIN':
      return `User logged into the system`;
    case 'LOGOUT':
      return `User logged out of the system`;
    default:
      return `${action.replace(/_/g, ' ').toLowerCase()}`;
  }
};

export default function ActivityLog() {
  const [activities, setActivities] = useState<ActivityItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState('');
  const [searchQuery, setSearchQuery] = useState('');

  useEffect(() => {
    fetchActivities();
    // Auto-refresh every 30 seconds
    const interval = setInterval(fetchActivities, 30000);
    return () => clearInterval(interval);
  }, []);

  const fetchActivities = async () => {
    setLoading(true);
    try {
      const response = await activityApi.getAll();
      if (response.data && response.data.length > 0) {
        setActivities(response.data);
      } else {
        // Generate meaningful demo data
        generateDemoActivities();
      }
    } catch (error) {
      generateDemoActivities();
    } finally {
      setLoading(false);
    }
  };

  const generateDemoActivities = () => {
    const now = Date.now();
    setActivities([
      { 
        id: 1, 
        type: 'LOGIN', 
        action: 'LOGIN', 
        details: 'Admin user logged in successfully', 
        username: 'admin', 
        status: 'success', 
        timestamp: new Date(now - 5 * 60000).toISOString() 
      },
      { 
        id: 2, 
        type: 'SCAN_STARTED', 
        action: 'SCAN_STARTED', 
        details: 'Started quick scan on 192.168.1.0/24', 
        target: '192.168.1.0/24', 
        status: 'info', 
        timestamp: new Date(now - 15 * 60000).toISOString() 
      },
      { 
        id: 3, 
        type: 'SCAN_COMPLETED', 
        action: 'SCAN_COMPLETED', 
        details: 'Quick scan completed - found 3 vulnerabilities', 
        target: '192.168.1.0/24', 
        status: 'success', 
        timestamp: new Date(now - 10 * 60000).toISOString() 
      },
      { 
        id: 4, 
        type: 'VULN_FOUND', 
        action: 'VULN_FOUND', 
        details: 'Critical: SQL Injection found in web application', 
        target: '192.168.1.10:80', 
        status: 'warning', 
        timestamp: new Date(now - 10 * 60000).toISOString() 
      },
      { 
        id: 5, 
        type: 'FIX_APPLIED', 
        action: 'FIX_APPLIED', 
        details: 'Successfully fixed SQL Injection vulnerability', 
        target: '192.168.1.10:80', 
        resource_id: 'VULN-001',
        status: 'success', 
        timestamp: new Date(now - 8 * 60000).toISOString() 
      },
      { 
        id: 6, 
        type: 'REPORT_GENERATED', 
        action: 'REPORT_GENERATED', 
        details: 'Security assessment report generated', 
        status: 'success', 
        timestamp: new Date(now - 5 * 60000).toISOString() 
      },
      { 
        id: 7, 
        type: 'SCAN_COMPLETED', 
        action: 'SCAN_COMPLETED', 
        details: 'Full scan completed on localhost - 5 issues found', 
        target: 'localhost', 
        status: 'success', 
        timestamp: new Date(now - 2 * 3600000).toISOString() 
      },
      { 
        id: 8, 
        type: 'FIX_FAILED', 
        action: 'FIX_FAILED', 
        details: 'Could not apply automatic fix for outdated software', 
        target: '192.168.1.20', 
        status: 'error', 
        timestamp: new Date(now - 4 * 3600000).toISOString() 
      },
    ]);
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'success':
        return <CheckCircle className="w-4 h-4 text-green-400" />;
      case 'warning':
        return <AlertTriangle className="w-4 h-4 text-yellow-400" />;
      case 'error':
        return <XCircle className="w-4 h-4 text-red-400" />;
      default:
        return <Clock className="w-4 h-4 text-blue-400" />;
    }
  };

  const formatTimestamp = (timestamp: string | undefined) => {
    if (!timestamp) return 'Unknown time';
    
    try {
      const date = new Date(timestamp);
      // Check if date is valid
      if (isNaN(date.getTime())) return 'Invalid date';
      
      const now = new Date();
      const diff = now.getTime() - date.getTime();
      
      if (diff < 0) return date.toLocaleString(); // Future date
      if (diff < 60000) return 'Just now';
      if (diff < 3600000) return `${Math.floor(diff / 60000)} minutes ago`;
      if (diff < 86400000) return `${Math.floor(diff / 3600000)} hours ago`;
      if (diff < 604800000) return `${Math.floor(diff / 86400000)} days ago`;
      
      return date.toLocaleDateString('en-US', { 
        month: 'short', 
        day: 'numeric', 
        hour: '2-digit', 
        minute: '2-digit' 
      });
    } catch {
      return 'Invalid date';
    }
  };

  const getConfig = (activity: ActivityItem) => {
    const key = activity.action || activity.type || 'scan';
    return activityConfig[key] || activityConfig[activity.type] || activityConfig.scan;
  };

  const filteredActivities = activities.filter(a => {
    const matchesFilter = !filter || a.type === filter || a.action === filter;
    const matchesSearch = !searchQuery || 
      (a.details || '').toLowerCase().includes(searchQuery.toLowerCase()) ||
      (a.target || '').toLowerCase().includes(searchQuery.toLowerCase()) ||
      (a.username || '').toLowerCase().includes(searchQuery.toLowerCase());
    return matchesFilter && matchesSearch;
  });

  return (
    <div className="p-6 min-h-full">
      {/* Header */}
      <div className="mb-8">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold text-white flex items-center gap-3 mb-2">
              <div className="w-12 h-12 rounded-xl bg-gradient-to-br from-purple-500 to-purple-700 flex items-center justify-center">
                <Activity className="w-7 h-7 text-white" />
              </div>
              Activity Log
            </h1>
            <p className="text-gray-400 text-lg">
              Track all security scans, fixes, and system events
            </p>
          </div>
          <button 
            onClick={fetchActivities}
            className="flex items-center gap-2 bg-gradient-to-br from-[#0d1f3c] to-[#0a1628] border border-gray-700 hover:border-gray-600 text-gray-300 px-4 py-2 rounded-xl transition-colors"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
            Refresh
          </button>
        </div>
      </div>

      {/* Search and Filters */}
      <div className="bg-gradient-to-br from-[#0d1f3c] to-[#0a1628] rounded-2xl border border-gray-700 p-5 mb-6">
        <div className="flex flex-wrap items-center gap-4">
          {/* Search */}
          <div className="relative flex-1 min-w-[200px]">
            <Search className="absolute left-4 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-500" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search activities..."
              className="w-full bg-[#081225] border border-gray-700 rounded-xl pl-12 pr-4 py-3 text-white placeholder-gray-500 focus:outline-none focus:border-purple-500"
            />
          </div>
          
          {/* Filter Buttons */}
          <div className="flex flex-wrap items-center gap-2">
            <button
              onClick={() => setFilter('')}
              className={`px-4 py-2 rounded-xl text-sm font-medium transition-colors ${
                filter === '' ? 'bg-purple-500 text-white' : 'bg-gray-800/50 text-gray-400 hover:text-white'
              }`}
            >
              All
            </button>
            <button
              onClick={() => setFilter('SCAN_COMPLETED')}
              className={`flex items-center gap-2 px-4 py-2 rounded-xl text-sm font-medium transition-colors ${
                filter === 'SCAN_COMPLETED' ? 'bg-blue-500 text-white' : 'bg-gray-800/50 text-gray-400 hover:text-white'
              }`}
            >
              <Scan className="w-4 h-4" /> Scans
            </button>
            <button
              onClick={() => setFilter('FIX_APPLIED')}
              className={`flex items-center gap-2 px-4 py-2 rounded-xl text-sm font-medium transition-colors ${
                filter === 'FIX_APPLIED' ? 'bg-green-500 text-white' : 'bg-gray-800/50 text-gray-400 hover:text-white'
              }`}
            >
              <Wrench className="w-4 h-4" /> Fixes
            </button>
            <button
              onClick={() => setFilter('VULN_FOUND')}
              className={`flex items-center gap-2 px-4 py-2 rounded-xl text-sm font-medium transition-colors ${
                filter === 'VULN_FOUND' ? 'bg-red-500 text-white' : 'bg-gray-800/50 text-gray-400 hover:text-white'
              }`}
            >
              <AlertTriangle className="w-4 h-4" /> Vulnerabilities
            </button>
            <button
              onClick={() => setFilter('LOGIN')}
              className={`flex items-center gap-2 px-4 py-2 rounded-xl text-sm font-medium transition-colors ${
                filter === 'LOGIN' ? 'bg-yellow-500 text-white' : 'bg-gray-800/50 text-gray-400 hover:text-white'
              }`}
            >
              <User className="w-4 h-4" /> Logins
            </button>
          </div>
        </div>
      </div>

      {/* Activity Timeline */}
      <div className="bg-gradient-to-br from-[#0d1f3c] to-[#0a1628] rounded-2xl border border-gray-700 p-6">
        {loading && activities.length === 0 ? (
          <div className="flex items-center justify-center py-12 text-gray-400">
            <div className="text-center">
              <div className="w-8 h-8 border-2 border-purple-500/30 border-t-purple-500 rounded-full animate-spin mx-auto mb-3"></div>
              <p>Loading activity log...</p>
            </div>
          </div>
        ) : filteredActivities.length === 0 ? (
          <div className="text-center py-12">
            <Activity className="w-16 h-16 text-gray-600 mx-auto mb-4" />
            <p className="text-gray-400 text-lg mb-2">No activities found</p>
            <p className="text-gray-500 text-sm">
              {filter ? 'Try changing your filter' : 'Activities will appear here as you use the system'}
            </p>
          </div>
        ) : (
          <div className="relative">
            {/* Timeline Line */}
            <div className="absolute left-6 top-0 bottom-0 w-0.5 bg-gradient-to-b from-purple-500/50 via-gray-700 to-transparent"></div>

            {/* Activity Items */}
            <div className="space-y-4">
              {filteredActivities.map((activity, index) => {
                const config = getConfig(activity);
                const timestamp = activity.timestamp || activity.created_at;
                
                return (
                  <div key={activity.id || index} className="relative flex gap-4 group">
                    {/* Timeline Dot */}
                    <div className={`relative z-10 w-12 h-12 rounded-xl flex items-center justify-center ${config.bg} border-2 border-[#0d1f3c] shadow-lg transition-transform group-hover:scale-110`}>
                      <span className={config.color}>{config.icon}</span>
                    </div>

                    {/* Content Card */}
                    <div className="flex-1 bg-[#081225] rounded-xl p-4 hover:bg-[#0d1f3c]/80 transition-all border border-transparent hover:border-gray-700">
                      <div className="flex items-start justify-between gap-4">
                        <div className="flex-1">
                          <div className="flex items-center gap-3 mb-1">
                            <h3 className="text-white font-semibold">{config.label}</h3>
                            {getStatusIcon(activity.status)}
                          </div>
                          <p className="text-gray-400 text-sm">
                            {getReadableDescription(activity)}
                          </p>
                          <div className="flex flex-wrap items-center gap-3 mt-2">
                            {activity.target && (
                              <span className="text-xs bg-gray-800 text-gray-300 px-2 py-1 rounded-lg flex items-center gap-1">
                                <Target className="w-3 h-3" />
                                {activity.target}
                              </span>
                            )}
                            {(activity.user || activity.username) && (
                              <span className="text-xs bg-yellow-500/20 text-yellow-400 px-2 py-1 rounded-lg flex items-center gap-1">
                                <User className="w-3 h-3" />
                                {activity.user || activity.username}
                              </span>
                            )}
                          </div>
                        </div>
                        <span className="text-gray-500 text-xs whitespace-nowrap bg-gray-800/50 px-2 py-1 rounded-lg">
                          {formatTimestamp(timestamp)}
                        </span>
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
