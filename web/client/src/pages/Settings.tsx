import { useState, useEffect } from 'react';
import { Save, Shield, Bell, Database, Key, Monitor, Moon, Check, Wrench, CheckCircle2, XCircle, RefreshCw, Sun, Download, Trash2, Eye, EyeOff } from 'lucide-react';

interface ToolStatus {
  name: string;
  installed: boolean;
  version?: string;
  description: string;
}

interface Settings {
  darkMode: boolean;
  notifications: {
    email: boolean;
    push: boolean;
    critical: boolean;
    scans: boolean;
    reports: boolean;
  };
  scanSettings: {
    autoScan: boolean;
    scanInterval: string;
    maxConcurrent: string;
    timeout: string;
  };
}

const DEFAULT_SETTINGS: Settings = {
  darkMode: true,
  notifications: {
    email: true,
    push: false,
    critical: true,
    scans: true,
    reports: false,
  },
  scanSettings: {
    autoScan: false,
    scanInterval: '24',
    maxConcurrent: '5',
    timeout: '300',
  }
};

export default function Settings() {
  // Load settings from localStorage on mount
  const [settings, setSettings] = useState<Settings>(() => {
    const saved = localStorage.getItem('redshield_settings');
    return saved ? JSON.parse(saved) : DEFAULT_SETTINGS;
  });
  
  const [saved, setSaved] = useState(false);
  const [toolsStatus, setToolsStatus] = useState<ToolStatus[]>([]);
  const [toolsLoading, setToolsLoading] = useState(false);
  const [pythonApiRunning, setPythonApiRunning] = useState(false);
  
  // Password change
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [passwordMessage, setPasswordMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null);
  
  // Database
  const [dbSize, setDbSize] = useState('Calculating...');
  const [clearingData, setClearingData] = useState(false);
  const [exportingData, setExportingData] = useState(false);

  // Check tools status on component mount
  useEffect(() => {
    checkToolsStatus();
    calculateDbSize();
  }, []);

  // Save settings to localStorage whenever they change
  const saveSettings = (newSettings: Settings) => {
    setSettings(newSettings);
    localStorage.setItem('redshield_settings', JSON.stringify(newSettings));
  };

  const checkToolsStatus = async () => {
    setToolsLoading(true);
    try {
      // First check if Python API is running
      const healthResponse = await fetch('http://localhost:5000/api/health');
      if (healthResponse.ok) {
        setPythonApiRunning(true);
        
        // Get detailed tools status
        const toolsResponse = await fetch('http://localhost:5000/api/tools/status');
        if (toolsResponse.ok) {
          const toolsData = await toolsResponse.json();
          const tools: ToolStatus[] = [
            {
              name: 'Nmap',
              installed: toolsData.nmap?.installed || false,
              version: toolsData.nmap?.version,
              description: 'Network scanner for port discovery and service detection'
            },
            {
              name: 'Nuclei',
              installed: toolsData.nuclei?.installed || false,
              version: toolsData.nuclei?.version,
              description: 'Fast vulnerability scanner with templated detection'
            },
            {
              name: 'Metasploit',
              installed: toolsData.metasploit?.installed || false,
              version: toolsData.metasploit?.version,
              description: 'Penetration testing framework for exploit verification'
            },
            {
              name: 'Ansible',
              installed: toolsData.ansible?.installed || false,
              version: toolsData.ansible?.version,
              description: 'Automation tool for vulnerability remediation'
            }
          ];
          setToolsStatus(tools);
        }
      } else {
        setPythonApiRunning(false);
        setDefaultToolsStatus();
      }
    } catch {
      setPythonApiRunning(false);
      setDefaultToolsStatus();
    }
    setToolsLoading(false);
  };

  const setDefaultToolsStatus = () => {
    setToolsStatus([
      { name: 'Nmap', installed: false, description: 'Network scanner for port discovery and service detection' },
      { name: 'Nuclei', installed: false, description: 'Fast vulnerability scanner with templated detection' },
      { name: 'Metasploit', installed: false, description: 'Penetration testing framework for exploit verification' },
      { name: 'Ansible', installed: false, description: 'Automation tool for vulnerability remediation' }
    ]);
  };

  const calculateDbSize = async () => {
    try {
      const response = await fetch('http://localhost:3001/api/stats');
      if (response.ok) {
        const data = await response.json();
        // Estimate DB size based on records
        const totalRecords = (data.totalScans || 0) + (data.totalVulnerabilities || 0) + (data.totalUsers || 0);
        const estimatedSize = (totalRecords * 0.5 + 100).toFixed(1); // Rough estimate in KB
        setDbSize(`~${estimatedSize} KB (${totalRecords} records)`);
      } else {
        setDbSize('2.4 MB');
      }
    } catch {
      setDbSize('2.4 MB');
    }
  };

  const handleSave = () => {
    localStorage.setItem('redshield_settings', JSON.stringify(settings));
    setSaved(true);
    setTimeout(() => setSaved(false), 3000);
  };

  const handleExportData = async () => {
    setExportingData(true);
    try {
      // Export settings
      const settingsExport = {
        settings: settings,
        exportedAt: new Date().toISOString(),
        version: '1.0.0'
      };
      
      const blob = new Blob([JSON.stringify(settingsExport, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `redshield-settings-${new Date().toISOString().split('T')[0]}.json`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (error) {
      console.error('Export failed:', error);
    }
    setExportingData(false);
  };

  const handleClearData = async () => {
    if (!confirm('Are you sure you want to clear all data? This cannot be undone.')) return;
    
    setClearingData(true);
    try {
      // Clear localStorage
      localStorage.removeItem('redshield_settings');
      setSettings(DEFAULT_SETTINGS);
      
      // Try to clear server data
      await fetch('http://localhost:3001/api/reset', { method: 'POST' });
      
      alert('All data has been cleared successfully.');
    } catch (error) {
      alert('Local data cleared. Server data may still exist.');
    }
    setClearingData(false);
  };

  const handlePasswordChange = async () => {
    if (!currentPassword || !newPassword) {
      setPasswordMessage({ type: 'error', text: 'Please fill in both fields' });
      return;
    }
    
    if (newPassword.length < 6) {
      setPasswordMessage({ type: 'error', text: 'New password must be at least 6 characters' });
      return;
    }
    
    try {
      const token = localStorage.getItem('token');
      const response = await fetch('http://localhost:3001/api/auth/change-password', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({ currentPassword, newPassword })
      });
      
      if (response.ok) {
        setPasswordMessage({ type: 'success', text: 'Password changed successfully!' });
        setCurrentPassword('');
        setNewPassword('');
      } else {
        const data = await response.json();
        setPasswordMessage({ type: 'error', text: data.error || 'Failed to change password' });
      }
    } catch {
      setPasswordMessage({ type: 'error', text: 'Failed to connect to server' });
    }
    
    setTimeout(() => setPasswordMessage(null), 5000);
  };

  const toggleNotification = (key: keyof typeof settings.notifications) => {
    const newSettings = {
      ...settings,
      notifications: { ...settings.notifications, [key]: !settings.notifications[key] }
    };
    saveSettings(newSettings);
  };

  const updateScanSetting = (key: keyof typeof settings.scanSettings, value: string | boolean) => {
    const newSettings = {
      ...settings,
      scanSettings: { ...settings.scanSettings, [key]: value }
    };
    saveSettings(newSettings);
  };

  const toggleDarkMode = () => {
    const newSettings = { ...settings, darkMode: !settings.darkMode };
    saveSettings(newSettings);
  };

  return (
    <div className="p-6 max-w-4xl min-h-full">
      {/* Header */}
      <div className="flex items-center justify-between mb-8">
        <div>
          <h1 className="text-3xl font-bold text-white flex items-center gap-3 mb-2">
            <div className="w-12 h-12 rounded-xl bg-gradient-to-br from-gray-500 to-gray-700 flex items-center justify-center">
              <Monitor className="w-7 h-7 text-white" />
            </div>
            Settings
          </h1>
          <p className="text-gray-400 text-lg">Manage your RedShield preferences</p>
        </div>
        <button 
          onClick={handleSave}
          className={`flex items-center gap-2 px-5 py-2.5 rounded-xl transition-all font-medium ${
            saved 
              ? 'bg-green-500 text-white' 
              : 'bg-gradient-to-r from-purple-500 to-purple-700 hover:from-purple-600 hover:to-purple-800 text-white'
          }`}
        >
          {saved ? <Check className="w-5 h-5" /> : <Save className="w-5 h-5" />}
          {saved ? 'Settings Saved!' : 'Save Changes'}
        </button>
      </div>

      <div className="space-y-6">
        {/* Security Tools Status */}
        <div className="bg-gradient-to-br from-[#0d1f3c] to-[#0a1628] rounded-2xl border border-gray-700 p-6">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-3">
              <div className="p-2 bg-purple-500/20 rounded-xl">
                <Wrench className="w-5 h-5 text-purple-400" />
              </div>
              <div>
                <h2 className="text-lg font-semibold text-white">Security Tools Status</h2>
                <p className="text-gray-500 text-sm">Required tools for real vulnerability scanning</p>
              </div>
            </div>
            <button
              onClick={checkToolsStatus}
              disabled={toolsLoading}
              className="flex items-center gap-2 px-4 py-2 bg-[#081225] border border-gray-700 rounded-xl text-gray-300 hover:border-purple-500 transition-colors disabled:opacity-50"
            >
              <RefreshCw className={`w-4 h-4 ${toolsLoading ? 'animate-spin' : ''}`} />
              Check Status
            </button>
          </div>

          {/* Python API Status */}
          <div className={`flex items-center gap-3 p-4 rounded-xl mb-4 ${pythonApiRunning ? 'bg-green-500/10 border border-green-500/30' : 'bg-blue-500/10 border border-blue-500/30'}`}>
            {pythonApiRunning ? (
              <CheckCircle2 className="w-6 h-6 text-green-400" />
            ) : (
              <Shield className="w-6 h-6 text-blue-400" />
            )}
            <div className="flex-1">
              <p className={`font-medium ${pythonApiRunning ? 'text-green-400' : 'text-blue-400'}`}>
                Python Scanner API: {pythonApiRunning ? 'Connected & Running' : 'Optional (Using Demo Mode)'}
              </p>
              <p className="text-gray-500 text-sm">
                {pythonApiRunning 
                  ? 'Real scanning tools are available for use' 
                  : '✅ RedShield works perfectly in Demo Mode! The Python API is only needed for real network scans.'}
              </p>
            </div>
            <div className={`px-3 py-1 rounded-lg text-xs font-medium ${pythonApiRunning ? 'bg-green-500/20 text-green-400' : 'bg-blue-500/20 text-blue-400'}`}>
              {pythonApiRunning ? 'Online' : 'Demo Mode Active'}
            </div>
          </div>

          {/* Demo Mode Info Box */}
          {!pythonApiRunning && (
            <div className="bg-blue-500/5 border border-blue-500/20 rounded-xl p-4 mb-4">
              <div className="flex items-start gap-3">
                <div className="p-2 bg-blue-500/20 rounded-lg">
                  <Shield className="w-4 h-4 text-blue-400" />
                </div>
                <div>
                  <h4 className="text-blue-400 font-medium mb-1">Demo Mode is Perfect for Your Project</h4>
                  <p className="text-gray-400 text-sm mb-2">
                    All features work in Demo Mode with simulated data. This is ideal for:
                  </p>
                  <ul className="text-gray-400 text-sm space-y-1">
                    <li>• College project demonstrations</li>
                    <li>• Learning how security scanners work</li>
                    <li>• Testing the user interface</li>
                    <li>• Showing vulnerability management workflows</li>
                  </ul>
                  <p className="text-gray-500 text-xs mt-3">
                    To enable real scans, install the tools below and run: <code className="bg-gray-800 px-1 rounded">python api/scanner_api.py</code>
                  </p>
                </div>
              </div>
            </div>
          )}

          {/* Tools Grid */}
          <div className="grid grid-cols-2 gap-4">
            {toolsStatus.map((tool) => (
              <div
                key={tool.name}
                className={`p-4 rounded-xl border transition-all ${
                  tool.installed 
                    ? 'bg-green-500/5 border-green-500/30 hover:border-green-500/50' 
                    : 'bg-gray-800/30 border-gray-700 hover:border-gray-600'
                }`}
              >
                <div className="flex items-center justify-between mb-2">
                  <span className="font-medium text-white">{tool.name}</span>
                  {tool.installed ? (
                    <CheckCircle2 className="w-5 h-5 text-green-400" />
                  ) : (
                    <XCircle className="w-5 h-5 text-gray-500" />
                  )}
                </div>
                <p className="text-gray-500 text-sm mb-2">{tool.description}</p>
                {tool.installed && tool.version && (
                  <span className="text-xs text-green-400 bg-green-500/20 px-2 py-1 rounded-lg">
                    v{tool.version}
                  </span>
                )}
                {!tool.installed && (
                  <span className="text-xs text-yellow-400 bg-yellow-500/20 px-2 py-1 rounded-lg">
                    Not Installed
                  </span>
                )}
              </div>
            ))}
          </div>
        </div>

        {/* Appearance */}
        <div className="bg-gradient-to-br from-[#0d1f3c] to-[#0a1628] rounded-2xl border border-gray-700 p-6">
          <div className="flex items-center gap-3 mb-4">
            <div className="p-2 bg-purple-500/20 rounded-xl">
              {settings.darkMode ? <Moon className="w-5 h-5 text-purple-400" /> : <Sun className="w-5 h-5 text-yellow-400" />}
            </div>
            <h2 className="text-lg font-semibold text-white">Appearance</h2>
          </div>
          
          <div className="flex items-center justify-between py-4 px-4 bg-[#081225] rounded-xl">
            <div>
              <p className="text-white font-medium">Dark Mode</p>
              <p className="text-gray-500 text-sm">Use dark theme for the dashboard</p>
            </div>
            <button
              onClick={toggleDarkMode}
              className={`relative w-16 h-8 rounded-full transition-colors ${settings.darkMode ? 'bg-purple-500' : 'bg-gray-600'}`}
            >
              <div className={`absolute top-1 w-6 h-6 rounded-full bg-white shadow-lg transform transition-transform ${settings.darkMode ? 'left-9' : 'left-1'}`}></div>
            </button>
          </div>
        </div>

        {/* Notifications */}
        <div className="bg-gradient-to-br from-[#0d1f3c] to-[#0a1628] rounded-2xl border border-gray-700 p-6">
          <div className="flex items-center gap-3 mb-4">
            <div className="p-2 bg-yellow-500/20 rounded-xl">
              <Bell className="w-5 h-5 text-yellow-400" />
            </div>
            <h2 className="text-lg font-semibold text-white">Notifications</h2>
          </div>
          
          <div className="space-y-2">
            {Object.entries(settings.notifications).map(([key, value]) => (
              <div key={key} className="flex items-center justify-between py-3 px-4 bg-[#081225] rounded-xl">
                <div>
                  <p className="text-white font-medium capitalize">{key.replace(/([A-Z])/g, ' $1').trim()}</p>
                  <p className="text-gray-500 text-sm">
                    {key === 'email' && 'Receive notifications via email'}
                    {key === 'push' && 'Receive push notifications in browser'}
                    {key === 'critical' && 'Get notified for critical vulnerabilities'}
                    {key === 'scans' && 'Notify when scans complete'}
                    {key === 'reports' && 'Notify when reports are ready'}
                  </p>
                </div>
                <button
                  onClick={() => toggleNotification(key as keyof typeof settings.notifications)}
                  className={`relative w-16 h-8 rounded-full transition-colors ${value ? 'bg-purple-500' : 'bg-gray-600'}`}
                >
                  <div className={`absolute top-1 w-6 h-6 rounded-full bg-white shadow-lg transform transition-transform ${value ? 'left-9' : 'left-1'}`}></div>
                </button>
              </div>
            ))}
          </div>
        </div>

        {/* Scan Settings */}
        <div className="bg-gradient-to-br from-[#0d1f3c] to-[#0a1628] rounded-2xl border border-gray-700 p-6">
          <div className="flex items-center gap-3 mb-4">
            <div className="p-2 bg-blue-500/20 rounded-xl">
              <Monitor className="w-5 h-5 text-blue-400" />
            </div>
            <h2 className="text-lg font-semibold text-white">Scan Settings</h2>
          </div>
          
          <div className="grid grid-cols-2 gap-4">
            <div className="bg-[#081225] rounded-xl p-4">
              <label className="block text-gray-400 text-sm mb-3">Auto Scan</label>
              <div className="flex items-center justify-between">
                <span className="text-white">{settings.scanSettings.autoScan ? 'Enabled' : 'Disabled'}</span>
                <button
                  onClick={() => updateScanSetting('autoScan', !settings.scanSettings.autoScan)}
                  className={`relative w-16 h-8 rounded-full transition-colors ${settings.scanSettings.autoScan ? 'bg-purple-500' : 'bg-gray-600'}`}
                >
                  <div className={`absolute top-1 w-6 h-6 rounded-full bg-white shadow-lg transform transition-transform ${settings.scanSettings.autoScan ? 'left-9' : 'left-1'}`}></div>
                </button>
              </div>
            </div>
            <div className="bg-[#081225] rounded-xl p-4">
              <label className="block text-gray-400 text-sm mb-2">Scan Interval (hours)</label>
              <input
                type="number"
                value={settings.scanSettings.scanInterval}
                onChange={(e) => updateScanSetting('scanInterval', e.target.value)}
                className="w-full bg-[#0d1f3c] border border-gray-700 rounded-lg px-4 py-2 text-white focus:outline-none focus:border-purple-500"
              />
            </div>
            <div className="bg-[#081225] rounded-xl p-4">
              <label className="block text-gray-400 text-sm mb-2">Max Concurrent Scans</label>
              <input
                type="number"
                value={settings.scanSettings.maxConcurrent}
                onChange={(e) => updateScanSetting('maxConcurrent', e.target.value)}
                className="w-full bg-[#0d1f3c] border border-gray-700 rounded-lg px-4 py-2 text-white focus:outline-none focus:border-purple-500"
              />
            </div>
            <div className="bg-[#081225] rounded-xl p-4">
              <label className="block text-gray-400 text-sm mb-2">Timeout (seconds)</label>
              <input
                type="number"
                value={settings.scanSettings.timeout}
                onChange={(e) => updateScanSetting('timeout', e.target.value)}
                className="w-full bg-[#0d1f3c] border border-gray-700 rounded-lg px-4 py-2 text-white focus:outline-none focus:border-purple-500"
              />
            </div>
          </div>
        </div>

        {/* Security */}
        <div className="bg-gradient-to-br from-[#0d1f3c] to-[#0a1628] rounded-2xl border border-gray-700 p-6">
          <div className="flex items-center gap-3 mb-4">
            <div className="p-2 bg-green-500/20 rounded-xl">
              <Key className="w-5 h-5 text-green-400" />
            </div>
            <h2 className="text-lg font-semibold text-white">Security</h2>
          </div>
          
          <div className="space-y-4">
            <div className="bg-[#081225] rounded-xl p-4">
              <label className="block text-white font-medium mb-3">Change Password</label>
              <div className="grid grid-cols-2 gap-4 mb-3">
                <div className="relative">
                  <input
                    type={showPassword ? 'text' : 'password'}
                    value={currentPassword}
                    onChange={(e) => setCurrentPassword(e.target.value)}
                    placeholder="Current password"
                    className="w-full bg-[#0d1f3c] border border-gray-700 rounded-lg px-4 py-3 text-white placeholder-gray-500 focus:outline-none focus:border-purple-500"
                  />
                </div>
                <div className="relative">
                  <input
                    type={showPassword ? 'text' : 'password'}
                    value={newPassword}
                    onChange={(e) => setNewPassword(e.target.value)}
                    placeholder="New password"
                    className="w-full bg-[#0d1f3c] border border-gray-700 rounded-lg px-4 py-3 pr-12 text-white placeholder-gray-500 focus:outline-none focus:border-purple-500"
                  />
                  <button
                    type="button"
                    onClick={() => setShowPassword(!showPassword)}
                    className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-500 hover:text-white"
                  >
                    {showPassword ? <EyeOff className="w-5 h-5" /> : <Eye className="w-5 h-5" />}
                  </button>
                </div>
              </div>
              <div className="flex items-center justify-between">
                <button
                  onClick={handlePasswordChange}
                  className="px-4 py-2 bg-gradient-to-r from-green-500 to-green-600 text-white rounded-lg hover:from-green-600 hover:to-green-700 transition-colors"
                >
                  Update Password
                </button>
                {passwordMessage && (
                  <span className={`text-sm ${passwordMessage.type === 'success' ? 'text-green-400' : 'text-red-400'}`}>
                    {passwordMessage.text}
                  </span>
                )}
              </div>
            </div>
          </div>
        </div>

        {/* Database */}
        <div className="bg-gradient-to-br from-[#0d1f3c] to-[#0a1628] rounded-2xl border border-gray-700 p-6">
          <div className="flex items-center gap-3 mb-4">
            <div className="p-2 bg-red-500/20 rounded-xl">
              <Database className="w-5 h-5 text-red-400" />
            </div>
            <h2 className="text-lg font-semibold text-white">Database</h2>
          </div>
          
          <div className="bg-[#081225] rounded-xl p-4 mb-4">
            <div className="grid grid-cols-2 gap-4">
              <div>
                <span className="text-gray-500 text-sm">Database Path</span>
                <p className="text-white font-mono text-sm">redshield.db</p>
              </div>
              <div>
                <span className="text-gray-500 text-sm">Database Size</span>
                <p className="text-white">{dbSize}</p>
              </div>
            </div>
          </div>
          
          <div className="flex flex-wrap gap-3">
            <button 
              onClick={handleExportData}
              disabled={exportingData}
              className="flex items-center gap-2 px-4 py-2 bg-[#081225] border border-gray-700 rounded-xl text-gray-300 hover:border-blue-500 hover:text-blue-400 transition-colors disabled:opacity-50"
            >
              <Download className="w-4 h-4" />
              {exportingData ? 'Exporting...' : 'Export Settings'}
            </button>
            <button 
              onClick={handleClearData}
              disabled={clearingData}
              className="flex items-center gap-2 px-4 py-2 bg-[#081225] border border-red-500/50 rounded-xl text-red-400 hover:bg-red-500/20 transition-colors disabled:opacity-50"
            >
              <Trash2 className="w-4 h-4" />
              {clearingData ? 'Clearing...' : 'Clear All Data'}
            </button>
          </div>
        </div>

        {/* About */}
        <div className="bg-gradient-to-br from-[#0d1f3c] to-[#0a1628] rounded-2xl border border-gray-700 p-6">
          <div className="flex items-center gap-3 mb-4">
            <div className="p-2 bg-red-500/20 rounded-xl">
              <Shield className="w-5 h-5 text-red-400" />
            </div>
            <h2 className="text-lg font-semibold text-white">About RedShield</h2>
          </div>
          
          <div className="bg-[#081225] rounded-xl p-4">
            <div className="grid grid-cols-2 gap-4 mb-4">
              <div>
                <span className="text-gray-500 text-sm">Version</span>
                <p className="text-white font-medium">1.0.0</p>
              </div>
              <div>
                <span className="text-gray-500 text-sm">License</span>
                <p className="text-white font-medium">MIT</p>
              </div>
            </div>
            <p className="text-gray-400 text-sm">
              RedShield is an advanced security scanning and vulnerability management toolkit 
              designed for security professionals. It provides comprehensive scanning, 
              vulnerability detection, and automated remediation capabilities.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}
