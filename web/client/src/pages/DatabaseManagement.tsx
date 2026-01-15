import { useState } from 'react';
import {
  Database,
  HardDrive,
  Download,
  Upload,
  Trash2,
  CheckCircle,
  XCircle,
  AlertTriangle,
  FileJson,
  FileSpreadsheet,
  Clock,
  Server,
  Loader2,
  Play
} from 'lucide-react';

interface DatabaseStats {
  engine: string;
  url: string;
  status: 'connected' | 'disconnected';
  tables: { name: string; rows: number }[];
  size: string;
  lastBackup: string | null;
}

interface BackupFile {
  name: string;
  date: string;
  size: string;
}

export default function DatabaseManagement() {
  const [stats, setStats] = useState<DatabaseStats>({
    engine: 'SQLite',
    url: 'sqlite:///redshield.db',
    status: 'connected',
    tables: [
      { name: 'users', rows: 3 },
      { name: 'scans', rows: 12 },
      { name: 'vulnerabilities', rows: 47 },
      { name: 'remediations', rows: 23 }
    ],
    size: '2.4 MB',
    lastBackup: '2026-01-15 10:30:00'
  });
  
  const [backups, setBackups] = useState<BackupFile[]>([
    { name: 'redshield_backup_20260115_103000.db', date: '2026-01-15 10:30:00', size: '2.3 MB' },
    { name: 'redshield_backup_20260114_180000.db', date: '2026-01-14 18:00:00', size: '2.1 MB' },
    { name: 'redshield_backup_20260113_090000.db', date: '2026-01-13 09:00:00', size: '1.9 MB' }
  ]);

  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null);
  const [showClearConfirm, setShowClearConfirm] = useState(false);
  const [exportFormat, setExportFormat] = useState<'json' | 'csv'>('json');

  const showMessage = (type: 'success' | 'error', text: string) => {
    setMessage({ type, text });
    setTimeout(() => setMessage(null), 3000);
  };

  const handleInitialize = async () => {
    setLoading(true);
    // Simulate API call
    await new Promise(resolve => setTimeout(resolve, 1500));
    setStats(prev => ({ ...prev, status: 'connected' }));
    showMessage('success', 'Database initialized successfully');
    setLoading(false);
  };

  const handleBackup = async () => {
    setLoading(true);
    await new Promise(resolve => setTimeout(resolve, 2000));
    const now = new Date();
    const backupName = `redshield_backup_${now.toISOString().replace(/[-:T]/g, '').slice(0, 14)}.db`;
    setBackups(prev => [{
      name: backupName,
      date: now.toLocaleString(),
      size: stats.size
    }, ...prev]);
    setStats(prev => ({ ...prev, lastBackup: now.toLocaleString() }));
    showMessage('success', `Backup created: ${backupName}`);
    setLoading(false);
  };

  const handleRestore = async (backupName: string) => {
    setLoading(true);
    await new Promise(resolve => setTimeout(resolve, 2000));
    showMessage('success', `Database restored from ${backupName}`);
    setLoading(false);
  };

  const handleExport = async () => {
    setLoading(true);
    await new Promise(resolve => setTimeout(resolve, 1500));
    const filename = `redshield_export_${Date.now()}.${exportFormat}`;
    showMessage('success', `Exported to ${filename}`);
    setLoading(false);
  };

  const handleClear = async () => {
    setLoading(true);
    await new Promise(resolve => setTimeout(resolve, 1500));
    setStats(prev => ({
      ...prev,
      tables: prev.tables.map(t => ({ ...t, rows: t.name === 'users' ? 1 : 0 }))
    }));
    setShowClearConfirm(false);
    showMessage('success', 'Database cleared (admin user preserved)');
    setLoading(false);
  };

  const handleDeleteBackup = (name: string) => {
    setBackups(prev => prev.filter(b => b.name !== name));
    showMessage('success', `Deleted backup: ${name}`);
  };

  const totalRows = stats.tables.reduce((sum, t) => sum + t.rows, 0);

  return (
    <div className="p-8">
      {/* Header */}
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-white mb-2">Database Management</h1>
        <p className="text-gray-400">Manage RedShield database, backups, and exports</p>
      </div>

      {/* Message Toast */}
      {message && (
        <div className={`fixed top-4 right-4 z-50 px-4 py-3 rounded-lg flex items-center gap-2 ${
          message.type === 'success' ? 'bg-green-500/20 border border-green-500/50 text-green-400' : 'bg-red-500/20 border border-red-500/50 text-red-400'
        }`}>
          {message.type === 'success' ? <CheckCircle className="w-5 h-5" /> : <XCircle className="w-5 h-5" />}
          {message.text}
        </div>
      )}

      {/* Status Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-8">
        <div className="bg-[#1a1a2e] rounded-xl p-4 border border-gray-800">
          <div className="flex items-center gap-3">
            <div className={`w-10 h-10 rounded-lg flex items-center justify-center ${
              stats.status === 'connected' ? 'bg-green-500/20' : 'bg-red-500/20'
            }`}>
              <Server className={`w-5 h-5 ${stats.status === 'connected' ? 'text-green-400' : 'text-red-400'}`} />
            </div>
            <div>
              <p className={`text-lg font-bold ${stats.status === 'connected' ? 'text-green-400' : 'text-red-400'}`}>
                {stats.status === 'connected' ? 'Connected' : 'Disconnected'}
              </p>
              <p className="text-gray-400 text-sm">{stats.engine}</p>
            </div>
          </div>
        </div>
        <div className="bg-[#1a1a2e] rounded-xl p-4 border border-gray-800">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 bg-blue-500/20 rounded-lg flex items-center justify-center">
              <Database className="w-5 h-5 text-blue-400" />
            </div>
            <div>
              <p className="text-2xl font-bold text-white">{stats.tables.length}</p>
              <p className="text-gray-400 text-sm">Tables</p>
            </div>
          </div>
        </div>
        <div className="bg-[#1a1a2e] rounded-xl p-4 border border-gray-800">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 bg-purple-500/20 rounded-lg flex items-center justify-center">
              <HardDrive className="w-5 h-5 text-purple-400" />
            </div>
            <div>
              <p className="text-2xl font-bold text-white">{stats.size}</p>
              <p className="text-gray-400 text-sm">Database Size</p>
            </div>
          </div>
        </div>
        <div className="bg-[#1a1a2e] rounded-xl p-4 border border-gray-800">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 bg-cyan-500/20 rounded-lg flex items-center justify-center">
              <Clock className="w-5 h-5 text-cyan-400" />
            </div>
            <div>
              <p className="text-lg font-bold text-white">{totalRows}</p>
              <p className="text-gray-400 text-sm">Total Records</p>
            </div>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
        {/* Database Info */}
        <div className="bg-[#1a1a2e] rounded-xl border border-gray-800">
          <div className="p-4 border-b border-gray-800">
            <h2 className="text-lg font-semibold text-white">Database Details</h2>
          </div>
          <div className="p-4">
            <div className="space-y-3 mb-6">
              <div className="flex justify-between py-2 border-b border-gray-800">
                <span className="text-gray-400">Engine</span>
                <span className="text-white font-mono">{stats.engine}</span>
              </div>
              <div className="flex justify-between py-2 border-b border-gray-800">
                <span className="text-gray-400">Connection URL</span>
                <span className="text-cyan-400 font-mono text-sm">{stats.url}</span>
              </div>
              <div className="flex justify-between py-2 border-b border-gray-800">
                <span className="text-gray-400">Last Backup</span>
                <span className="text-white">{stats.lastBackup || 'Never'}</span>
              </div>
            </div>

            <h3 className="text-white font-medium mb-3">Tables</h3>
            <div className="space-y-2">
              {stats.tables.map(table => (
                <div key={table.name} className="flex items-center justify-between p-3 bg-gray-800/30 rounded-lg">
                  <span className="text-gray-300 font-mono">{table.name}</span>
                  <span className="text-gray-400">{table.rows} rows</span>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Actions */}
        <div className="space-y-6">
          {/* Quick Actions */}
          <div className="bg-[#1a1a2e] rounded-xl border border-gray-800">
            <div className="p-4 border-b border-gray-800">
              <h2 className="text-lg font-semibold text-white">Quick Actions</h2>
            </div>
            <div className="p-4 space-y-3">
              <button
                onClick={handleInitialize}
                disabled={loading}
                className="w-full flex items-center justify-center gap-2 px-4 py-3 bg-green-500/20 text-green-400 rounded-lg hover:bg-green-500/30 transition-colors disabled:opacity-50"
              >
                {loading ? <Loader2 className="w-5 h-5 animate-spin" /> : <Play className="w-5 h-5" />}
                Initialize Database
              </button>
              <button
                onClick={handleBackup}
                disabled={loading}
                className="w-full flex items-center justify-center gap-2 px-4 py-3 bg-blue-500/20 text-blue-400 rounded-lg hover:bg-blue-500/30 transition-colors disabled:opacity-50"
              >
                {loading ? <Loader2 className="w-5 h-5 animate-spin" /> : <Download className="w-5 h-5" />}
                Create Backup
              </button>
              <div className="flex gap-2">
                <select
                  value={exportFormat}
                  onChange={(e) => setExportFormat(e.target.value as 'json' | 'csv')}
                  className="bg-gray-800 border border-gray-700 rounded-lg px-3 py-3 text-white"
                >
                  <option value="json">JSON</option>
                  <option value="csv">CSV</option>
                </select>
                <button
                  onClick={handleExport}
                  disabled={loading}
                  className="flex-1 flex items-center justify-center gap-2 px-4 py-3 bg-purple-500/20 text-purple-400 rounded-lg hover:bg-purple-500/30 transition-colors disabled:opacity-50"
                >
                  {exportFormat === 'json' ? <FileJson className="w-5 h-5" /> : <FileSpreadsheet className="w-5 h-5" />}
                  Export Data
                </button>
              </div>
              <button
                onClick={() => setShowClearConfirm(true)}
                disabled={loading}
                className="w-full flex items-center justify-center gap-2 px-4 py-3 bg-red-500/20 text-red-400 rounded-lg hover:bg-red-500/30 transition-colors disabled:opacity-50"
              >
                <Trash2 className="w-5 h-5" />
                Clear Database
              </button>
            </div>
          </div>

          {/* Backups */}
          <div className="bg-[#1a1a2e] rounded-xl border border-gray-800">
            <div className="p-4 border-b border-gray-800">
              <h2 className="text-lg font-semibold text-white">Backups</h2>
            </div>
            <div className="p-4">
              {backups.length === 0 ? (
                <p className="text-gray-400 text-center py-4">No backups available</p>
              ) : (
                <div className="space-y-2">
                  {backups.map(backup => (
                    <div key={backup.name} className="flex items-center justify-between p-3 bg-gray-800/30 rounded-lg">
                      <div>
                        <p className="text-white font-mono text-sm">{backup.name}</p>
                        <p className="text-gray-500 text-xs">{backup.date} - {backup.size}</p>
                      </div>
                      <div className="flex gap-2">
                        <button
                          onClick={() => handleRestore(backup.name)}
                          disabled={loading}
                          className="p-2 text-blue-400 hover:bg-blue-500/20 rounded-lg transition-colors"
                          title="Restore"
                        >
                          <Upload className="w-4 h-4" />
                        </button>
                        <button
                          onClick={() => handleDeleteBackup(backup.name)}
                          className="p-2 text-red-400 hover:bg-red-500/20 rounded-lg transition-colors"
                          title="Delete"
                        >
                          <Trash2 className="w-4 h-4" />
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* Clear Confirmation Modal */}
      {showClearConfirm && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-[#1a1a2e] rounded-xl border border-red-500/50 p-6 max-w-md w-full mx-4">
            <div className="flex items-center gap-3 mb-4">
              <div className="w-12 h-12 bg-red-500/20 rounded-full flex items-center justify-center">
                <AlertTriangle className="w-6 h-6 text-red-400" />
              </div>
              <div>
                <h3 className="text-xl font-bold text-white">Clear Database?</h3>
                <p className="text-gray-400 text-sm">This action cannot be undone</p>
              </div>
            </div>
            <p className="text-gray-300 mb-6">
              This will delete all scans, vulnerabilities, and remediations. The admin user will be preserved.
            </p>
            <div className="flex gap-3">
              <button
                onClick={() => setShowClearConfirm(false)}
                className="flex-1 px-4 py-2 bg-gray-700 text-white rounded-lg hover:bg-gray-600 transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={handleClear}
                disabled={loading}
                className="flex-1 px-4 py-2 bg-red-500 text-white rounded-lg hover:bg-red-600 transition-colors disabled:opacity-50"
              >
                {loading ? 'Clearing...' : 'Clear Database'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
