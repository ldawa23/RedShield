import { NavLink, useLocation } from 'react-router-dom';
import { useContext } from 'react';
import { AuthContext } from '../App';
import {
  LayoutDashboard,
  FileText,
  Shield,
  Activity,
  Settings,
  LogOut,
  ChevronRight,
  AlertTriangle,
  Scan,
  Wrench,
  History,
  Lock,
  Crown,
  Users,
  Target,
  FileCode,
  Database,
  Radar
} from 'lucide-react';

interface MenuItem {
  path: string;
  icon: any;
  label: string;
  highlight?: boolean;
  adminOnly?: boolean;
}

const menuItems: MenuItem[] = [
  { path: '/', icon: LayoutDashboard, label: 'Dashboard' },
  { path: '/new-scan', icon: Scan, label: 'New Scan', highlight: true, adminOnly: true },
  { path: '/scans', icon: History, label: 'Scan History' },
  { path: '/detect', icon: Radar, label: 'Detection Engine', adminOnly: true },
  { path: '/vulnerabilities', icon: AlertTriangle, label: 'Vulnerabilities' },
  { path: '/signatures', icon: FileCode, label: 'Signatures' },
  { path: '/attack-flow', icon: Target, label: 'Attack Flow' },
  { path: '/fix', icon: Wrench, label: 'Fix', adminOnly: true },
  { path: '/reports', icon: FileText, label: 'Reports' },
  { path: '/report-generator', icon: FileText, label: 'Report Generator' },
  { path: '/database', icon: Database, label: 'Database', adminOnly: true },
  { path: '/activity', icon: Activity, label: 'Activity Log' },
  { path: '/users', icon: Users, label: 'User Management', adminOnly: true },
  { path: '/settings', icon: Settings, label: 'Settings' },
];

export default function Sidebar() {
  const location = useLocation();
  const auth = useContext(AuthContext);
  const isAdmin = auth?.user?.role === 'admin';

  // Sidebar background based on role
  const sidebarBg = isAdmin 
    ? 'bg-gradient-to-b from-[#1a0a2e] to-[#0d1f3c]' 
    : 'bg-gradient-to-b from-[#0d1f3c] to-[#081225]';

  return (
    <div className={`fixed left-0 top-0 h-screen w-64 ${sidebarBg} border-r border-gray-800 flex flex-col z-50`}>
      {/* Logo */}
      <div className="p-6 border-b border-gray-800">
        <div className="flex items-center gap-3">
          <div className={`w-10 h-10 ${isAdmin ? 'bg-gradient-to-br from-purple-500 to-pink-600' : 'bg-gradient-to-br from-red-500 to-red-700'} rounded-lg flex items-center justify-center`}>
            <Shield className="w-6 h-6 text-white" />
          </div>
          <div>
            <span className="text-xl font-bold text-white">RedShield</span>
            {isAdmin && (
              <div className="flex items-center gap-1 text-xs text-purple-400">
                <Crown className="w-3 h-3" />
                Admin Mode
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 p-4 space-y-1 overflow-y-auto">
        {menuItems.map((item) => {
          const isActive = location.pathname === item.path;
          const isHighlight = item.highlight;
          const isAdminOnly = item.adminOnly;
          const isDisabled = isAdminOnly && !isAdmin;
          
          return (
            <NavLink
              key={item.path}
              to={isDisabled ? '#' : item.path}
              onClick={(e) => isDisabled && e.preventDefault()}
              className={`flex items-center gap-3 px-4 py-3 rounded-lg transition-all duration-200 group ${
                isDisabled
                  ? 'text-gray-600 cursor-not-allowed opacity-50'
                  : isActive 
                    ? isAdmin 
                      ? 'bg-purple-500/20 text-purple-400 border-l-4 border-purple-500'
                      : 'bg-red-500/20 text-red-400 border-l-4 border-red-500' 
                    : isHighlight
                      ? 'bg-green-500/10 text-green-400 hover:bg-green-500/20'
                      : 'text-gray-400 hover:bg-gray-800/50 hover:text-white'
              }`}
            >
              <item.icon className={`w-5 h-5 ${
                isDisabled ? 'text-gray-600' :
                isActive ? (isAdmin ? 'text-purple-400' : 'text-red-400') : 
                isHighlight ? 'text-green-400' : 
                'text-gray-500 group-hover:text-white'
              }`} />
              <span className="font-medium flex-1">{item.label}</span>
              {isAdminOnly && !isAdmin && <Lock className="w-4 h-4 text-gray-600" />}
              {isAdminOnly && isAdmin && <Crown className="w-4 h-4 text-purple-400" />}
              {isActive && !isDisabled && <ChevronRight className="w-4 h-4" />}
            </NavLink>
          );
        })}
      </nav>

      {/* User Section */}
      <div className="p-4 border-t border-gray-800">
        <div className="flex items-center gap-3 px-4 py-3 rounded-lg bg-gray-800/30">
          <div className={`w-10 h-10 ${isAdmin ? 'bg-gradient-to-br from-purple-500 to-pink-600' : 'bg-gradient-to-br from-blue-500 to-cyan-600'} rounded-full flex items-center justify-center`}>
            {isAdmin ? (
              <Crown className="w-5 h-5 text-white" />
            ) : (
              <Users className="w-5 h-5 text-white" />
            )}
          </div>
          <div className="flex-1">
            <p className="text-white font-medium text-sm">{auth?.user?.username || 'User'}</p>
            <p className={`text-xs capitalize ${isAdmin ? 'text-purple-400' : 'text-cyan-400'}`}>
              {isAdmin ? 'Administrator' : 'Standard User'}
            </p>
          </div>
          <button 
            onClick={() => auth?.logout()}
            className="p-2 text-gray-500 hover:text-red-400 hover:bg-red-500/10 rounded-lg transition-colors"
            title="Logout"
          >
            <LogOut className="w-5 h-5" />
          </button>
        </div>
      </div>
    </div>
  );
}
