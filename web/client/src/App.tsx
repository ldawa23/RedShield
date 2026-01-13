import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { useState, useEffect, createContext } from 'react';
import Sidebar from './components/Sidebar';
import { Dashboard, Scans, ScanDetails, Vulnerabilities, Reports, Activity, Settings, Login, NewScan, Exploits, Fix, Users, AttackFlow, ReportGenerator } from './pages';
import { api } from './services/api';

// Auth Context
interface User {
  id: number;
  username: string;
  role: 'admin' | 'user';
}

interface AuthContextType {
  user: User | null;
  token: string | null;
  login: (username: string, password: string) => Promise<void>;
  logout: () => void;
  isAuthenticated: boolean;
  isAdmin: boolean;
}

export const AuthContext = createContext<AuthContextType | null>(null);

// Protected Route for Admin-only pages
function AdminRoute({ children }: { children: React.ReactNode }) {
  const auth = useContext(AuthContext);
  if (!auth?.isAdmin) {
    return (
      <div className="flex items-center justify-center h-full bg-gradient-to-br from-red-900/20 to-black p-8">
        <div className="bg-[#1a1a2e] border border-red-500/50 rounded-xl p-8 text-center max-w-md">
          <div className="w-16 h-16 bg-red-500/20 rounded-full flex items-center justify-center mx-auto mb-4">
            <svg className="w-8 h-8 text-red-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
            </svg>
          </div>
          <h2 className="text-xl font-bold text-white mb-2">Access Denied</h2>
          <p className="text-gray-400">This feature requires administrator privileges. Contact your admin for access.</p>
        </div>
      </div>
    );
  }
  return <>{children}</>;
}

// Import useContext at top
import { useContext } from 'react';

// Layout component for authenticated pages
function AuthenticatedLayout({ children }: { children: React.ReactNode }) {
  const auth = useContext(AuthContext);
  const bgClass = auth?.isAdmin ? 'bg-gradient-to-br from-[#0f0c29] via-[#302b63] to-[#24243e]' : 'bg-gradient-to-br from-[#0a1628] via-[#1a1a3e] to-[#16213e]';
  
  return (
    <div className={`flex min-h-screen ${bgClass}`}>
      <Sidebar />
      <main className="flex-1 ml-64 overflow-auto">
        {children}
      </main>
    </div>
  );
}

function App() {
  const [user, setUser] = useState<User | null>(null);
  const [token, setToken] = useState<string | null>(localStorage.getItem('token'));
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const initAuth = async () => {
      if (token) {
        try {
          const response = await api.get('/auth/me', {
            headers: { Authorization: `Bearer ${token}` }
          });
          setUser(response.data.user);
        } catch {
          localStorage.removeItem('token');
          setToken(null);
        }
      }
      setLoading(false);
    };
    initAuth();
  }, [token]);

  const login = async (username: string, password: string) => {
    const response = await api.post('/auth/login', { username, password });
    const { token: newToken, user: newUser } = response.data;
    localStorage.setItem('token', newToken);
    setToken(newToken);
    setUser(newUser);
  };

  const logout = () => {
    localStorage.removeItem('token');
    setToken(null);
    setUser(null);
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-[#0f0c29] via-[#302b63] to-[#24243e] flex items-center justify-center">
        <div className="text-center">
          <div className="animate-spin rounded-full h-16 w-16 border-t-2 border-b-2 border-red-500 mx-auto"></div>
          <p className="text-gray-400 mt-4">Loading RedShield...</p>
        </div>
      </div>
    );
  }

  const isAdmin = user?.role === 'admin';

  return (
    <AuthContext.Provider value={{ user, token, login, logout, isAuthenticated: !!token, isAdmin }}>
      <BrowserRouter>
        {!token ? (
          <Routes>
            <Route path="*" element={<Login />} />
          </Routes>
        ) : (
          <AuthenticatedLayout>
            <Routes>
              {/* Public routes for all authenticated users */}
              <Route path="/" element={<Dashboard />} />
              <Route path="/dashboard" element={<Dashboard />} />
              <Route path="/scans" element={<Scans />} />
              <Route path="/scans/:scanId" element={<ScanDetails />} />
              <Route path="/vulnerabilities" element={<Vulnerabilities />} />
              <Route path="/attack-flow" element={<AttackFlow />} />
              <Route path="/reports" element={<Reports />} />
              <Route path="/report-generator" element={<ReportGenerator />} />
              <Route path="/activity" element={<Activity />} />
              <Route path="/settings" element={<Settings />} />
              
              {/* Admin-only routes */}
              <Route path="/new-scan" element={<AdminRoute><NewScan /></AdminRoute>} />
              <Route path="/exploits" element={<AdminRoute><Exploits /></AdminRoute>} />
              <Route path="/fix" element={<AdminRoute><Fix /></AdminRoute>} />
              <Route path="/users" element={<AdminRoute><Users /></AdminRoute>} />
              
              <Route path="*" element={<Navigate to="/" />} />
            </Routes>
          </AuthenticatedLayout>
        )}
      </BrowserRouter>
    </AuthContext.Provider>
  );
}

export default App;
