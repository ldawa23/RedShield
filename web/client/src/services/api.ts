import axios from 'axios';

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:3001/api';

export const api = axios.create({
  baseURL: API_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Add auth token to requests
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// Handle auth errors
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      localStorage.removeItem('token');
      window.location.href = '/login';
    }
    return Promise.reject(error);
  }
);

// Auth API
export const authApi = {
  login: (data: { username: string; password: string }) => api.post('/auth/login', data),
  register: (data: { username: string; password: string; role?: string }) => api.post('/auth/register', data),
  me: () => api.get('/auth/me'),
};

// API functions
export const statsApi = {
  getDashboard: () => api.get('/stats'),
  getTrends: (days = 30) => api.get(`/stats/trends?days=${days}`),
  getSeverity: () => api.get('/stats/severity'),
  getFixRate: () => api.get('/stats/fix-rate'),
  getTopServices: () => api.get('/stats/top-services'),
  getOwasp: () => api.get('/stats/owasp'),
  getRealtime: () => api.get('/stats/realtime'),
};

export const scansApi = {
  getAll: () => api.get('/scans'),
  getById: (scanId: string) => api.get(`/scans/${scanId}`),
  compare: (scanId1: string, scanId2: string) => api.get(`/scans/compare/${scanId1}/${scanId2}`),
  getByTarget: (target: string) => api.get(`/scans/target/${target}`),
  delete: (scanId: string) => api.delete(`/scans/${scanId}`),
};

export const vulnerabilitiesApi = {
  getAll: (params?: { page?: number; limit?: number; severity?: string; status?: string }) =>
    api.get('/vulnerabilities', { params }),
  getById: (id: number) => api.get(`/vulnerabilities/${id}`),
  getByScan: (scanId: string) => api.get(`/vulnerabilities/scan/${scanId}`),
  getSeverityStats: () => api.get('/vulnerabilities/stats/severity'),
  getTypes: () => api.get('/vulnerabilities/stats/types'),
  getRemediation: (id: number) => api.get(`/vulnerabilities/${id}/remediation`),
};

export const vulnsApi = vulnerabilitiesApi; // Alias

export const activityApi = {
  getAll: (limit: number = 100) => api.get('/activity', { params: { limit } }),
  log: (data: { action: string; resourceType?: string; resourceId?: string; details?: string }) =>
    api.post('/activity', data),
  getSummary: () => api.get('/activity/summary'),
};

export default api;
