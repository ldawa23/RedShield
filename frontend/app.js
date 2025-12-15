/**
 * RedShield Dashboard - JavaScript Application
 * Handles authentication, API calls, and UI interactions
 */

// Configuration
const CONFIG = {
    apiUrl: 'http://localhost:8000',
    demoMode: true  // Set to false to use real API
};

// State
let currentUser = null;
let currentToken = null;
let scansData = [];
let vulnsData = [];

// Demo Data for testing without API
const DEMO_DATA = {
    users: [
        { username: 'admin', password: 'admin123', email: 'admin@redshield.local', role: 'admin' },
        { username: 'user', password: 'user123', email: 'user@redshield.local', role: 'user' }
    ],
    scans: [
        { scan_id: 'scan-20251211-7F765C', target: 'http://localhost/dvwa', scan_type: 'zap', status: 'completed', vuln_count: 10, created_at: '2024-12-11T10:30:00' },
        { scan_id: 'scan-20251210-A2B3C4', target: '192.168.1.100', scan_type: 'nmap', status: 'completed', vuln_count: 5, created_at: '2024-12-10T14:20:00' },
        { scan_id: 'scan-20251209-D5E6F7', target: 'https://testsite.com', scan_type: 'nuclei', status: 'completed', vuln_count: 3, created_at: '2024-12-09T09:15:00' }
    ],
    vulnerabilities: [
        { id: 1, scan_id: 'scan-20251211-7F765C', severity: 'critical', vuln_type: 'SQL Injection', target: 'http://localhost/dvwa', port: 80, status: 'pending', owasp_category: 'A03:2021-Injection', mitre_id: 'T1190' },
        { id: 2, scan_id: 'scan-20251211-7F765C', severity: 'critical', vuln_type: 'Remote OS Command Injection', target: 'http://localhost/dvwa', port: 80, status: 'pending', owasp_category: 'A03:2021-Injection', mitre_id: 'T1059' },
        { id: 3, scan_id: 'scan-20251211-7F765C', severity: 'critical', vuln_type: 'Cross Site Scripting (Reflected)', target: 'http://localhost/dvwa', port: 80, status: 'fixed', owasp_category: 'A03:2021-Injection', mitre_id: 'T1059.007' },
        { id: 4, scan_id: 'scan-20251211-7F765C', severity: 'high', vuln_type: 'Path Traversal', target: 'http://localhost/dvwa', port: 80, status: 'pending', owasp_category: 'A01:2021-Broken Access Control', mitre_id: 'T1083' },
        { id: 5, scan_id: 'scan-20251210-A2B3C4', severity: 'critical', vuln_type: 'SSH Weak Ciphers', target: '192.168.1.100', port: 22, status: 'pending', owasp_category: 'A02:2021-Cryptographic Failures', mitre_id: 'T1557' },
        { id: 6, scan_id: 'scan-20251210-A2B3C4', severity: 'medium', vuln_type: 'FTP Anonymous Login', target: '192.168.1.100', port: 21, status: 'fixed', owasp_category: 'A07:2021-Identification Failures', mitre_id: 'T1078' },
        { id: 7, scan_id: 'scan-20251209-D5E6F7', severity: 'medium', vuln_type: 'Missing Security Headers', target: 'https://testsite.com', port: 443, status: 'pending', owasp_category: 'A05:2021-Security Misconfiguration', mitre_id: 'T1189' },
        { id: 8, scan_id: 'scan-20251209-D5E6F7', severity: 'low', vuln_type: 'Information Disclosure', target: 'https://testsite.com', port: 443, status: 'pending', owasp_category: 'A01:2021-Broken Access Control', mitre_id: 'T1087' }
    ]
};

// DOM Elements
document.addEventListener('DOMContentLoaded', () => {
    initializeApp();
});

function initializeApp() {
    // Check for saved session
    const savedUser = localStorage.getItem('redshield_user');
    const savedToken = localStorage.getItem('redshield_token');
    
    if (savedUser && savedToken) {
        currentUser = JSON.parse(savedUser);
        currentToken = savedToken;
        showDashboard();
    } else {
        showLoginPage();
    }
    
    // Setup event listeners
    setupEventListeners();
}

function setupEventListeners() {
    // Login form
    document.getElementById('login-form').addEventListener('submit', handleLogin);
    
    // Register form
    document.getElementById('register-form').addEventListener('submit', handleRegister);
    
    // Toggle login/register
    document.getElementById('show-register').addEventListener('click', (e) => {
        e.preventDefault();
        document.getElementById('login-page').classList.add('d-none');
        document.getElementById('register-page').classList.remove('d-none');
    });
    
    document.getElementById('show-login').addEventListener('click', (e) => {
        e.preventDefault();
        document.getElementById('register-page').classList.add('d-none');
        document.getElementById('login-page').classList.remove('d-none');
    });
    
    // Logout
    document.getElementById('logout-btn').addEventListener('click', handleLogout);
    
    // Sidebar navigation
    document.querySelectorAll('.sidebar-menu li').forEach(item => {
        item.addEventListener('click', () => {
            const page = item.getAttribute('data-page');
            if (page) navigateTo(page);
        });
    });
    
    // Quick scan form
    document.getElementById('quick-scan-form').addEventListener('submit', handleQuickScan);
    
    // New scan modal
    document.getElementById('start-scan-btn').addEventListener('click', handleNewScan);
    
    // Report form
    document.getElementById('report-form').addEventListener('submit', handleGenerateReport);
    
    // Filter buttons
    document.querySelectorAll('.filter-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            filterVulnerabilities(btn.getAttribute('data-filter'));
        });
    });
    
    // Settings form
    document.getElementById('settings-form').addEventListener('submit', handleSaveSettings);
}

// Authentication
async function handleLogin(e) {
    e.preventDefault();
    
    const username = document.getElementById('login-username').value;
    const password = document.getElementById('login-password').value;
    const errorDiv = document.getElementById('login-error');
    
    errorDiv.classList.add('d-none');
    
    if (CONFIG.demoMode) {
        // Demo mode login
        const user = DEMO_DATA.users.find(u => u.username === username && u.password === password);
        if (user) {
            currentUser = { username: user.username, email: user.email, role: user.role };
            currentToken = 'demo-token-' + Date.now();
            localStorage.setItem('redshield_user', JSON.stringify(currentUser));
            localStorage.setItem('redshield_token', currentToken);
            showDashboard();
        } else {
            errorDiv.textContent = 'Invalid username or password';
            errorDiv.classList.remove('d-none');
        }
    } else {
        // Real API login
        try {
            const response = await fetch(`${CONFIG.apiUrl}/api/auth/login`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, password })
            });
            
            if (response.ok) {
                const data = await response.json();
                currentUser = data.user;
                currentToken = data.token;
                localStorage.setItem('redshield_user', JSON.stringify(currentUser));
                localStorage.setItem('redshield_token', currentToken);
                showDashboard();
            } else {
                const error = await response.json();
                errorDiv.textContent = error.detail || 'Login failed';
                errorDiv.classList.remove('d-none');
            }
        } catch (err) {
            errorDiv.textContent = 'Connection error. Please check if API is running.';
            errorDiv.classList.remove('d-none');
        }
    }
}

async function handleRegister(e) {
    e.preventDefault();
    
    const username = document.getElementById('register-username').value;
    const email = document.getElementById('register-email').value;
    const password = document.getElementById('register-password').value;
    const errorDiv = document.getElementById('register-error');
    const successDiv = document.getElementById('register-success');
    
    errorDiv.classList.add('d-none');
    successDiv.classList.add('d-none');
    
    if (CONFIG.demoMode) {
        // Demo mode - simulate registration
        if (DEMO_DATA.users.find(u => u.username === username)) {
            errorDiv.textContent = 'Username already exists';
            errorDiv.classList.remove('d-none');
        } else {
            DEMO_DATA.users.push({ username, email, password, role: 'user' });
            successDiv.textContent = 'Registration successful! You can now login.';
            successDiv.classList.remove('d-none');
            document.getElementById('register-form').reset();
        }
    } else {
        // Real API registration
        try {
            const response = await fetch(`${CONFIG.apiUrl}/api/auth/register`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, email, password })
            });
            
            if (response.ok) {
                successDiv.textContent = 'Registration successful! You can now login.';
                successDiv.classList.remove('d-none');
                document.getElementById('register-form').reset();
            } else {
                const error = await response.json();
                errorDiv.textContent = error.detail || 'Registration failed';
                errorDiv.classList.remove('d-none');
            }
        } catch (err) {
            errorDiv.textContent = 'Connection error. Please check if API is running.';
            errorDiv.classList.remove('d-none');
        }
    }
}

function handleLogout() {
    currentUser = null;
    currentToken = null;
    localStorage.removeItem('redshield_user');
    localStorage.removeItem('redshield_token');
    showLoginPage();
}

// Page Navigation
function showLoginPage() {
    document.getElementById('login-page').classList.remove('d-none');
    document.getElementById('register-page').classList.add('d-none');
    document.getElementById('dashboard').classList.add('d-none');
}

function showDashboard() {
    document.getElementById('login-page').classList.add('d-none');
    document.getElementById('register-page').classList.add('d-none');
    document.getElementById('dashboard').classList.remove('d-none');
    
    // Update user info
    document.getElementById('current-user').textContent = currentUser.username;
    document.getElementById('user-role').textContent = currentUser.role;
    document.getElementById('user-role').className = `badge ${currentUser.role === 'admin' ? 'bg-danger' : 'bg-secondary'}`;
    
    // Show/hide admin menu
    if (currentUser.role === 'admin') {
        document.getElementById('admin-menu').classList.remove('d-none');
    } else {
        document.getElementById('admin-menu').classList.add('d-none');
    }
    
    // Load dashboard data
    loadDashboardData();
    navigateTo('dashboard');
}

function navigateTo(page) {
    // Update sidebar
    document.querySelectorAll('.sidebar-menu li').forEach(item => {
        item.classList.toggle('active', item.getAttribute('data-page') === page);
    });
    
    // Update pages
    document.querySelectorAll('.page').forEach(p => {
        p.classList.toggle('active', p.id === `page-${page}`);
    });
    
    // Load page-specific data
    switch(page) {
        case 'dashboard':
            loadDashboardData();
            break;
        case 'scans':
            loadScansData();
            break;
        case 'vulnerabilities':
            loadVulnerabilitiesData();
            break;
        case 'reports':
            loadReportsData();
            break;
        case 'admin':
            if (currentUser.role === 'admin') {
                loadAdminData();
            }
            break;
    }
}

// Data Loading
async function loadDashboardData() {
    if (CONFIG.demoMode) {
        scansData = DEMO_DATA.scans;
        vulnsData = DEMO_DATA.vulnerabilities;
    } else {
        try {
            const [scansRes, vulnsRes] = await Promise.all([
                fetch(`${CONFIG.apiUrl}/api/scans`, {
                    headers: { 'Authorization': `Bearer ${currentToken}` }
                }),
                fetch(`${CONFIG.apiUrl}/api/vulnerabilities`, {
                    headers: { 'Authorization': `Bearer ${currentToken}` }
                })
            ]);
            
            if (scansRes.ok) scansData = await scansRes.json();
            if (vulnsRes.ok) vulnsData = await vulnsRes.json();
        } catch (err) {
            showToast('Error', 'Failed to load dashboard data', 'danger');
        }
    }
    
    updateDashboardStats();
    updateSeverityChart();
    updateRecentActivity();
}

function updateDashboardStats() {
    document.getElementById('stat-scans').textContent = scansData.length;
    document.getElementById('stat-vulns').textContent = vulnsData.length;
    document.getElementById('stat-fixed').textContent = vulnsData.filter(v => v.status === 'fixed').length;
    document.getElementById('stat-pending').textContent = vulnsData.filter(v => v.status === 'pending').length;
}

function updateSeverityChart() {
    const total = vulnsData.length || 1;
    const counts = {
        critical: vulnsData.filter(v => v.severity === 'critical').length,
        high: vulnsData.filter(v => v.severity === 'high').length,
        medium: vulnsData.filter(v => v.severity === 'medium').length,
        low: vulnsData.filter(v => v.severity === 'low').length
    };
    
    ['critical', 'high', 'medium', 'low'].forEach(sev => {
        const bar = document.getElementById(`bar-${sev}`);
        const pct = (counts[sev] / total) * 100;
        bar.style.width = `${Math.max(pct, counts[sev] > 0 ? 10 : 0)}%`;
        bar.textContent = counts[sev];
    });
}

function updateRecentActivity() {
    const container = document.getElementById('recent-activity');
    const activities = [];
    
    // Recent scans
    scansData.slice(0, 3).forEach(scan => {
        activities.push({
            icon: 'bi-search',
            iconClass: 'bg-primary',
            text: `Scan completed: ${scan.target}`,
            time: formatDate(scan.created_at)
        });
    });
    
    // Recent vulnerabilities
    vulnsData.slice(0, 3).forEach(vuln => {
        activities.push({
            icon: 'bi-bug',
            iconClass: vuln.severity === 'critical' ? 'bg-danger' : 'bg-warning',
            text: `${vuln.severity.toUpperCase()} vulnerability: ${vuln.vuln_type}`,
            time: 'Recently'
        });
    });
    
    if (activities.length === 0) {
        container.innerHTML = '<p class="text-muted">No recent activity</p>';
        return;
    }
    
    container.innerHTML = activities.slice(0, 5).map(act => `
        <div class="activity-item">
            <div class="activity-icon ${act.iconClass}">
                <i class="bi ${act.icon}"></i>
            </div>
            <div class="activity-details">
                <p>${act.text}</p>
                <small>${act.time}</small>
            </div>
        </div>
    `).join('');
}

async function loadScansData() {
    if (CONFIG.demoMode) {
        scansData = DEMO_DATA.scans;
    } else {
        try {
            const response = await fetch(`${CONFIG.apiUrl}/api/scans`, {
                headers: { 'Authorization': `Bearer ${currentToken}` }
            });
            if (response.ok) {
                scansData = await response.json();
            }
        } catch (err) {
            showToast('Error', 'Failed to load scans', 'danger');
        }
    }
    
    renderScansTable();
}

function renderScansTable() {
    const tbody = document.getElementById('scans-tbody');
    
    if (scansData.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" class="text-center text-muted">No scans found. Start a new scan to get started.</td></tr>';
        return;
    }
    
    tbody.innerHTML = scansData.map(scan => `
        <tr>
            <td><code>${scan.scan_id}</code></td>
            <td>${scan.target}</td>
            <td><span class="badge bg-info">${scan.scan_type.toUpperCase()}</span></td>
            <td><span class="badge status-${scan.status}">${scan.status}</span></td>
            <td>${scan.vuln_count || 0}</td>
            <td>${formatDate(scan.created_at)}</td>
            <td>
                <button class="btn btn-sm btn-outline-primary btn-action" onclick="viewScanDetails('${scan.scan_id}')" title="View Details">
                    <i class="bi bi-eye"></i>
                </button>
                <button class="btn btn-sm btn-outline-success btn-action" onclick="generateReportFor('${scan.scan_id}')" title="Generate Report">
                    <i class="bi bi-file-earmark-text"></i>
                </button>
            </td>
        </tr>
    `).join('');
}

async function loadVulnerabilitiesData() {
    if (CONFIG.demoMode) {
        vulnsData = DEMO_DATA.vulnerabilities;
    } else {
        try {
            const response = await fetch(`${CONFIG.apiUrl}/api/vulnerabilities`, {
                headers: { 'Authorization': `Bearer ${currentToken}` }
            });
            if (response.ok) {
                vulnsData = await response.json();
            }
        } catch (err) {
            showToast('Error', 'Failed to load vulnerabilities', 'danger');
        }
    }
    
    renderVulnerabilitiesTable(vulnsData);
}

function renderVulnerabilitiesTable(data) {
    const tbody = document.getElementById('vulns-tbody');
    
    if (data.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" class="text-center text-muted">No vulnerabilities found.</td></tr>';
        return;
    }
    
    tbody.innerHTML = data.map(vuln => `
        <tr>
            <td>#${vuln.id}</td>
            <td><span class="badge badge-${vuln.severity}">${vuln.severity.toUpperCase()}</span></td>
            <td>${vuln.vuln_type}</td>
            <td>${vuln.target}</td>
            <td>${vuln.port || '-'}</td>
            <td><span class="badge status-${vuln.status === 'fixed' ? 'completed' : 'pending'}">${vuln.status}</span></td>
            <td>
                <button class="btn btn-sm btn-outline-info btn-action" onclick="viewVulnDetails(${vuln.id})" title="View Details">
                    <i class="bi bi-eye"></i>
                </button>
                ${vuln.status !== 'fixed' ? `
                <button class="btn btn-sm btn-outline-warning btn-action" onclick="showFixModal(${vuln.id})" title="Fix Vulnerability">
                    <i class="bi bi-wrench"></i>
                </button>
                ` : ''}
            </td>
        </tr>
    `).join('');
}

function filterVulnerabilities(severity) {
    if (severity === 'all') {
        renderVulnerabilitiesTable(vulnsData);
    } else {
        const filtered = vulnsData.filter(v => v.severity === severity);
        renderVulnerabilitiesTable(filtered);
    }
}

async function loadReportsData() {
    // Populate scan dropdown
    const select = document.getElementById('report-scan-id');
    select.innerHTML = '<option value="">Select a scan...</option>';
    
    scansData.forEach(scan => {
        select.innerHTML += `<option value="${scan.scan_id}">${scan.scan_id} - ${scan.target}</option>`;
    });
}

async function loadAdminData() {
    if (currentUser.role !== 'admin') return;
    
    const tbody = document.getElementById('users-tbody');
    
    if (CONFIG.demoMode) {
        tbody.innerHTML = DEMO_DATA.users.map(user => `
            <tr>
                <td>${user.username}</td>
                <td>${user.email}</td>
                <td><span class="badge ${user.role === 'admin' ? 'bg-danger' : 'bg-secondary'}">${user.role}</span></td>
                <td>
                    ${user.username !== 'admin' ? `
                    <button class="btn btn-sm btn-outline-warning btn-action" onclick="toggleUserRole('${user.username}')" title="Toggle Role">
                        <i class="bi bi-person-gear"></i>
                    </button>
                    <button class="btn btn-sm btn-outline-danger btn-action" onclick="deleteUser('${user.username}')" title="Delete User">
                        <i class="bi bi-trash"></i>
                    </button>
                    ` : '-'}
                </td>
            </tr>
        `).join('');
    } else {
        try {
            const response = await fetch(`${CONFIG.apiUrl}/api/admin/users`, {
                headers: { 'Authorization': `Bearer ${currentToken}` }
            });
            if (response.ok) {
                const users = await response.json();
                tbody.innerHTML = users.map(user => `
                    <tr>
                        <td>${user.username}</td>
                        <td>${user.email}</td>
                        <td><span class="badge ${user.role === 'admin' ? 'bg-danger' : 'bg-secondary'}">${user.role}</span></td>
                        <td>
                            ${user.username !== 'admin' ? `
                            <button class="btn btn-sm btn-outline-warning" onclick="toggleUserRole('${user.username}')">
                                <i class="bi bi-person-gear"></i>
                            </button>
                            <button class="btn btn-sm btn-outline-danger" onclick="deleteUser('${user.username}')">
                                <i class="bi bi-trash"></i>
                            </button>
                            ` : '-'}
                        </td>
                    </tr>
                `).join('');
            }
        } catch (err) {
            tbody.innerHTML = '<tr><td colspan="4" class="text-danger">Failed to load users</td></tr>';
        }
    }
}

// Scan Operations
async function handleQuickScan(e) {
    e.preventDefault();
    
    const target = document.getElementById('scan-target').value;
    const scanner = document.getElementById('scan-scanner').value;
    
    await startScan(target, scanner);
}

async function handleNewScan() {
    const target = document.getElementById('modal-target').value;
    const scanner = document.getElementById('modal-scanner').value;
    
    if (!target) {
        showToast('Error', 'Please enter a target', 'danger');
        return;
    }
    
    // Close modal
    bootstrap.Modal.getInstance(document.getElementById('newScanModal')).hide();
    
    await startScan(target, scanner);
}

async function startScan(target, scanner) {
    showToast('Scan Started', `Scanning ${target}...`, 'info');
    
    if (CONFIG.demoMode) {
        // Simulate scan
        const newScan = {
            scan_id: `scan-${Date.now().toString(36).toUpperCase()}`,
            target: target,
            scan_type: scanner === 'auto' ? 'nmap' : scanner,
            status: 'completed',
            vuln_count: Math.floor(Math.random() * 5) + 1,
            created_at: new Date().toISOString()
        };
        
        DEMO_DATA.scans.unshift(newScan);
        
        // Add some demo vulnerabilities
        const vulnTypes = ['SQL Injection', 'XSS', 'SSH Weak Ciphers', 'Open Port', 'Missing Headers'];
        const severities = ['critical', 'high', 'medium', 'low'];
        
        for (let i = 0; i < newScan.vuln_count; i++) {
            DEMO_DATA.vulnerabilities.push({
                id: DEMO_DATA.vulnerabilities.length + 1,
                scan_id: newScan.scan_id,
                severity: severities[Math.floor(Math.random() * severities.length)],
                vuln_type: vulnTypes[Math.floor(Math.random() * vulnTypes.length)],
                target: target,
                port: Math.floor(Math.random() * 1000) + 20,
                status: 'pending',
                owasp_category: 'A03:2021-Injection',
                mitre_id: 'T1190'
            });
        }
        
        showToast('Scan Complete', `Found ${newScan.vuln_count} vulnerabilities`, 'success');
        loadDashboardData();
    } else {
        try {
            const response = await fetch(`${CONFIG.apiUrl}/api/scans`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${currentToken}`
                },
                body: JSON.stringify({ target, scanner })
            });
            
            if (response.ok) {
                const result = await response.json();
                showToast('Scan Complete', `Scan ${result.scan_id} completed`, 'success');
                loadDashboardData();
            } else {
                const error = await response.json();
                showToast('Scan Failed', error.detail || 'Failed to start scan', 'danger');
            }
        } catch (err) {
            showToast('Error', 'Connection error. Please check if API is running.', 'danger');
        }
    }
    
    // Clear form
    document.getElementById('scan-target').value = '';
    document.getElementById('modal-target').value = '';
}

// Vulnerability Operations
function viewVulnDetails(vulnId) {
    const vuln = vulnsData.find(v => v.id === vulnId);
    if (!vuln) return;
    
    const modal = new bootstrap.Modal(document.getElementById('fixVulnModal'));
    
    document.getElementById('fix-vuln-content').innerHTML = `
        <div class="vuln-details">
            <h5><span class="badge badge-${vuln.severity}">${vuln.severity.toUpperCase()}</span> ${vuln.vuln_type}</h5>
            <dl>
                <dt>Target</dt>
                <dd>${vuln.target}:${vuln.port || 'N/A'}</dd>
                
                <dt>Status</dt>
                <dd><span class="badge status-${vuln.status === 'fixed' ? 'completed' : 'pending'}">${vuln.status}</span></dd>
                
                <dt>OWASP Category</dt>
                <dd>${vuln.owasp_category || 'N/A'}</dd>
                
                <dt>MITRE ATT&CK</dt>
                <dd>${vuln.mitre_id || 'N/A'}</dd>
                
                <dt>Scan ID</dt>
                <dd><code>${vuln.scan_id}</code></dd>
            </dl>
        </div>
    `;
    
    // Store current vuln ID for fix buttons
    document.getElementById('fixVulnModal').setAttribute('data-vuln-id', vulnId);
    
    modal.show();
}

function showFixModal(vulnId) {
    const vuln = vulnsData.find(v => v.id === vulnId);
    if (!vuln) return;
    
    const modal = new bootstrap.Modal(document.getElementById('fixVulnModal'));
    
    document.getElementById('fix-vuln-content').innerHTML = `
        <div class="vuln-details">
            <h5><span class="badge badge-${vuln.severity}">${vuln.severity.toUpperCase()}</span> ${vuln.vuln_type}</h5>
            <dl>
                <dt>Target</dt>
                <dd>${vuln.target}:${vuln.port || 'N/A'}</dd>
                
                <dt>Remediation</dt>
                <dd>
                    <div class="code-block">
# Suggested fix for ${vuln.vuln_type}
# Run the following command to apply automated remediation:

redshield fix ${vulnId}

# Or for dry-run (preview only):
redshield fix ${vulnId} --dry-run
                    </div>
                </dd>
            </dl>
        </div>
    `;
    
    document.getElementById('fixVulnModal').setAttribute('data-vuln-id', vulnId);
    
    // Setup fix buttons
    document.getElementById('dry-run-btn').onclick = () => applyFix(vulnId, true);
    document.getElementById('apply-fix-btn').onclick = () => applyFix(vulnId, false);
    
    modal.show();
}

async function applyFix(vulnId, dryRun = false) {
    showToast('Fix', dryRun ? 'Running dry-run...' : 'Applying fix...', 'info');
    
    if (CONFIG.demoMode) {
        setTimeout(() => {
            if (!dryRun) {
                const vuln = DEMO_DATA.vulnerabilities.find(v => v.id === vulnId);
                if (vuln) vuln.status = 'fixed';
                loadVulnerabilitiesData();
            }
            showToast('Success', dryRun ? 'Dry-run completed successfully' : 'Fix applied successfully', 'success');
            bootstrap.Modal.getInstance(document.getElementById('fixVulnModal')).hide();
        }, 1000);
    } else {
        try {
            const response = await fetch(`${CONFIG.apiUrl}/api/vulnerabilities/${vulnId}/fix`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${currentToken}`
                },
                body: JSON.stringify({ dry_run: dryRun })
            });
            
            if (response.ok) {
                const result = await response.json();
                showToast('Success', result.message || 'Fix applied', 'success');
                loadVulnerabilitiesData();
                bootstrap.Modal.getInstance(document.getElementById('fixVulnModal')).hide();
            } else {
                const error = await response.json();
                showToast('Error', error.detail || 'Failed to apply fix', 'danger');
            }
        } catch (err) {
            showToast('Error', 'Connection error', 'danger');
        }
    }
}

// Report Operations
async function handleGenerateReport(e) {
    e.preventDefault();
    
    const scanId = document.getElementById('report-scan-id').value;
    const format = document.getElementById('report-format').value;
    
    if (!scanId) {
        showToast('Error', 'Please select a scan', 'danger');
        return;
    }
    
    const preview = document.getElementById('report-preview');
    preview.innerHTML = '<div class="text-center"><div class="spinner"></div> Generating report...</div>';
    
    if (CONFIG.demoMode) {
        setTimeout(() => {
            const scan = DEMO_DATA.scans.find(s => s.scan_id === scanId);
            const scanVulns = DEMO_DATA.vulnerabilities.filter(v => v.scan_id === scanId);
            
            let report = '';
            if (format === 'json') {
                report = JSON.stringify({ scan, vulnerabilities: scanVulns }, null, 2);
            } else if (format === 'summary') {
                report = `
REDSHIELD SECURITY REPORT
========================
Scan ID: ${scan.scan_id}
Target: ${scan.target}
Type: ${scan.scan_type.toUpperCase()}
Date: ${formatDate(scan.created_at)}

SUMMARY
-------
Total Vulnerabilities: ${scanVulns.length}
Critical: ${scanVulns.filter(v => v.severity === 'critical').length}
High: ${scanVulns.filter(v => v.severity === 'high').length}
Medium: ${scanVulns.filter(v => v.severity === 'medium').length}
Low: ${scanVulns.filter(v => v.severity === 'low').length}

VULNERABILITIES
---------------
${scanVulns.map(v => `[${v.severity.toUpperCase()}] ${v.vuln_type} (Port: ${v.port})`).join('\n')}
                `;
            } else {
                report = `
<h3>Security Report</h3>
<p><strong>Scan ID:</strong> ${scan.scan_id}</p>
<p><strong>Target:</strong> ${scan.target}</p>
<p><strong>Date:</strong> ${formatDate(scan.created_at)}</p>
<hr>
<h4>Vulnerabilities Found: ${scanVulns.length}</h4>
<ul>
${scanVulns.map(v => `<li><span class="badge badge-${v.severity}">${v.severity}</span> ${v.vuln_type}</li>`).join('')}
</ul>
                `;
            }
            
            preview.innerHTML = format === 'html' ? report : `<pre>${report}</pre>`;
        }, 500);
    } else {
        try {
            const response = await fetch(`${CONFIG.apiUrl}/api/reports/${scanId}?format=${format}`, {
                headers: { 'Authorization': `Bearer ${currentToken}` }
            });
            
            if (response.ok) {
                const data = await response.text();
                preview.innerHTML = format === 'html' ? data : `<pre>${data}</pre>`;
            } else {
                preview.innerHTML = '<p class="text-danger">Failed to generate report</p>';
            }
        } catch (err) {
            preview.innerHTML = '<p class="text-danger">Connection error</p>';
        }
    }
}

function generateReportFor(scanId) {
    navigateTo('reports');
    document.getElementById('report-scan-id').value = scanId;
}

function viewScanDetails(scanId) {
    navigateTo('vulnerabilities');
    // Filter vulnerabilities by scan
    const filtered = vulnsData.filter(v => v.scan_id === scanId);
    renderVulnerabilitiesTable(filtered);
}

// Admin Operations
function toggleUserRole(username) {
    if (!confirm(`Toggle role for user ${username}?`)) return;
    
    if (CONFIG.demoMode) {
        const user = DEMO_DATA.users.find(u => u.username === username);
        if (user) {
            user.role = user.role === 'admin' ? 'user' : 'admin';
            loadAdminData();
            showToast('Success', `User ${username} role updated`, 'success');
        }
    }
}

function deleteUser(username) {
    if (!confirm(`Delete user ${username}? This cannot be undone.`)) return;
    
    if (CONFIG.demoMode) {
        DEMO_DATA.users = DEMO_DATA.users.filter(u => u.username !== username);
        loadAdminData();
        showToast('Success', `User ${username} deleted`, 'success');
    }
}

function handleSaveSettings(e) {
    e.preventDefault();
    
    CONFIG.apiUrl = document.getElementById('api-url').value;
    CONFIG.demoMode = document.getElementById('demo-mode').checked;
    
    localStorage.setItem('redshield_config', JSON.stringify(CONFIG));
    showToast('Settings Saved', 'Configuration updated', 'success');
}

// Utility Functions
function formatDate(dateStr) {
    if (!dateStr) return 'N/A';
    const date = new Date(dateStr);
    return date.toLocaleDateString() + ' ' + date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

function showToast(title, message, type = 'info') {
    const toast = document.getElementById('toast');
    const toastTitle = document.getElementById('toast-title');
    const toastBody = document.getElementById('toast-body');
    
    toastTitle.textContent = title;
    toastBody.textContent = message;
    
    // Update toast color based on type
    toast.className = 'toast';
    if (type === 'success') toast.style.borderLeft = '4px solid var(--success)';
    else if (type === 'danger') toast.style.borderLeft = '4px solid var(--danger)';
    else if (type === 'warning') toast.style.borderLeft = '4px solid var(--warning)';
    else toast.style.borderLeft = '4px solid var(--info)';
    
    const bsToast = new bootstrap.Toast(toast);
    bsToast.show();
}

// Initialize settings from localStorage
const savedConfig = localStorage.getItem('redshield_config');
if (savedConfig) {
    Object.assign(CONFIG, JSON.parse(savedConfig));
}

