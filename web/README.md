# RedShield Web Application

A professional, full-stack security operations dashboard for vulnerability management.

## Tech Stack

### Frontend
- **React 18** - Modern UI framework with hooks
- **TypeScript** - Type-safe development
- **Vite** - Lightning-fast build tool
- **Tailwind CSS** - Utility-first styling
- **Recharts** - Beautiful charts and visualizations
- **Framer Motion** - Smooth animations
- **Lucide React** - Modern icons

### Backend
- **Node.js + Express** - Fast, minimal API server
- **TypeScript** - Type-safe backend
- **better-sqlite3** - High-performance SQLite
- **JWT** - Secure authentication
- **bcryptjs** - Password hashing
- **Socket.IO** - Real-time updates (optional)

## Prerequisites

- Node.js 18+ installed
- npm or pnpm package manager
- RedShield CLI already set up (for database access)

## Installation

### 1. Install Server Dependencies

```bash
cd web/server
npm install
```

### 2. Install Client Dependencies

```bash
cd web/client
npm install
```

### 3. Or Install All at Once (from web folder)

```bash
cd web
npm install
```

## Running the Application

### Development Mode

**Option 1: Run both simultaneously (from web folder)**
```bash
cd web
npm run dev
```

**Option 2: Run separately**

Terminal 1 - Backend:
```bash
cd web/server
npm run dev
```

Terminal 2 - Frontend:
```bash
cd web/client
npm run dev
```

### Production Build

```bash
# Build client
cd web/client
npm run build

# Start server (serves built client)
cd web/server
npm start
```

## Access

- **Frontend**: http://localhost:5173 (development)
- **Backend API**: http://localhost:3000/api
- **Production**: http://localhost:3000 (serves both)

## Default Credentials

On first run, register a new account. The first user will automatically be assigned **admin** role.

For testing, you can create:
- Username: `admin`
- Password: `admin123`

## Features

### Dashboard
- Real-time vulnerability statistics
- Severity distribution pie chart
- Vulnerability discovery trend (30 days)
- Remediation status bar chart
- Recent scans list
- 24-hour activity summary

### Scans
- List all security scans
- Filter by status
- Search by target or scan ID
- View detailed scan reports
- Compare two scans
- Delete scans

### Vulnerabilities
- Comprehensive vulnerability list
- Filter by severity and status
- Search by name, CVE, or description
- Expandable details with OWASP/MITRE mappings
- External links to NVD and MITRE
- Remediation details for fixed vulnerabilities

### Reports
- Generate custom reports
- Multiple output formats (PDF, HTML, JSON)
- Executive, Technical, and Compliance templates
- Select multiple scans for combined reports

### Activity Log
- Track all security operations
- Filter by activity type
- Timeline view grouped by date
- Activity statistics

### Settings
- Profile management
- Security settings (password change)
- Notification preferences
- System configuration

## API Endpoints

### Authentication
- `POST /api/auth/register` - Register new user
- `POST /api/auth/login` - User login
- `GET /api/auth/me` - Get current user
- `POST /api/auth/logout` - Logout

### Scans
- `GET /api/scans` - List all scans
- `GET /api/scans/:scanId` - Get scan details
- `GET /api/scans/compare/:id1/:id2` - Compare two scans
- `DELETE /api/scans/:scanId` - Delete a scan

### Vulnerabilities
- `GET /api/vulnerabilities` - List all vulnerabilities
- `GET /api/vulnerabilities/:id` - Get vulnerability details
- `GET /api/vulnerabilities/scan/:scanId` - Get vulnerabilities by scan

### Statistics
- `GET /api/stats` - Dashboard statistics
- `GET /api/stats/trends` - Vulnerability trends
- `GET /api/stats/realtime` - Real-time stats

### Activity
- `GET /api/activity` - Get activity log
- `POST /api/activity` - Log an activity

## Database

The web application shares the SQLite database with the CLI tool at:
```
RedShield/redshield.db
```

This ensures both CLI and web interface show the same data.

## Environment Variables

Create a `.env` file in `web/server`:

```env
PORT=3000
JWT_SECRET=your-super-secret-key
DB_PATH=../../redshield.db
```

## Troubleshooting

### Database not found
Ensure you've run at least one CLI scan first to create the database, or the web server will create an empty one.

### Port already in use
Change the port in `.env` or kill the process using the port:
```bash
# Windows
netstat -ano | findstr :3000
taskkill /PID <PID> /F
```

### TypeScript errors
Run `npm install` in both server and client directories to ensure all type definitions are installed.

## Development Notes

- Frontend hot-reloads on file changes
- Backend uses nodemon for auto-restart
- Tailwind CSS JIT compilation for instant style updates
- API proxy configured in Vite to avoid CORS issues

## Customization

### Theme Colors
Edit `web/client/tailwind.config.js` to customize the dark theme colors.

### Adding New Pages
1. Create component in `web/client/src/pages/`
2. Add route in `web/client/src/App.tsx`
3. Add navigation link in `web/client/src/components/Layout.tsx`

### Adding New API Endpoints
1. Create route file in `web/server/src/routes/`
2. Register route in `web/server/src/index.ts`
3. Add API function in `web/client/src/services/api.ts`
