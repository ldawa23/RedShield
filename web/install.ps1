# Install web application dependencies
Write-Host "Installing RedShield Web Application..." -ForegroundColor Cyan
Write-Host ""

# Check if Node.js is installed
try {
    $nodeVersion = node --version
    Write-Host "✓ Node.js $nodeVersion found" -ForegroundColor Green
} catch {
    Write-Host "✗ Node.js not found. Please install Node.js 18+ from https://nodejs.org" -ForegroundColor Red
    exit 1
}

# Check if npm is installed
try {
    $npmVersion = npm --version
    Write-Host "✓ npm $npmVersion found" -ForegroundColor Green
} catch {
    Write-Host "✗ npm not found" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "Installing server dependencies..." -ForegroundColor Yellow
Set-Location -Path "server"
npm install

Write-Host ""
Write-Host "Installing client dependencies..." -ForegroundColor Yellow
Set-Location -Path "../client"
npm install

Set-Location -Path ".."

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  RedShield Web Installation Complete!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "To start the application:" -ForegroundColor White
Write-Host "  1. Run: npm run dev" -ForegroundColor Yellow
Write-Host "  2. Open: http://localhost:5173" -ForegroundColor Yellow
Write-Host ""
Write-Host "First user registered will be admin!" -ForegroundColor Magenta
