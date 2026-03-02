# Fillr Setup Script
# Initializes environment configuration files

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Fillr Environment Setup" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Environment file paths
$clientEnv = "client\env.js"
$clientExample = "client\env.example.js"
$extEnv = "extension\env.js"
$extExample = "extension\env.example.js"
$serverEnv = "server\.env"

# Function to copy if not exists
function Copy-IfMissing {
    param(
        [string]$Source,
        [string]$Dest,
        [string]$Name
    )
    
    if (Test-Path $Dest) {
        Write-Host "[SKIP] " -NoNewline -ForegroundColor Yellow
        Write-Host "$Name already exists: $Dest"
        return $true
    }
    
    if (Test-Path $Source) {
        Copy-Item $Source $Dest
        Write-Host "[OK] " -NoNewline -ForegroundColor Green
        Write-Host "Created $Name`: $Dest"
        return $true
    }
    
    Write-Host "[ERROR] " -NoNewline -ForegroundColor Red
    Write-Host "Template not found: $Source"
    return $false
}

Write-Host "Setting up environment files..." -ForegroundColor White
Write-Host ""

# Client env
Copy-IfMissing -Source $clientExample -Dest $clientEnv -Name "Frontend config" | Out-Null

# Extension env
Copy-IfMissing -Source $extExample -Dest $extEnv -Name "Extension config" | Out-Null

# Server env
if (Test-Path $serverEnv) {
    Write-Host "[SKIP] " -NoNewline -ForegroundColor Yellow
    Write-Host "Server config already exists: $serverEnv"
} else {
    Write-Host "[MANUAL] " -NoNewline -ForegroundColor Yellow
    Write-Host "Create $serverEnv manually with:"
    Write-Host "  PORT=5000" -ForegroundColor Gray
    Write-Host "  MONGO_URI=your-mongodb-connection-string" -ForegroundColor Gray
    Write-Host "  JWT_SECRET=your-secret-key" -ForegroundColor Gray
    Write-Host "  (see README.md for full configuration)" -ForegroundColor Gray
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Setup Complete!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Cyan
Write-Host "  1. Edit client\env.js with your API URL" -ForegroundColor White
Write-Host "  2. Edit extension\env.js with your API URL" -ForegroundColor White
Write-Host "  3. Create server\.env with database credentials" -ForegroundColor White
Write-Host "  4. Run 'cd server' and 'npm install' and 'npm run dev'" -ForegroundColor White
Write-Host ""
