# Fillr Extension Builder v2.0
# Creates fillr-extension-v2.0.0-beta.zip for distribution

Write-Host ""
Write-Host "[*] Building Fillr Extension Package..." -ForegroundColor Cyan

# Navigate to extension directory
$extensionPath = Join-Path $PSScriptRoot "extension"
$outputZip = Join-Path $PSScriptRoot "fillr-extension-v2.0.0-beta.zip"

# Remove old ZIP if exists
if (Test-Path $outputZip) {
    Remove-Item $outputZip -Force
    Write-Host "[~] Removed old package" -ForegroundColor Yellow
}

# Get all extension files
$filesToPackage = @(
    "manifest.json",
    "background.js",
    "content.js",
    "matcher.js",
    "popup.html",
    "popup.js",
    "styles.css",
    "env.js",
    "icons"
)

# Verify all required files exist
$missingFiles = @()
foreach ($file in $filesToPackage) {
    $fullPath = Join-Path $extensionPath $file
    if (-not (Test-Path $fullPath)) {
        $missingFiles += $file
    }
}

if ($missingFiles.Count -gt 0) {
    Write-Host "[X] Missing required files:" -ForegroundColor Red
    $missingFiles | ForEach-Object { Write-Host "   - $_" -ForegroundColor Red }
    exit 1
}

# Create temp directory for packaging
$tempDir = Join-Path $env:TEMP "fillr-extension-temp"
if (Test-Path $tempDir) {
    Remove-Item $tempDir -Recurse -Force
}
New-Item -ItemType Directory -Path $tempDir -Force | Out-Null

# Copy files to temp directory
Write-Host "[+] Copying extension files..." -ForegroundColor Green
foreach ($file in $filesToPackage) {
    $source = Join-Path $extensionPath $file
    $dest = Join-Path $tempDir $file
    
    if (Test-Path $source -PathType Container) {
        Copy-Item -Path $source -Destination $dest -Recurse -Force
    } else {
        Copy-Item -Path $source -Destination $dest -Force
    }
}

# Create ZIP archive
Write-Host "[+] Creating ZIP archive..." -ForegroundColor Green
Compress-Archive -Path "$tempDir\*" -DestinationPath $outputZip -CompressionLevel Optimal -Force

# Clean up temp directory
Remove-Item $tempDir -Recurse -Force

# Get package info
$zipSize = [math]::Round((Get-Item $outputZip).Length / 1KB, 2)

# Success message
Write-Host ""
Write-Host "[OK] Extension package created successfully!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Location: " -NoNewline -ForegroundColor White
Write-Host "$outputZip" -ForegroundColor Yellow
Write-Host "Size: " -NoNewline -ForegroundColor White
Write-Host "$zipSize KB" -ForegroundColor Yellow
Write-Host "========================================" -ForegroundColor Cyan

Write-Host ""
Write-Host "Next Steps:" -ForegroundColor Cyan
Write-Host "  1. Test: Load unpacked in chrome://extensions/" -ForegroundColor White
Write-Host "  2. Upload to GitHub Releases (tag: v2.0.0-beta)" -ForegroundColor White
Write-Host "  3. Or submit to Chrome Web Store" -ForegroundColor White
Write-Host ""
