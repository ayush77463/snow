# sync_web_ui.ps1 — Hot-swap sync script for local SNOW Web Dashboard development
# Copies allowlisted static UI assets to ~/.snow/web_override/ without rebuilding Windows installer.

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Split-Path -Parent $ScriptDir
$SourceStaticDir = Join-Path $RepoRoot "src\snow\web\static"
$TargetOverrideDir = Join-Path $HOME ".snow\web_override"

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " SNOW Web UI Hot-Swap Synchronization" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "Source: $SourceStaticDir"
Write-Host "Target: $TargetOverrideDir"

if (-not (Test-Path $SourceStaticDir)) {
    Write-Error "Source static directory not found: $SourceStaticDir"
    exit 1
}

# 1. Validate required source assets exist
$RequiredFiles = @("index.html", "app.js", "app.css", "tokens.css", "theme-init.js")
foreach ($req in $RequiredFiles) {
    $reqPath = Join-Path $SourceStaticDir $req
    if (-not (Test-Path $reqPath)) {
        Write-Error "Missing mandatory UI asset: $reqPath"
        exit 1
    }
}

# 2. Prepare override directory
if (-not (Test-Path $TargetOverrideDir)) {
    New-Item -ItemType Directory -Path $TargetOverrideDir -Force | Out-Null
}

# 3. Copy allowlisted assets only
$AllowedExtensions = @(".html", ".css", ".js", ".svg", ".png", ".jpg", ".jpeg", ".ico", ".woff", ".woff2")
$FilesCopied = 0

Get-ChildItem -Path $SourceStaticDir -File | ForEach-Object {
    $ext = $_.Extension.ToLower()
    if ($AllowedExtensions -contains $ext) {
        $destPath = Join-Path $TargetOverrideDir $_.Name
        Copy-Item -Path $_.FullName -Destination $destPath -Force
        $FilesCopied++
        Write-Host "  -> Synced: $($_.Name)" -ForegroundColor Green
    } else {
        Write-Host "  -- Skipped disallowed file: $($_.Name)" -ForegroundColor Yellow
    }
}

# 4. Final verification of override directory
foreach ($req in $RequiredFiles) {
    $reqDest = Join-Path $TargetOverrideDir $req
    if (-not (Test-Path $reqDest)) {
        Write-Error "Verification failed: $req missing in override directory."
        exit 1
    }
}

Write-Host "`nSuccessfully synchronized $FilesCopied UI asset(s) to ~/.snow/web_override/" -ForegroundColor Green
Write-Host "The SNOW Web Dashboard will automatically serve these files with priority." -ForegroundColor Cyan
Write-Host "To revert to bundled assets, click 'Reset to Bundled UI' in Dashboard Settings." -ForegroundColor Gray
