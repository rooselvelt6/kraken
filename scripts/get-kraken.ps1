<#
.SYNOPSIS
    Universal Kraken binary installer for Windows
.DESCRIPTION
    Downloads the pre-compiled Kraken binary for Windows from GitHub Releases
    and installs it to your PATH.
.PARAMETER Version
    Version tag to install (default: latest)
.PARAMETER InstallDir
    Installation directory (default: $HOME\.local\bin or $env:USERPROFILE\bin)
.PARAMETER SkipVerify
    Skip checksum verification
.EXAMPLE
    iex ((New-Object System.Net.WebClient).DownloadString('https://git.io/get-kraken'))
.EXAMPLE
    .\get-kraken.ps1 -Version v0.2.0 -InstallDir C:\tools
#>

param(
    [string]$Version = "latest",
    [string]$InstallDir = "",
    [switch]$SkipVerify = $false
)

$ErrorActionPrevention = "Stop"

$Repo = "rooselvelt6/kraken"
$BinaryName = "kraken"

# ---------------------------------------------------------------------------
# Step 1: Detect architecture
# ---------------------------------------------------------------------------
Write-Host "`nDetecting platform" -ForegroundColor Cyan

$Arch = "x86_64"
switch ($env:PROCESSOR_ARCHITECTURE) {
    "AMD64"  { $Arch = "x86_64" }
    "ARM64"  { $Arch = "aarch64" }
    default  {
        Write-Error "Unsupported architecture: $env:PROCESSOR_ARCHITECTURE"
        exit 1
    }
}

$AssetName = "${BinaryName}-windows-${Arch}.exe"
Write-Host "  -> Detected: Windows $Arch" -ForegroundColor Gray
Write-Host "  -> Asset:    $AssetName" -ForegroundColor Gray

# ---------------------------------------------------------------------------
# Step 2: Resolve version
# ---------------------------------------------------------------------------
Write-Host "`nResolving version" -ForegroundColor Cyan

$ReleaseUrl = "https://api.github.com/repos/${Repo}/releases"
$DownloadBase = "https://github.com/${Repo}/releases/download"

if ($Version -eq "latest") {
    Write-Host "  -> Fetching latest release..." -ForegroundColor Gray
    try {
        $response = Invoke-RestMethod -Uri "${ReleaseUrl}/latest" -Method Get
        $Tag = $response.tag_name
    } catch {
        Write-Error "Failed to fetch latest release: $_"
        exit 1
    }
} else {
    $Tag = $Version
}

Write-Host "  ok Version: $Tag" -ForegroundColor Green

# ---------------------------------------------------------------------------
# Step 3: Determine install directory
# ---------------------------------------------------------------------------
Write-Host "`nSetting up installation path" -ForegroundColor Cyan

if (-not $InstallDir) {
    $LocalBin = Join-Path $HOME ".local" "bin"
    $UserBin = Join-Path $HOME "bin"

    if (Test-Path $LocalBin) {
        $InstallDir = $LocalBin
    } elseif (Test-Path $UserBin) {
        $InstallDir = $UserBin
    } else {
        $InstallDir = $LocalBin
    }
}

New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
$InstallPath = Join-Path $InstallDir "${BinaryName}.exe"
Write-Host "  -> Target: $InstallPath" -ForegroundColor Gray

# ---------------------------------------------------------------------------
# Step 4: Download binary
# ---------------------------------------------------------------------------
Write-Host "`nDownloading Kraken ${Tag}" -ForegroundColor Cyan

$BinaryUrl = "${DownloadBase}/${Tag}/${AssetName}"
$ChecksumsUrl = "${DownloadBase}/${Tag}/SHA256SUMS"
$TmpDir = Join-Path $env:TEMP "kraken-install"
$TmpBin = Join-Path $TmpDir $AssetName

New-Object -TypeName System.Net.WebClient

try {
    New-Item -ItemType Directory -Force -Path $TmpDir | Out-Null
    Write-Host "  -> Downloading: ${AssetName}" -ForegroundColor Gray
    Invoke-WebRequest -Uri $BinaryUrl -OutFile $TmpBin -UseBasicParsing -ErrorAction Stop
} catch {
    Write-Error "Download failed: $_"
    Write-Host "  -> URL: $BinaryUrl" -ForegroundColor Red
    exit 1
}

$FileSize = (Get-Item $TmpBin).Length
Write-Host "  ok Downloaded ($([math]::Round($FileSize / 1MB, 2)) MB)" -ForegroundColor Green

# ---------------------------------------------------------------------------
# Step 5: Verify checksum
# ---------------------------------------------------------------------------
if (-not $SkipVerify) {
    Write-Host "`nVerifying checksum" -ForegroundColor Cyan

    try {
        $TmpChecksums = Join-Path $TmpDir "SHA256SUMS"
        Invoke-WebRequest -Uri $ChecksumsUrl -OutFile $TmpChecksums -UseBasicParsing -ErrorAction Stop

        $ExpectedHash = Get-Content $TmpChecksums | Where-Object { $_ -match "  ${AssetName}$" } | ForEach-Object { $_ -split '\s+' | Select-Object -First 1 }

        if ($ExpectedHash) {
            $ComputedHash = (Get-FileHash -Path $TmpBin -Algorithm SHA256).Hash.ToLower()
            if ($ExpectedHash.ToLower() -eq $ComputedHash) {
                Write-Host "  ok Checksum matches: $ComputedHash" -ForegroundColor Green
            } else {
                Write-Error "Checksum mismatch!"
                Write-Host "  Expected: $ExpectedHash" -ForegroundColor Red
                Write-Host "  Computed: $ComputedHash" -ForegroundColor Red
                exit 1
            }
        } else {
            Write-Host "  warn No checksum found for $AssetName in SHA256SUMS" -ForegroundColor Yellow
        }
    } catch {
        Write-Host "  warn No SHA256SUMS file — skipping verification" -ForegroundColor Yellow
    }
}

# ---------------------------------------------------------------------------
# Step 6: Install binary
# ---------------------------------------------------------------------------
Write-Host "`nInstalling" -ForegroundColor Cyan

try {
    Copy-Item -Path $TmpBin -Destination $InstallPath -Force -ErrorAction Stop
    Write-Host "  ok Installed to $InstallPath" -ForegroundColor Green
} catch {
    Write-Error "Failed to install: $_"
    Write-Host "  Try running PowerShell as Administrator" -ForegroundColor Yellow
    exit 1
}

# ---------------------------------------------------------------------------
# Step 7: Add to PATH if not present
# ---------------------------------------------------------------------------
$currentPath = [Environment]::GetEnvironmentVariable("PATH", [EnvironmentVariableTarget]::User)
if ($currentPath -notlike "*$InstallDir*") {
    Write-Host "`nAdding to PATH" -ForegroundColor Cyan
    try {
        $newPath = "$InstallDir;$currentPath"
        [Environment]::SetEnvironmentVariable("PATH", $newPath, [EnvironmentVariableTarget]::User)
        $env:PATH = $newPath
        Write-Host "  ok Added $InstallDir to PATH" -ForegroundColor Green
    } catch {
        Write-Host "  warn Could not update PATH — add manually: $InstallDir" -ForegroundColor Yellow
    }
}

# ---------------------------------------------------------------------------
# Step 8: Verify installation
# ---------------------------------------------------------------------------
Write-Host "`nVerifying installation" -ForegroundColor Cyan

try {
    $versionOut = & $InstallPath --version 2>&1
    Write-Host "  ok kraken --version: $versionOut" -ForegroundColor Green
} catch {
    Write-Host "  warn Binary installed but verification failed" -ForegroundColor Yellow
}

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------
Write-Host "`nKraken is ready!" -ForegroundColor Cyan

Write-Host @"

  Binary: $InstallPath

  Try it out:
    kraken
    kraken --help
    kraken vulnscan --dir .

  Set your API key:
    set ANTHROPIC_API_KEY=sk-ant-...
    # or use Ollama (free, local):
    kraken --provider ollama
"@

Remove-Item -Recurse -Force $TmpDir -ErrorAction SilentlyContinue
