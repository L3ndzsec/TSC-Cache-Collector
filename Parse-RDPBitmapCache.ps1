#Requires -Version 5.1
<#
.SYNOPSIS
    RDP Bitmap Cache Parser — offline analysis of collected RDP cache files.

.DESCRIPTION
    Takes the ZIP produced by Collect-RDPBitmapCache.ps1 (or a raw directory of
    cache files) and performs:

      1. SHA-256 integrity verification against the collection manifest
      2. Bitmap extraction via bmc-tools (Python) if available
      3. Tile catalogue and per-user analysis report (JSON + text)

    The extracted tiles and analysis report are written to -OutputPath, which
    can then be loaded directly into IRFlow Timeline via
    Tools > RDP Bitmap Cache > Browse folder.

.PARAMETER InputPath
    Path to the ZIP archive from Collect-RDPBitmapCache.ps1, or a directory
    containing .bmc / cache####.bin files directly.

.PARAMETER OutputPath
    Directory for extracted tiles and analysis report.
    Default: same location as InputPath, with suffix -Analysis.

.PARAMETER BmcToolsPath
    Full path to bmc-tools.py (or compiled bmc-tools executable).
    If omitted the script searches common locations and PATH.

.PARAMETER PythonPath
    Path to the Python 3 interpreter.  Default: auto-detect (python3, python).

.PARAMETER SkipExtraction
    Verify hashes and produce the metadata report without running bmc-tools.
    Useful when bmc-tools is not available or you only need integrity checking.

.PARAMETER SkipVerify
    Skip SHA-256 hash verification (faster; use when no manifest is present).

.PARAMETER BmcWidth
    Tile width hint passed to bmc-tools (-w).  Default: 64.

.PARAMETER KeepTemp
    Keep the temporary extraction directory when input is a ZIP.

.EXAMPLE
    .\Parse-RDPBitmapCache.ps1 -InputPath C:\IRCase\RDPCache-PC01-20240115.zip

.EXAMPLE
    .\Parse-RDPBitmapCache.ps1 -InputPath C:\IRCase\RDPCache-PC01-20240115.zip `
        -BmcToolsPath C:\Tools\bmc-tools\bmc-tools.py -OutputPath C:\IRCase\Analysis

.EXAMPLE
    .\Parse-RDPBitmapCache.ps1 -InputPath C:\RawCache -SkipVerify
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string] $InputPath,

    [string] $OutputPath    = '',
    [string] $BmcToolsPath  = '',
    [string] $PythonPath    = '',
    [switch] $SkipExtraction,
    [switch] $SkipVerify,
    [int]    $BmcWidth      = 64,
    [switch] $KeepTemp
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

$script:StartTime = Get-Date
$script:Warnings  = [System.Collections.Generic.List[string]]::new()

# -- Console helpers -----------------------------------------------------------
function Write-Banner {
    Write-Host ""
    Write-Host "  +------------------------------------------------------+" -ForegroundColor Cyan
    Write-Host "  |   RDP Bitmap Cache Parser                            |" -ForegroundColor Cyan
    Write-Host "  |   IRFlow Timeline — github.com/L3ndzsec              |" -ForegroundColor DarkGray
    Write-Host "  +------------------------------------------------------+" -ForegroundColor Cyan
    Write-Host ""
}
function Write-Section([string]$msg) {
    $pad = '-' * [Math]::Max(1, 54 - $msg.Length)
    Write-Host ("`n  -- $msg $pad") -ForegroundColor Cyan
}
function Write-Found([string]$msg)  { Write-Host "  [+] $msg" -ForegroundColor Green }
function Write-Info([string]$msg)   { Write-Host "  [.] $msg" -ForegroundColor DarkGray }
function Write-Warn([string]$msg)   { Write-Host "  [!] $msg" -ForegroundColor Yellow; $script:Warnings.Add($msg) }
function Write-Miss([string]$msg)   { Write-Host "  [-] $msg" -ForegroundColor DarkGray }
function Write-Ok([string]$msg)     { Write-Host "  [✓] $msg" -ForegroundColor Green }
function Write-Fail([string]$msg)   { Write-Host "  [✗] $msg" -ForegroundColor Red }

# -- File helpers --------------------------------------------------------------
function Get-Sha256([string]$FilePath) {
    try {
        $sha    = [System.Security.Cryptography.SHA256]::Create()
        $stream = [System.IO.File]::OpenRead($FilePath)
        $bytes  = $sha.ComputeHash($stream)
        $stream.Close(); $sha.Dispose()
        return ([BitConverter]::ToString($bytes) -replace '-', '').ToLower()
    } catch {
        return $null
    }
}

function Get-UtcIso([System.DateTime]$dt) {
    return $dt.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
}

# -- Input resolution ----------------------------------------------------------
function Expand-InputZip([string]$ZipPath) {
    $ts      = Get-Date -Format 'yyyyMMdd-HHmmss'
    $tempDir = Join-Path $env:TEMP "rdpbc-parse-$ts"
    try {
        try { Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction Stop } catch {}
        [System.IO.Compression.ZipFile]::ExtractToDirectory($ZipPath, $tempDir)
        Write-Info "Extracted ZIP to: $tempDir"
        return $tempDir
    } catch {
        throw "Failed to extract ZIP '$ZipPath': $($_.Exception.Message)"
    }
}

function Read-CollectionManifest([string]$Dir) {
    $manifestPath = Join-Path $Dir 'manifest.json'
    if (-not (Test-Path $manifestPath)) { return $null }
    try {
        $json = Get-Content $manifestPath -Raw -Encoding UTF8
        return $json | ConvertFrom-Json
    } catch {
        Write-Warn "Could not read manifest.json: $($_.Exception.Message)"
        return $null
    }
}

# -- Hash verification ---------------------------------------------------------
function Invoke-IntegrityCheck {
    param(
        [object]   $Manifest,
        [string]   $BaseDir
    )

    $results = [System.Collections.Generic.List[hashtable]]::new()
    $passed  = 0
    $failed  = 0
    $skipped = 0

    if (-not $Manifest -or -not $Manifest.cacheFiles) {
        Write-Warn "No manifest or cacheFiles — skipping integrity check"
        return @{ passed = 0; failed = 0; skipped = 0; results = @() }
    }

    foreach ($cf in $Manifest.cacheFiles) {
        if (-not $cf.collectedPath) { $skipped++; continue }
        $filePath = Join-Path $BaseDir $cf.collectedPath
        if (-not (Test-Path $filePath)) {
            Write-Warn "File missing from archive: $($cf.collectedPath)"
            $results.Add(@{ file = $cf.collectedPath; status = 'missing' })
            $failed++; continue
        }

        if (-not $cf.sha256 -or $Manifest.hashingPerformed -eq $false) {
            $results.Add(@{ file = $cf.collectedPath; status = 'no-hash' })
            $skipped++; continue
        }

        $actual = Get-Sha256 $filePath
        if ($actual -eq $cf.sha256) {
            $results.Add(@{ file = $cf.collectedPath; status = 'ok'; sha256 = $actual })
            $passed++
        } else {
            Write-Fail "Hash MISMATCH: $($cf.collectedPath)"
            Write-Info "  Expected : $($cf.sha256)"
            Write-Info "  Actual   : $actual"
            $results.Add(@{
                file     = $cf.collectedPath; status = 'mismatch'
                expected = $cf.sha256; actual = $actual
            })
            $failed++
        }
    }

    return @{
        passed  = $passed
        failed  = $failed
        skipped = $skipped
        results = @($results)
    }
}

# -- bmc-tools discovery -------------------------------------------------------
function Find-BmcTools {
    $candidates = @(
        $BmcToolsPath,
        (Join-Path $PSScriptRoot 'bmc-tools.py'),
        (Join-Path $PSScriptRoot 'bmc-tools\bmc-tools.py'),
        (Join-Path $env:USERPROFILE 'bmc-tools\bmc-tools.py'),
        (Join-Path $env:USERPROFILE 'Tools\bmc-tools\bmc-tools.py'),
        'C:\Tools\bmc-tools\bmc-tools.py',
        'C:\Tools\bmc-tools.py'
    )
    foreach ($c in $candidates) {
        if ($c -and (Test-Path $c -PathType Leaf)) { return $c }
    }
    # Also check PATH for a compiled bmc-tools executable
    $found = Get-Command 'bmc-tools' -ErrorAction SilentlyContinue
    if ($found) { return $found.Source }
    return $null
}

function Find-Python {
    if ($PythonPath -and (Test-Path $PythonPath -PathType Leaf)) { return $PythonPath }
    foreach ($cmd in @('python3', 'python')) {
        $found = Get-Command $cmd -ErrorAction SilentlyContinue
        if ($found) {
            # Confirm it's Python 3
            $ver = & $found.Source --version 2>&1
            if ($ver -match 'Python 3') { return $found.Source }
        }
    }
    return $null
}

# -- bmc-tools extraction ------------------------------------------------------
function Invoke-BmcExtraction {
    param(
        [string]   $BmcTool,
        [string]   $Python,
        [string[]] $CacheFilePaths,
        [string]   $OutDir
    )

    $results = [System.Collections.Generic.List[hashtable]]::new()
    $isPy    = $BmcTool -imatch '\.py$'

    foreach ($cacheFile in $CacheFilePaths) {
        $leafName = [System.IO.Path]::GetFileNameWithoutExtension($cacheFile)
        $destDir  = Join-Path $OutDir "tiles_$leafName"
        New-Item $destDir -ItemType Directory -Force | Out-Null

        $args = if ($isPy) {
            @($BmcTool, '-s', $cacheFile, '-d', $destDir, '-b', '-w', [string]$BmcWidth)
        } else {
            @('-s', $cacheFile, '-d', $destDir, '-b', '-w', [string]$BmcWidth)
        }
        $exe = if ($isPy) { $Python } else { $BmcTool }

        Write-Info "  Extracting: $(Split-Path $cacheFile -Leaf) → $(Split-Path $destDir -Leaf)"
        try {
            $proc = Start-Process -FilePath $exe -ArgumentList $args `
                -NoNewWindow -Wait -PassThru `
                -RedirectStandardOutput "$destDir\_stdout.txt" `
                -RedirectStandardError  "$destDir\_stderr.txt" `
                -ErrorAction Stop

            $tiles = Get-ChildItem $destDir -File -Recurse -ErrorAction SilentlyContinue |
                     Where-Object { $_.Name -imatch '\.(bmp|png|jpg)$' -and $_.Name -notmatch '^_' }

            if ($proc.ExitCode -eq 0) {
                Write-Found "    $($tiles.Count) image(s) extracted"
                $results.Add(@{
                    sourceFile = $cacheFile
                    outputDir  = $destDir
                    exitCode   = $proc.ExitCode
                    tileCount  = $tiles.Count
                    status     = 'ok'
                })
            } else {
                $errText = Get-Content "$destDir\_stderr.txt" -Raw -ErrorAction SilentlyContinue
                Write-Warn "    bmc-tools exited $($proc.ExitCode): $errText"
                $results.Add(@{
                    sourceFile = $cacheFile; outputDir = $destDir
                    exitCode   = $proc.ExitCode; status = 'error'; error = $errText
                })
            }
        } catch {
            Write-Warn "  Failed to run bmc-tools on $($cacheFile): $($_.Exception.Message)"
            $results.Add(@{ sourceFile = $cacheFile; status = 'spawn-error'; error = $_.Exception.Message })
        }
    }
    return @($results)
}

# -- Collect cache file paths from a directory ---------------------------------
function Get-CacheFilesFromDir([string]$Dir) {
    return @(Get-ChildItem $Dir -File -Recurse -ErrorAction SilentlyContinue |
             Where-Object { $_.Name -imatch '^bcache.*\.bmc$' -or $_.Name -imatch '^cache\d{4}\.bin$' } |
             Select-Object -ExpandProperty FullName)
}

# -- Analysis report -----------------------------------------------------------
function Write-AnalysisReport {
    param(
        [string] $OutDir,
        [object] $Manifest,
        [hashtable] $Integrity,
        [array]  $ExtractionResults,
        [bool]   $ExtractionRan
    )

    $elapsed = (Get-Date) - $script:StartTime

    $perUser = @{}
    if ($Manifest -and $Manifest.cacheFiles) {
        foreach ($cf in $Manifest.cacheFiles) {
            $u = if ($cf.userName) { $cf.userName } else { '_unknown' }
            if (-not $perUser.ContainsKey($u)) {
                $perUser[$u] = @{ files = @(); totalBytes = 0; kinds = @{} }
            }
            $perUser[$u]['files'] += $cf
            $perUser[$u]['totalBytes'] += [long]($cf.size)
            $k = $cf.kind; if (-not $perUser[$u]['kinds'][$k]) { $perUser[$u]['kinds'][$k] = 0 }
            $perUser[$u]['kinds'][$k]++
        }
    }

    $totalTiles = 0
    foreach ($r in $ExtractionResults) {
        if ($r['status'] -eq 'ok') { $totalTiles += [int]($r['tileCount']) }
    }

    $report = @{
        schemaVersion      = 1
        artifactType       = 'rdp-bitmap-cache-analysis'
        analyzedAt         = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        analysisHost       = $env:COMPUTERNAME
        elapsedSeconds     = [Math]::Round($elapsed.TotalSeconds, 1)
        sourceManifest     = $Manifest
        integrityCheck     = $Integrity
        extractionPerformed = $ExtractionRan
        extractionResults  = @($ExtractionResults)
        summary = @{
            cacheFilesAnalyzed = if ($Manifest) { $Manifest.filesCollected } else { 0 }
            integrityPassed    = $Integrity['passed']
            integrityFailed    = $Integrity['failed']
            totalTilesExtracted = $totalTiles
            users              = @($perUser.Keys | Sort-Object)
        }
        perUser    = $perUser
        warnings   = @($script:Warnings)
    }

    $jsonPath = Join-Path $OutDir 'analysis-report.json'
    [System.IO.File]::WriteAllText($jsonPath,
        ($report | ConvertTo-Json -Depth 10),
        [System.Text.Encoding]::UTF8)

    # Human-readable text report
    $txtPath = Join-Path $OutDir 'analysis-report.txt'
    $lines   = @(
        "IRFlow Timeline - RDP Bitmap Cache Analysis Report",
        "===================================================",
        "Analyzed  : $($report.analyzedAt)",
        "Host      : $($report.analysisHost)",
        "Elapsed   : $($report.elapsedSeconds)s",
        ""
    )

    if ($Manifest) {
        $lines += "Collection info:"
        $lines += "  Collected on  : $($Manifest.collectedAt)"
        $lines += "  Source host   : $($Manifest.collectionHost)"
        $lines += "  Cache files   : $($Manifest.filesCollected)"
        $lines += "  bcache (.bmc) : $($Manifest.summary.bcacheCount)"
        $lines += "  cache-bin     : $($Manifest.summary.cacheBinCount)"
        $lines += ""
    }

    $lines += "Integrity verification:"
    if ($SkipVerify) {
        $lines += "  Skipped (--SkipVerify)"
    } else {
        $lines += "  Passed  : $($Integrity['passed'])"
        $lines += "  Failed  : $($Integrity['failed'])"
        $lines += "  Skipped : $($Integrity['skipped'])"
        foreach ($r in $Integrity['results']) {
            if ($r['status'] -eq 'mismatch') {
                $lines += "  [MISMATCH] $($r['file'])"
            }
        }
    }
    $lines += ""

    if ($ExtractionRan) {
        $lines += "Bitmap extraction:"
        $lines += "  Total tiles extracted : $totalTiles"
        foreach ($r in $ExtractionResults) {
            $status = if ($r['status'] -eq 'ok') { "[OK]  " } else { "[ERR] " }
            $lines += "  $status $(Split-Path $r['sourceFile'] -Leaf)  →  $($r['tileCount']) tile(s)"
        }
    } else {
        $lines += "Bitmap extraction: skipped (--SkipExtraction or bmc-tools not found)"
    }
    $lines += ""

    if ($perUser.Count -gt 0) {
        $lines += "Per-user breakdown:"
        foreach ($u in ($perUser.Keys | Sort-Object)) {
            $ud = $perUser[$u]
            $lines += "  User: $u"
            $lines += "    Files      : $($ud['files'].Count)"
            $lines += "    Total size : $([Math]::Round($ud['totalBytes']/1KB, 1)) KB"
            foreach ($k in $ud['kinds'].Keys) {
                $lines += "    $k : $($ud['kinds'][$k])"
            }
        }
        $lines += ""
    }

    $lines += "Load into IRFlow Timeline:"
    $lines += "  Tools > RDP Bitmap Cache > Browse folder > select: $OutDir"
    $lines | Set-Content $txtPath -Encoding UTF8

    return @{ jsonPath = $jsonPath; txtPath = $txtPath }
}

# -- Main ----------------------------------------------------------------------
Write-Banner

$InputPath = [System.IO.Path]::GetFullPath($InputPath)
if (-not (Test-Path $InputPath)) {
    Write-Error "Input path not found: $InputPath"; exit 1
}

# -- Step 1: Resolve working directory (extract ZIP if needed) ----------------
Write-Section 'Input'
$tempDirToClean = $null
$workDir        = $null

if ($InputPath -imatch '\.zip$') {
    Write-Info "Input is a ZIP archive: $(Split-Path $InputPath -Leaf)"
    $workDir = Expand-InputZip $InputPath
    if (-not $KeepTemp) { $tempDirToClean = $workDir }
} elseif (Test-Path $InputPath -PathType Container) {
    Write-Info "Input is a directory: $InputPath"
    $workDir = $InputPath
} else {
    Write-Error "InputPath must be a .zip file or directory."; exit 1
}

# -- Step 2: Read manifest ----------------------------------------------------
Write-Section 'Manifest'
$manifest = Read-CollectionManifest $workDir
if ($manifest) {
    Write-Found "manifest.json found"
    Write-Info "  Source host    : $($manifest.collectionHost)"
    Write-Info "  Collected at   : $($manifest.collectedAt)"
    Write-Info "  Cache files    : $($manifest.filesCollected)"
    Write-Info "  bcache count   : $($manifest.summary.bcacheCount)"
    Write-Info "  cache-bin count: $($manifest.summary.cacheBinCount)"
    Write-Info "  Users          : $($manifest.summary.users -join ', ')"
} else {
    Write-Miss "No manifest.json found — proceeding without it"
}

# -- Step 3: Integrity check --------------------------------------------------
Write-Section 'Integrity Check'
$integrityResult = @{ passed = 0; failed = 0; skipped = 0; results = @() }

if ($SkipVerify) {
    Write-Miss "Skipped (--SkipVerify)"
} elseif (-not $manifest) {
    Write-Miss "No manifest — cannot verify hashes"
} else {
    $integrityResult = Invoke-IntegrityCheck -Manifest $manifest -BaseDir $workDir
    if ($integrityResult['failed'] -eq 0) {
        Write-Ok "$($integrityResult['passed']) file(s) verified OK"
    } else {
        Write-Fail "$($integrityResult['failed']) hash mismatch(es) detected"
    }
    if ($integrityResult['skipped'] -gt 0) {
        Write-Info "$($integrityResult['skipped']) file(s) skipped (no stored hash)"
    }
}

# -- Step 4: Bitmap extraction ------------------------------------------------
Write-Section 'Bitmap Extraction'
$extractionRan     = $false
$extractionResults = @()

if ($SkipExtraction) {
    Write-Miss "Skipped (--SkipExtraction)"
} else {
    $bmcTool = Find-BmcTools
    $python  = if ($bmcTool -imatch '\.py$') { Find-Python } else { $null }

    if (-not $bmcTool) {
        Write-Miss "bmc-tools not found — skipping extraction"
        Write-Info "  To enable: install bmc-tools and pass -BmcToolsPath"
        Write-Info "  https://github.com/ANSSI-FR/bmc-tools"
    } elseif ($bmcTool -imatch '\.py$' -and -not $python) {
        Write-Miss "bmc-tools.py found but Python 3 not detected — skipping extraction"
        Write-Info "  Pass -PythonPath to specify the Python 3 interpreter"
    } else {
        $label = if ($bmcTool -imatch '\.py$') { "python3 bmc-tools.py" } else { "bmc-tools" }
        Write-Found "bmc-tools: $bmcTool  ($label)"

        $cacheFilePaths = Get-CacheFilesFromDir $workDir
        if ($cacheFilePaths.Count -eq 0) {
            Write-Miss "No cache files found in working directory"
        } else {
            Write-Info "$($cacheFilePaths.Count) cache file(s) to extract"

            # Resolve output path
            if (-not $OutputPath) {
                $base       = if ($InputPath -imatch '\.zip$') { [System.IO.Path]::GetDirectoryName($InputPath) } else { [System.IO.Path]::GetDirectoryName($InputPath) }
                $stem       = [System.IO.Path]::GetFileNameWithoutExtension($InputPath)
                $OutputPath = Join-Path $base "$stem-Analysis"
            }
            $tilesDir = Join-Path $OutputPath 'extracted-tiles'
            New-Item $tilesDir -ItemType Directory -Force | Out-Null

            $extractionResults = Invoke-BmcExtraction `
                -BmcTool $bmcTool -Python $python `
                -CacheFilePaths $cacheFilePaths `
                -OutDir $tilesDir

            $extractionRan = $true
        }
    }
}

# -- Step 5: Analysis report --------------------------------------------------
Write-Section 'Analysis Report'

if (-not $OutputPath) {
    $base       = if ($InputPath -imatch '\.zip$') { [System.IO.Path]::GetDirectoryName($InputPath) } else { $InputPath }
    $stem       = [System.IO.Path]::GetFileNameWithoutExtension($InputPath)
    $OutputPath = Join-Path $base "$stem-Analysis"
}
New-Item $OutputPath -ItemType Directory -Force | Out-Null

$reportPaths = Write-AnalysisReport `
    -OutDir            $OutputPath `
    -Manifest          $manifest `
    -Integrity         $integrityResult `
    -ExtractionResults $extractionResults `
    -ExtractionRan     $extractionRan

Write-Found "JSON report : $($reportPaths['jsonPath'])"
Write-Found "Text report : $($reportPaths['txtPath'])"

# -- Cleanup temp dir ---------------------------------------------------------
if ($tempDirToClean -and (Test-Path $tempDirToClean)) {
    Remove-Item $tempDirToClean -Recurse -Force -ErrorAction SilentlyContinue
    Write-Info "Temp directory cleaned up"
}

# -- Final summary ------------------------------------------------------------
Write-Section 'Complete'
$elapsed = (Get-Date) - $script:StartTime

Write-Info "Elapsed : $([Math]::Round($elapsed.TotalSeconds,1))s"
Write-Host ""
Write-Host "  Output folder: $OutputPath" -ForegroundColor Cyan
Write-Host "  Load into IRFlow Timeline: Tools > RDP Bitmap Cache > Browse folder" -ForegroundColor Green
Write-Host ""
