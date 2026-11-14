#Requires -Version 5.1
<#
.SYNOPSIS
    RDP Bitmap Cache Collector — standalone triage script for IR / Defender Live Response.

.DESCRIPTION
    Discovers and collects RDP bitmap cache files (bcache*.bmc, cache####.bin) from
    all Windows user profiles on the target host.  Produces a ZIP archive containing
    the raw cache files plus a SHA-256 chain-of-custody manifest.json, ready for
    offline analysis with Parse-RDPBitmapCache.ps1 or IRFlow Timeline.

    Designed for use in Microsoft Defender Live Response:
        run Collect-RDPBitmapCache.ps1
        getfile C:\Windows\Temp\RDPCache-<hostname>-<ts>.zip

    Also works as a standalone script on any Windows host.

.PARAMETER OutputPath
    Directory to write the final ZIP archive.
    Default: C:\Windows\Temp

.PARAMETER ProfilePath
    Collect from a single user profile path instead of all profiles.
    Useful for mounted images: -ProfilePath D:\Image\Users\victim

.PARAMETER AllUsers
    Force scanning all profiles under C:\Users (or Documents and Settings).
    Default when running as admin or SYSTEM; otherwise current user only.

.PARAMETER InventoryOnly
    Discover and report cache files without copying any data.

.PARAMETER SkipHash
    Skip SHA-256 hashing (faster collection; no integrity verification).

.PARAMETER MaxFileSizeMB
    Skip individual cache files larger than this size in MB.  Default: 500.

.EXAMPLE
    # Defender Live Response — no arguments needed:
    run Collect-RDPBitmapCache.ps1

.EXAMPLE
    .\Collect-RDPBitmapCache.ps1 -OutputPath C:\IRCase -InventoryOnly

.EXAMPLE
    .\Collect-RDPBitmapCache.ps1 -ProfilePath D:\Image\Users\victim -OutputPath C:\IRCase
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string] $OutputPath    = 'C:\Windows\Temp',
    [string] $ProfilePath   = '',
    [switch] $AllUsers,
    [switch] $InventoryOnly,
    [switch] $SkipHash,
    [int]    $MaxFileSizeMB = 500
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

$script:ScriptVersion  = '1.0'
$script:StartTime      = Get-Date
$script:MaxBytes       = [long]$MaxFileSizeMB * 1MB
$script:Collected      = 0
$script:SkippedSize    = 0
$script:Errors         = 0
$script:Warnings       = [System.Collections.Generic.List[string]]::new()
$script:CacheFileRows  = [System.Collections.Generic.List[hashtable]]::new()

# File patterns that identify RDP bitmap cache files
$BCACHE_RE    = [regex]'^bcache.*\.bmc$'
$CACHE_BIN_RE = [regex]'^cache\d{4}\.bin$'

# Standard cache path fragment (Vista+)
$CACHE_REL_PATH = 'AppData\Local\Microsoft\Terminal Server Client\Cache'
# Legacy cache path fragment (XP / 2003)
$CACHE_REL_PATH_XP = 'Local Settings\Application Data\Microsoft\Terminal Server Client\Cache'

# -- Console helpers -----------------------------------------------------------
function Write-Banner {
    Write-Host ""
    Write-Host "  +------------------------------------------------------+" -ForegroundColor Cyan
    Write-Host "  |   RDP Bitmap Cache Collector                         |" -ForegroundColor Cyan
    Write-Host "  |   IRFlow Timeline — github.com/L3ndzsec              |" -ForegroundColor DarkGray
    Write-Host "  +------------------------------------------------------+" -ForegroundColor Cyan
    Write-Host ""
}
function Write-Section([string]$msg) {
    $pad = '-' * [Math]::Max(1, 54 - $msg.Length)
    Write-Host ("`n  -- $msg $pad") -ForegroundColor Cyan
}
function Write-Found([string]$msg) { Write-Host "  [+] $msg" -ForegroundColor Green }
function Write-Info([string]$msg)  { Write-Host "  [.] $msg" -ForegroundColor DarkGray }
function Write-Warn([string]$msg)  { Write-Host "  [!] $msg" -ForegroundColor Yellow; $script:Warnings.Add($msg) }
function Write-Miss([string]$msg)  { Write-Host "  [-] $msg" -ForegroundColor DarkGray }

# -- File helpers --------------------------------------------------------------
function Get-Sha256([string]$FilePath) {
    if ($SkipHash) { return $null }
    try {
        $sha = [System.Security.Cryptography.SHA256]::Create()
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

function Test-IsRdpCacheFile([string]$Name) {
    return ($BCACHE_RE.IsMatch($Name) -or $CACHE_BIN_RE.IsMatch($Name))
}

function Get-CacheFileKind([string]$Name) {
    if ($BCACHE_RE.IsMatch($Name))    { return 'bcache' }
    if ($CACHE_BIN_RE.IsMatch($Name)) { return 'cache-bin' }
    return 'unknown'
}

function Get-UserNameFromPath([string]$FilePath) {
    $parts = $FilePath -split '[\\/]+'
    for ($i = 0; $i -lt $parts.Count - 1; $i++) {
        if ($parts[$i] -imatch '^(Users|Documents and Settings)$') {
            $candidate = $parts[$i + 1]
            if ($candidate -and $candidate -notmatch '^(All Users|Default|Default User|Public)$') {
                return $candidate
            }
        }
    }
    return $null
}

function Test-IsExpectedCachePath([string]$FilePath) {
    return ($FilePath -imatch [regex]::Escape('Terminal Server Client') + '.*' + [regex]::Escape('Cache'))
}

# -- Profile resolution --------------------------------------------------------
function Resolve-Profiles {
    $list = [System.Collections.Generic.List[string]]::new()

    if ($ProfilePath) {
        $list.Add([System.IO.Path]::GetFullPath($ProfilePath))
        return $list
    }

    # Determine users base dirs to scan
    $isElevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)

    $scanAll = $AllUsers -or $isElevated

    if ($scanAll) {
        foreach ($base in @('C:\Users', 'C:\Documents and Settings')) {
            if (-not (Test-Path $base -PathType Container)) { continue }
            Get-ChildItem $base -Directory -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -notmatch '^(Public|Default|Default User|All Users)$' } |
                ForEach-Object { $list.Add($_.FullName) }
        }
    }

    # Always fall back to current user if nothing resolved
    if ($list.Count -eq 0) {
        $list.Add($env:USERPROFILE)
    }

    return $list
}

# -- Cache discovery -----------------------------------------------------------
function Find-CacheFilesInProfile([string]$ProfileRoot) {
    $found = [System.Collections.Generic.List[hashtable]]::new()

    $searchRoots = @(
        (Join-Path $ProfileRoot $CACHE_REL_PATH),
        (Join-Path $ProfileRoot $CACHE_REL_PATH_XP)
    )

    foreach ($cacheDir in $searchRoots) {
        if (-not (Test-Path $cacheDir -PathType Container)) { continue }

        $items = Get-ChildItem $cacheDir -File -Recurse -ErrorAction SilentlyContinue |
                 Where-Object { Test-IsRdpCacheFile $_.Name }

        foreach ($f in $items) {
            $found.Add(@{
                file      = $f
                cacheDir  = $cacheDir
            })
        }
    }

    # Also do a broader search under the profile in case the cache was moved/copied
    if ($found.Count -eq 0) {
        Get-ChildItem $ProfileRoot -File -Recurse -Depth 8 -ErrorAction SilentlyContinue |
            Where-Object { Test-IsRdpCacheFile $_.Name } |
            ForEach-Object {
                $found.Add(@{ file = $_; cacheDir = $null })
            }
    }

    return $found
}

# -- File collection -----------------------------------------------------------
function Collect-CacheFile {
    param(
        [System.IO.FileInfo] $File,
        [string] $StagingDir
    )

    if ($File.Length -gt $script:MaxBytes) {
        $mb = [Math]::Round($File.Length / 1MB, 1)
        Write-Warn "Skipping oversized file ($mb MB): $($File.FullName)"
        $script:SkippedSize++
        return $null
    }

    $userName    = Get-UserNameFromPath $File.FullName
    $kind        = Get-CacheFileKind $File.Name
    $isExpected  = Test-IsExpectedCachePath $File.FullName
    $sha256      = Get-Sha256 $File.FullName

    $row = @{
        originalPath      = $File.FullName
        userName          = $userName
        kind              = $kind
        size              = $File.Length
        createdAt         = Get-UtcIso $File.CreationTimeUtc
        modifiedAt        = Get-UtcIso $File.LastWriteTimeUtc
        accessedAt        = Get-UtcIso $File.LastAccessTimeUtc
        sha256            = $sha256
        isExpectedCachePath = $isExpected
        status            = 'pending'
        collectedPath     = $null
    }

    if (-not $InventoryOnly) {
        # Destination: <staging>/<username>/<filename>  (or <staging>/<filename> if no user)
        $subDir  = if ($userName) { $userName } else { '_unknown' }
        $destDir = Join-Path $StagingDir $subDir
        $dest    = Join-Path $destDir $File.Name

        # Handle duplicate filenames in same user dir (different cache dirs)
        if (Test-Path $dest) {
            $base = [System.IO.Path]::GetFileNameWithoutExtension($File.Name)
            $ext  = [System.IO.Path]::GetExtension($File.Name)
            $dest = Join-Path $destDir "$base`_$([System.IO.Path]::GetRandomFileName().Substring(0,4))$ext"
        }

        try {
            if (-not (Test-Path $destDir)) { New-Item $destDir -ItemType Directory -Force | Out-Null }
            Copy-Item $File.FullName $dest -Force -ErrorAction Stop
            $row['status']        = 'collected'
            $row['collectedPath'] = $dest.Substring($StagingDir.Length).TrimStart('\', '/')
            $script:Collected++
        } catch {
            Write-Warn "Copy failed for $($File.Name): $($_.Exception.Message)"
            $row['status'] = 'error'
            $row['error']  = $_.Exception.Message
            $script:Errors++
        }
    } else {
        $row['status'] = 'inventory'
    }

    return $row
}

# -- Manifest ------------------------------------------------------------------
function Write-Manifest([string]$StagingDir, [string]$ProfileLabel) {
    $elapsed = (Get-Date) - $script:StartTime

    $summary = @{
        bcacheCount     = ($script:CacheFileRows | Where-Object { $_['kind'] -eq 'bcache' }).Count
        cacheBinCount   = ($script:CacheFileRows | Where-Object { $_['kind'] -eq 'cache-bin' }).Count
        totalBytes      = ($script:CacheFileRows | Measure-Object -Property size -Sum).Sum
        users           = @(($script:CacheFileRows | Where-Object { $_['userName'] } |
                             Select-Object -ExpandProperty userName | Sort-Object -Unique))
        cacheDirectories = @(($script:CacheFileRows | ForEach-Object {
                             [System.IO.Path]::GetDirectoryName($_['originalPath']) } | Sort-Object -Unique))
    }

    $manifest = @{
        schemaVersion    = 1
        artifactType     = 'rdp-bitmap-cache-collection'
        collectedAt      = $script:StartTime.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        collectionHost   = $env:COMPUTERNAME
        profileLabel     = $ProfileLabel
        scriptVersion    = $script:ScriptVersion
        elapsedSeconds   = [Math]::Round($elapsed.TotalSeconds, 1)
        filesCollected   = $script:Collected
        filesSkipped     = $script:SkippedSize
        errors           = $script:Errors
        hashingPerformed = (-not $SkipHash)
        maxFileSizeMB    = $MaxFileSizeMB
        summary          = $summary
        cacheFiles       = @($script:CacheFileRows)
        warnings         = @($script:Warnings)
    }

    $jsonPath = Join-Path $StagingDir 'manifest.json'
    [System.IO.File]::WriteAllText($jsonPath,
        ($manifest | ConvertTo-Json -Depth 8),
        [System.Text.Encoding]::UTF8)
    return $jsonPath
}

# -- ZIP -----------------------------------------------------------------------
function New-ZipArchive([string]$StagingDir, [string]$ZipPath) {
    try {
        try { Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction Stop } catch {}
        if (Test-Path $ZipPath) { Remove-Item $ZipPath -Force -ErrorAction Stop }
        [System.IO.Compression.ZipFile]::CreateFromDirectory($StagingDir, $ZipPath)
        return $true
    } catch {
        Write-Warn "ZIP creation failed: $($_.Exception.Message)"
        return $false
    }
}

# -- Main ----------------------------------------------------------------------
Write-Banner

if ($InventoryOnly) {
    Write-Host "  Mode: INVENTORY ONLY (no files will be copied)`n" -ForegroundColor Yellow
}

$profiles = @(Resolve-Profiles)
Write-Info "Profiles to scan: $($profiles.Count)"

$stagingDir = $null
if (-not $InventoryOnly) {
    $ts         = Get-Date -Format 'yyyyMMdd-HHmmss'
    $stagingDir = Join-Path $env:TEMP "rdpbc-staging-$ts"
    New-Item $stagingDir -ItemType Directory -Force | Out-Null
}

foreach ($profileRoot in $profiles) {
    $userName = Split-Path $profileRoot -Leaf
    Write-Section "Profile: $userName  ($profileRoot)"

    $hits = Find-CacheFilesInProfile $profileRoot
    if ($hits.Count -eq 0) {
        Write-Miss "No RDP bitmap cache files found"; continue
    }
    Write-Found "$($hits.Count) cache file(s) found"

    foreach ($hit in $hits) {
        $file = $hit['file']
        Write-Info "  $($file.Name)  ($([Math]::Round($file.Length/1KB,1)) KB)  →  $($file.FullName)"
        $row = Collect-CacheFile -File $file -StagingDir $stagingDir
        if ($row) { $script:CacheFileRows.Add($row) }
    }
}

Write-Section 'Summary'
$elapsed = (Get-Date) - $script:StartTime

if (-not $InventoryOnly -and $stagingDir) {
    $profileLabel = $profiles -join '; '
    $manifestPath = Write-Manifest -StagingDir $stagingDir -ProfileLabel $profileLabel

    $ts      = Get-Date -Format 'yyyyMMdd-HHmmss'
    $zipName = "RDPCache-$($env:COMPUTERNAME)-$ts.zip"
    $zipPath = Join-Path ([System.IO.Path]::GetFullPath($OutputPath)) $zipName

    if (-not (Test-Path $OutputPath)) { New-Item $OutputPath -ItemType Directory -Force | Out-Null }

    $zipped = New-ZipArchive -StagingDir $stagingDir -ZipPath $zipPath

    # Clean up staging dir
    Remove-Item $stagingDir -Recurse -Force -ErrorAction SilentlyContinue

    if ($zipped) {
        $zipMB = [Math]::Round((Get-Item $zipPath).Length / 1MB, 2)
        Write-Found "Output archive  : $zipPath  ($zipMB MB)"
        Write-Found "Files collected : $($script:Collected)"
    }
    if ($script:SkippedSize -gt 0) { Write-Warn "Files skipped   : $($script:SkippedSize) (size limit)" }
    if ($script:Errors -gt 0)      { Write-Warn "Copy errors     : $($script:Errors)" }
    Write-Info "Elapsed         : $([Math]::Round($elapsed.TotalSeconds,1))s"

    Write-Host ""
    Write-Host "  Defender Live Response — download the archive:" -ForegroundColor Cyan
    Write-Host "    getfile $zipPath" -ForegroundColor Green
    Write-Host ""
    Write-Host "  Then analyse with:" -ForegroundColor Cyan
    Write-Host "    .\Parse-RDPBitmapCache.ps1 -InputPath $zipPath" -ForegroundColor Green
    Write-Host "    — or load into IRFlow Timeline > Tools > RDP Bitmap Cache" -ForegroundColor Green
} else {
    Write-Host ""
    Write-Host "  Inventory results ($($script:CacheFileRows.Count) file(s) found):" -ForegroundColor Cyan
    foreach ($r in $script:CacheFileRows) {
        Write-Found ("{0,-14}  {1,8} KB  {2}" -f $r['kind'], [Math]::Round($r['size']/1KB,1), $r['originalPath'])
    }
    if ($script:CacheFileRows.Count -eq 0) { Write-Miss 'No RDP bitmap cache files found on this host.' }
    Write-Info "Elapsed: $([Math]::Round($elapsed.TotalSeconds,1))s"
}
Write-Host ""
