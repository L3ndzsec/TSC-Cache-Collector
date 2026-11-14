```
 ████████╗███████╗ ██████╗      ██████╗ █████╗  ██████╗██╗  ██╗███████╗
    ██╔══╝██╔════╝██╔════╝     ██╔════╝██╔══██╗██╔════╝██║  ██║██╔════╝
    ██║   ███████╗██║          ██║     ███████║██║     ███████║█████╗
    ██║   ╚════██║██║          ██║     ██╔══██║██║     ██╔══██║██╔══╝
    ██║   ███████║╚██████╗     ╚██████╗██║  ██║╚██████╗██║  ██║███████╗
    ╚═╝   ╚══════╝ ╚═════╝      ╚═════╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝

 ██████╗ ██████╗ ██╗     ██╗     ███████╗ ██████╗████████╗ ██████╗ ██████╗
██╔════╝██╔═══██╗██║     ██║     ██╔════╝██╔════╝╚══██╔══╝██╔═══██╗██╔══██╗
██║     ██║   ██║██║     ██║     █████╗  ██║        ██║   ██║   ██║██████╔╝
██║     ██║   ██║██║     ██║     ██╔══╝  ██║        ██║   ██║   ██║██╔══██╗
╚██████╗╚██████╔╝███████╗███████╗███████╗╚██████╗   ██║   ╚██████╔╝██║  ██║
 ╚═════╝ ╚═════╝ ╚══════╝╚══════╝╚══════╝ ╚═════╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝
```

> **RDP Bitmap Cache Collector** — Triage & evidence collection for IR / MDE Live Response  
> Part of the **IRFlow Timeline** toolkit

---

## What is this?

Terminal Server Client or
RDP Bitmap Cache files (`bcache*.bmc`, `cache####.bin`) are artifacts left behind whenever a user connects to a remote desktop. Windows caches tiles of the remote screen to reduce bandwidth — meaning those tiles can contain screenshots of credentials, sensitive documents, remote IPs, and lateral movement activity, even after the RDP session has ended.

This toolkit gives you two PowerShell scripts designed for **live incident response**:

| Script | Purpose |
|---|---|
| `Collect-RDPBitmapCache.ps1` | Collect raw cache files from a live host, produce a ZIP + chain-of-custody manifest |
| `Parse-RDPBitmapCache.ps1` | Verify integrity, extract bitmap tiles via `bmc-tools`, and generate an analysis report |

Both scripts run with **no external dependencies** for the collection phase and are tested on **Windows 10 / 11 / Server 2016+**.

---

## Requirements

| Requirement | Collect | Parse |
|---|---|---|
| PowerShell 5.1+ | ✅ Required | ✅ Required |
| Admin / SYSTEM privileges | Recommended (all-user scan) | Not required |
| [bmc-tools](https://github.com/ANSSI-FR/bmc-tools) (Python) | ❌ Not needed | Optional (bitmap extraction) |
| Python 3 | ❌ Not needed | Optional (for bmc-tools.py) |

---

## MDE Live Response — Step-by-Step

### 1  Upload the scripts to your MDE Live Response library

Before an incident, upload both scripts once to your tenant's Live Response library so they are available on any device:

```
1. Open Microsoft Defender XDR portal
2. Settings → Endpoints → Live Response file library
3. Upload: Collect-RDPBitmapCache.ps1
```

---

### 2  Initiate a Live Response session

```
Microsoft Defender XDR → Devices → <target device> → Initiate Live Response Session
```

Wait for the session to connect. You will land in the Live Response console.

---

### 3  Run the collector on the target host

**Default run — collects all users, writes ZIP to `C:\Windows\Temp`:**

```
run Collect-RDPBitmapCache.ps1
```

**Inventory only — no data leaves the disk yet:**

```
run Collect-RDPBitmapCache.ps1 -parameters "-InventoryOnly"
```

**Custom output path:**

```
run Collect-RDPBitmapCache.ps1 -parameters "-OutputPath C:\IRCase"
```

**Single user profile (e.g., suspect account):**

```
run Collect-RDPBitmapCache.ps1 -parameters "-ProfilePath C:\Users\jsmith -OutputPath C:\IRCase"
```

**Offline / mounted image:**

```
run Collect-RDPBitmapCache.ps1 -parameters "-ProfilePath D:\Image\Users\victim -OutputPath C:\IRCase"
```

The script will print the exact archive path when it finishes:

```
  [+] Output archive  : C:\Windows\Temp\RDPCache-PC01-20241115-143022.zip  (1.42 MB)
  [+] Files collected : 3

  Defender Live Response — download the archive:
    getfile C:\Windows\Temp\RDPCache-PC01-20241115-143022.zip
```

---

### 4  Download the archive to your analyst machine

Copy the `getfile` command from the output and run it in the Live Response console:

```
getfile C:\Windows\Temp\RDPCache-PC01-20241115-143022.zip
```

The file will appear in the **Downloads** section of the Live Response session panel inside the portal. Save it to your analysis workstation.

---

### 5  Parse and extract bitmap tiles (analyst workstation)

**Basic parse — hash verify + extract tiles (requires bmc-tools in PATH or common locations):**

```powershell
.\Parse-RDPBitmapCache.ps1 -InputPath C:\IRCase\RDPCache-PC01-20241115-143022.zip
```

**Specify bmc-tools path explicitly:**

```powershell
.\Parse-RDPBitmapCache.ps1 `
    -InputPath    C:\IRCase\RDPCache-PC01-20241115-143022.zip `
    -BmcToolsPath C:\Tools\bmc-tools\bmc-tools.py `
    -OutputPath   C:\IRCase\Analysis
```

**Hash verification only (no bmc-tools needed):**

```powershell
.\Parse-RDPBitmapCache.ps1 -InputPath C:\IRCase\RDPCache-PC01-20241115-143022.zip -SkipExtraction
```

**Skip verification on a raw directory (no manifest):**

```powershell
.\Parse-RDPBitmapCache.ps1 -InputPath C:\RawCacheFiles -SkipVerify
```

The parser produces in the output directory:

```
<OutputPath>\
  analysis-report.json      ← machine-readable analysis + integrity results
  analysis-report.txt       ← human-readable summary
  extracted-tiles\
    tiles_bcache22\         ← one folder per cache file
      *.bmp                 ← reconstructed screen tiles
```

---

### 6  Review extracted tiles

Open the `extracted-tiles` folder and browse the `.bmp` files. Look for:

- **Credential dialogs** (login prompts, UAC boxes)
- **Remote desktop session windows** (nested RDP, pivot indicators)
- **Internal hostnames / IP addresses** visible on-screen
- **Sensitive documents or dashboards** that were viewed remotely
- **Command prompts / PowerShell windows** showing attacker commands

---

## Full Parameter Reference

### Collect-RDPBitmapCache.ps1

| Parameter | Type | Default | Description |
|---|---|---|---|
| `-OutputPath` | String | `C:\Windows\Temp` | Destination for the ZIP archive |
| `-ProfilePath` | String | *(all profiles)* | Collect from a single profile path |
| `-AllUsers` | Switch | Auto | Force all-users scan (auto when admin) |
| `-InventoryOnly` | Switch | Off | List files only; do not copy |
| `-SkipHash` | Switch | Off | Skip SHA-256 hashing (faster) |
| `-MaxFileSizeMB` | Int | `500` | Skip files exceeding this size |

### Parse-RDPBitmapCache.ps1

| Parameter | Type | Default | Description |
|---|---|---|---|
| `-InputPath` | String | **Required** | ZIP archive or directory of cache files |
| `-OutputPath` | String | `<InputPath>-Analysis` | Destination for tiles and reports |
| `-BmcToolsPath` | String | *(auto-detect)* | Path to `bmc-tools.py` or compiled binary |
| `-PythonPath` | String | *(auto-detect)* | Python 3 interpreter path |
| `-SkipExtraction` | Switch | Off | Verify hashes only; skip bmc-tools |
| `-SkipVerify` | Switch | Off | Skip SHA-256 chain-of-custody check |
| `-BmcWidth` | Int | `64` | Tile width hint for bmc-tools (`-w`) |
| `-KeepTemp` | Switch | Off | Keep temporary ZIP extraction folder |

---

## Output: manifest.json

Every collection ZIP includes a `manifest.json` for chain-of-custody documentation:

```json
{
  "artifactType": "rdp-bitmap-cache-collection",
  "collectedAt":  "2024-11-15T14:30:22Z",
  "collectionHost": "PC01",
  "filesCollected": 3,
  "hashingPerformed": true,
  "cacheFiles": [
    {
      "originalPath": "C:\\Users\\jsmith\\AppData\\Local\\Microsoft\\Terminal Server Client\\Cache\\bcache22.bmc",
      "userName": "jsmith",
      "kind": "bcache",
      "size": 1048576,
      "sha256": "e3b0c44298fc1c149afb...",
      "createdAt": "2024-11-14T08:12:01Z",
      "modifiedAt": "2024-11-15T13:55:44Z"
    }
  ]
}
```

---

## Installing bmc-tools (optional, for bitmap extraction)

```powershell
# Using pip
pip install bmc-tools

# Or clone from source
git clone https://github.com/ANSSI-FR/bmc-tools.git C:\Tools\bmc-tools
```

Then pass the path to the parser:

```powershell
.\Parse-RDPBitmapCache.ps1 -InputPath .\RDPCache.zip -BmcToolsPath C:\Tools\bmc-tools\bmc-tools.py
```

---

## Typical IR Workflow

```
[MDE Live Response Console]              [Analyst Workstation]
─────────────────────────────            ──────────────────────────────────────
run Collect-RDPBitmapCache.ps1
        │
        ▼
  RDPCache-PC01-<ts>.zip
  (C:\Windows\Temp)
        │
getfile C:\Windows\Temp\RDPCache-PC01-<ts>.zip
        │
        ▼                              .\Parse-RDPBitmapCache.ps1
  [Download to analyst]  ─────────►       -InputPath .\RDPCache-PC01-<ts>.zip
                                          -BmcToolsPath C:\Tools\bmc-tools\bmc-tools.py
                                               │
                                               ▼
                                     analysis-report.txt
                                     extracted-tiles\*.bmp
                                               │
                                               ▼
                                     Review tiles for lateral movement,
                                     credentials, and pivot evidence
```

---

## Notes

- The collector runs silently and completes in seconds on most hosts.
- When running as `SYSTEM` (the default MDE execution context), all user profiles under `C:\Users` are automatically scanned.
- Cache files are copied, not moved — the original artifacts on the target are preserved.
- SHA-256 hashes in `manifest.json` allow you to demonstrate evidence integrity in court or escalation reports.
- If a cache file exceeds `-MaxFileSizeMB` (default 500 MB) it is skipped and recorded in `warnings` inside the manifest.

---

## License

MIT — free to use, modify, and distribute. Attribution appreciated.

---

*Part of the **IRFlow Timeline** project · [github.com/L3ndzsec](https://github.com/L3ndzsec)*
