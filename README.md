# Host-Audit.ps1 — GitHub README

## Overview

**Host-Audit.ps1** is a PowerShell-based host integrity and kernel filter/driver audit for Windows systems. It collects a compact, read-only set of artifacts useful for triage, forensics, and system health checks.

This repository-safe version does **not** contain or reveal any environment-specific mount points or private drive letters. Configure where results are written using the `HOSTAUDIT_ROOT` environment variable or the `-OutputRoot` parameter.

---

## ✳️ What it collects

* Windows image health (`DISM /CheckHealth`) and optional `SFC /scannow` (skippable with `-Quick`)
* Windows Defender status snapshot (if platform cmdlets available)
* Mini-filter driver list (`fltmc`) in raw and parsed CSV form
* Running kernel drivers with Authenticode signature status and SHA256 hashes
* Non-Microsoft or unsigned driver subset for focused review
* Sysmon service presence/state and version (best-effort)
* Human-readable summary and a transcript of the run

All actions are read-only — the script does not modify system state.

---

## ⚙️ Requirements

* PowerShell 7.0+ (`pwsh`)
* Administrator privileges (the script auto-elevates when necessary)
* Writable output root (see **Output** below)

---

## 📁 Output and where it goes

Set the destination for results in order of precedence:

1. `-OutputRoot` parameter when invoking the script
2. `HOSTAUDIT_ROOT` environment variable
3. Fallback: `$HOME\Reports\HostAudit`

A typical run creates a timestamped folder:

```
<OUTPUT_ROOT>/<HOST>_<YYYY-MM-DD_HH-mm-ss>/
```

Example artifacts:

* `Summary_<HOST>_<STAMP>.txt` — human summary and pointers
* `Transcript_<HOST>_<STAMP>.log` — console transcript (best-effort)
* `DISM_CheckHealth_<HOST>_<STAMP>.txt`
* `SFC_<HOST>_<STAMP>.txt` (omitted with `-Quick`)
* `fltmc_<HOST>_<STAMP>.txt`
* `MiniFilters_<HOST>_<STAMP>.csv`
* `RunningKernelDrivers_<HOST>_<STAMP>.csv`
* `NonMicrosoftDrivers_<HOST>_<STAMP>.csv`

Files are UTF-8 CSV/TXT so they can be imported into Excel, SIEMs, or text tools.

---

## 🔎 Parameters

| Parameter            | Description                                      |
| -------------------- | ------------------------------------------------ |
| `-Quick`             | Skip `sfc /scannow` to finish faster.            |
| `-NoExplorer`        | Do not open the results folder when finished.    |
| `-OutputRoot <path>` | Explicit output root folder (overrides env var). |

---

## 🚀 Usage examples

```powershell
# Full run (auto-elevates, runs SFC)
pwsh -File .\Host-Audit.ps1

# Faster run (skip SFC)
pwsh -File .\Host-Audit.ps1 -Quick

# Custom output root and no Explorer popup
pwsh -File .\Host-Audit.ps1 -OutputRoot 'D:\Forensics\HostAudits' -NoExplorer
```

---

## 🧾 Interpreting results

* **DISM:** If `CheckHealth` reports no corruption, the component store is intact. If it reports repairable corruption, consider running `DISM /RestoreHealth` in a controlled maintenance window.
* **SFC:** `Windows Resource Protection did not find any integrity violations` means protected files are intact.
* **NonMicrosoftDrivers CSV:** Review entries for unexpected publishers or unsigned drivers; many third-party drivers (NVIDIA, Intel, vendor utilities) are normal, but unknown/unexpected publishers should be validated.
* **MiniFilters CSV:** Expected filters include `WdFilter`, `bindflt`, `wcifs`, `SysmonDrv` (if installed). Unexpected filter names or altitudes should be investigated.

Start with `Summary_*.txt` and then open the CSVs referenced in that file for detailed review.

---

## 🛠️ Troubleshooting & notes

* **Self-elevation spawns a new elevated window and closes the original:** This is intentional to perform admin-only checks. Results are written to the output folder by the elevated run.
* **`fltmc` access denied:** Elevation required — rerun allowing the script to elevate.
* **Missing output drive:** If you depend on a removable or network volume, set `HOSTAUDIT_ROOT` to a stable local path or ensure the volume is mounted before running.

---

## 🧰 Integration tips

Add short aliases to your PowerShell profile for convenience:

```powershell
function Host-Audit   { pwsh -File "$HOME\Host-Audit.ps1" }
function Quick-Audit  { pwsh -File "$HOME\Host-Audit.ps1" -Quick }
function Silent-Audit { pwsh -File "$HOME\Host-Audit.ps1" -NoExplorer }
Set-Alias hostaudit Host-Audit
```

---

## ⚖️ License

MIT License — feel free to fork and adapt. Do not include sensitive environment paths or secrets in public forks.

---

If you'd like, I can also produce a compact QuickRef cheat-sheet version suitable for pasting in a repo `docs/` folder.
