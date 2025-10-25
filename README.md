# Host-Audit.ps1 — README

## What it does

**Host-Audit.ps1** collects an integrity baseline and kernel/filters inventory for Windows hosts. It is safe, read-only, and designed for repeatable triage.

* **Health:** `DISM /Online /Cleanup-Image /CheckHealth` and optional `SFC /scannow`
* **Defender:** `Get-MpComputerStatus` snapshot
* **Filters:** `fltmc` parsed → `MiniFilters_*.csv`
* **Kernel drivers:** running `Win32_SystemDriver` items with:

  * normalized on-disk path
  * Authenticode signer, status, `IsOSBinary`
  * SHA256 hash
* **Findings:** Non-Microsoft publishers → `NonMicrosoftDrivers_*.csv`
* **Sysmon:** service presence/state and version (if registry value available)
* **UX:** auto-elevates and opens the results folder (Explorer) by default

## Requirements

* PowerShell 7+ (`pwsh`)
* Administrator rights (script self-elevates)
* Default output root present or creatable:

  * `T:\GNO-JUNGLE\Jaguar\Reports\HostAudit` (created if missing)

## Usage

```powershell
# Full run (opens Explorer)
pwsh -File .\Host-Audit.ps1

# Faster run (skips SFC)
pwsh -File .\Host-Audit.ps1 -Quick

# No Explorer popup
pwsh -File .\Host-Audit.ps1 -NoExplorer
```

## Output layout

Each execution writes to:

```
T:\GNO-JUNGLE\Jaguar\Reports\HostAudit\<HOST>_<YYYY-MM-DD_HH-mm-ss>\
```

Artifacts:

* `Summary_<HOST>_<STAMP>.txt` — human summary and pointers
* `Transcript_<HOST>_<STAMP>.log` — console transcript (best effort)
* `DISM_CheckHealth_<HOST>_<STAMP>.txt`
* `SFC_<HOST>_<STAMP>.txt` *(omitted with `-Quick`)*
* `fltmc_<HOST>_<STAMP>.txt` and `MiniFilters_<HOST>_<STAMP>.csv`
* `RunningKernelDrivers_<HOST>_<STAMP>.csv`
* `NonMicrosoftDrivers_<HOST>_<STAMP>.csv`

## Interpreting results

* **SFC:** “did not find any integrity violations” → protected OS files OK.
* **DISM CheckHealth:** “No component store corruption” → WinSxS clean.
* **NonMicrosoftDrivers.csv:** any entries here should be expected (e.g., NVIDIA/Intel); unsigned or unknown publishers merit review.
* **MiniFilters.csv:** expected stack typically includes `WdFilter`, `SysmonDrv` (if installed), `bindflt`, `wcifs`, etc.

## Tips

* First triage: open `Summary_*.txt` then drill into the CSVs it references.
* Keep a known-good run for diffing against future runs.
* Add to your profile for convenience:

  ```powershell
  function Host-Audit   { pwsh -File "$HOME\Host-Audit.ps1" }
  function Quick-Audit  { pwsh -File "$HOME\Host-Audit.ps1" -Quick }
  function Silent-Audit { pwsh -File "$HOME\Host-Audit.ps1" -NoExplorer }
  ```

## Troubleshooting

* **Self-elevation relaunches a new window and closes the old one:** by design. Work is done in the elevated instance; outputs go to the run folder.
* **`fltmc` Access denied:** you aren’t admin yet; let the script elevate.
* **Output path missing:** the script creates it; if `T:` is a Dev Drive that sometimes mounts late, run again after the volume appears.

## License & Safety

* Read-only collection. No persistence or remediation actions taken.
* Use at your own risk in accordance with your environment’s policies.

---

**Authoring note:** This README matches the script’s defaults (paths/switches). If you customize the root path, update the references above accordingly.
