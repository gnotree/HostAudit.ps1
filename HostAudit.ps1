<#
.SYNOPSIS
  Host-Audit.ps1 — Windows host integrity & filter/driver audit (GitHub-safe).

.DESCRIPTION
  Read-only audit that collects:
    • DISM /CheckHealth (and optional SFC /scannow)
    • Defender status snapshot (if module available)
    • Mini-filter stack (fltmc) → CSV + raw txt
    • Running kernel drivers with signer + SHA256
    • Non-Microsoft driver subset
    • Sysmon service presence/state and version (best-effort)

  Outputs a timestamped folder under a configurable root. No environment-specific
  paths are embedded. The script self-elevates if needed and (by default) opens
  the results folder in Explorer when finished.

  Output root resolution (in order):
    1) -OutputRoot parameter
    2) $env:HOSTAUDIT_ROOT
    3) "$HOME\Reports\HostAudit"

.PARAMETER Quick
  Skip SFC /scannow (faster run).

.PARAMETER NoExplorer
  Do not auto-open Explorer on completion.

.PARAMETER OutputRoot
  Explicit output root (overrides HOSTAUDIT_ROOT).

.NOTES
  • Requires PowerShell 7+ and administrative rights (auto-elevates).
  • Repository-safe: does not disclose private mount points.
  • All actions are read-only.

.EXAMPLES
  pwsh -File .\Host-Audit.ps1
  pwsh -File .\Host-Audit.ps1 -Quick
  pwsh -File .\Host-Audit.ps1 -OutputRoot 'D:\Forensics\HostAudits' -NoExplorer
#>

[CmdletBinding()]
param(
  [switch]$Quick,
  [switch]$NoExplorer,
  [string]$OutputRoot
)

# ----------------------------- Elevation -----------------------------
function Ensure-Admin {
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  $p  = [Security.Principal.WindowsPrincipal]::new($id)
  if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "[+] Elevation required. Relaunching ..." -ForegroundColor Yellow
    $pwshExe = Join-Path $PSHOME 'pwsh.exe'
    $args = @('-NoLogo','-File',$PSCommandPath)
    if ($Quick) { $args += '-Quick' }
    if ($NoExplorer) { $args += '-NoExplorer' }
    if ($OutputRoot) { $args += @('-OutputRoot', $OutputRoot) }
    Start-Process -FilePath $pwshExe -ArgumentList $args -Verb RunAs | Out-Null
    exit
  }
}
Ensure-Admin

# ----------------------------- Output Paths -----------------------------
function Resolve-OutputRoot {
  param([string]$Override)
  if ($Override) { return $Override }
  if ($env:HOSTAUDIT_ROOT) { return $env:HOSTAUDIT_ROOT }
  return (Join-Path $HOME 'Reports\HostAudit')
}

$Root = Resolve-OutputRoot -Override $OutputRoot
if (-not (Test-Path $Root)) { New-Item -ItemType Directory -Path $Root -Force | Out-Null }
$HostName = $env:COMPUTERNAME
$Stamp    = Get-Date -Format 'yyyy-MM-dd_HH-mm-ss'
$OutDir   = Join-Path $Root "${HostName}_${Stamp}"
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null

# Files
$Summary   = Join-Path $OutDir "Summary_${HostName}_${Stamp}.txt"
$Transcript= Join-Path $OutDir "Transcript_${HostName}_${Stamp}.log"
$DismChk   = Join-Path $OutDir "DISM_CheckHealth_${HostName}_${Stamp}.txt"
$SfcPath   = Join-Path $OutDir "SFC_${HostName}_${Stamp}.txt"
$FltTxt    = Join-Path $OutDir "fltmc_${HostName}_${Stamp}.txt"
$FltCsv    = Join-Path $OutDir "MiniFilters_${HostName}_${Stamp}.csv"
$DrvCsv    = Join-Path $OutDir "RunningKernelDrivers_${HostName}_${Stamp}.csv"
$NonMsCsv  = Join-Path $OutDir "NonMicrosoftDrivers_${HostName}_${Stamp}.csv"

# Start transcript (best-effort)
try { Start-Transcript -Path $Transcript -Force | Out-Null } catch {}

function Write-Sum([string]$s){ Add-Content -Path $Summary -Value $s }
Add-Content -Path $Summary -Value "Host-Audit run: $((Get-Date).ToString('u'))"
Add-Content -Path $Summary -Value "Host: $HostName"
Add-Content -Path $Summary -Value "OutDir: $OutDir`n"

# ----------------------------- Health Checks -----------------------------
Write-Host "[DISM] /CheckHealth..." -ForegroundColor Cyan
$dout = cmd.exe /c 'dism /online /cleanup-image /checkhealth'
$dout | Out-File -FilePath $DismChk -Encoding UTF8
Add-Content -Path $Summary -Value "== DISM CheckHealth =="
Add-Content -Path $Summary -Value ($dout -join "`n")

$chk = ($dout -join "`n")
$needsRepair = ($chk -match 'The component store is repairable' -or $chk -match 'The component store is corrupted')
if ($needsRepair) {
  Write-Host "[DISM] Component store repairable or corrupted -> consider /RestoreHealth" -ForegroundColor Yellow
} else {
  Write-Host "[DISM] No repair needed." -ForegroundColor Green
}

if (-not $Quick) {
  Write-Host "[SFC] sfc /scannow..." -ForegroundColor Cyan
  $s = cmd.exe /c 'sfc /scannow'
  $s | Out-File -FilePath $SfcPath -Encoding UTF8
  Add-Content -Path $Summary -Value "\n== SFC /scannow =="
  Add-Content -Path $Summary -Value ($s -join "`n")
} else {
  Add-Content -Path $Summary -Value "(Quick mode: SFC skipped)"
}

# Defender status
Write-Host "[Defender] Snapshot..." -ForegroundColor Cyan
try {
  if (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue) {
    $mp = Get-MpComputerStatus
    Add-Content -Path $Summary -Value ("`n== Defender ==`nAMServiceEnabled={0} RealTime={1} Antispyware={2}" -f $mp.AMServiceEnabled,$mp.RealTimeProtectionEnabled,$mp.AntispywareEnabled)
  } else { Add-Content -Path $Summary -Value "Defender cmdlets not available." }
} catch { Add-Content -Path $Summary -Value "Defender snapshot failed: $($_.Exception.Message)" }

# Sysmon status (best-effort)
Write-Host "[Sysmon] Status..." -ForegroundColor Cyan
try {
  $sysmonSvc = Get-Service -Name 'Sysmon*' -ErrorAction SilentlyContinue | Select-Object -First 1
  if ($sysmonSvc) {
    $state = $sysmonSvc.Status
    $ver = (Get-ItemProperty -Path 'HKLM:SOFTWARE\\Microsoft\\Sysmon' -Name 'ProductVersion' -ErrorAction SilentlyContinue).ProductVersion
    Add-Content -Path $Summary -Value ("Sysmon: Service={0}  Status={1}  Version={2}" -f $sysmonSvc.Name,$state,($ver? $ver : 'Unknown'))
  } else {
    Add-Content -Path $Summary -Value "Sysmon: not installed."
  }
} catch { Add-Content -Path $Summary -Value "Sysmon check failed: $($_.Exception.Message)" }

# ----------------------------- Mini-filters -----------------------------
Write-Host "[Filters] fltmc list..." -ForegroundColor Cyan
try {
  $fltmc = & fltmc
  $fltmc | Out-File -FilePath $FltTxt -Encoding UTF8
  # Parse basic table lines into CSV (Filter Name, Num Instances, Altitude, Frame)
  $rows = @()
  foreach ($line in $fltmc) {
    if ($line -match '^-+$' -or $line -match 'Filter Name') { continue }
    $parts = ($line -replace '\s{2,}', '|').Trim('|').Split('|')
    if ($parts.Count -ge 4) {
      $rows += [pscustomobject]@{ FilterName=$parts[0].Trim(); NumInstances=$parts[1].Trim(); Altitude=$parts[2].Trim(); Frame=$parts[3].Trim() }
    }
  }
  $rows | Export-Csv -Path $FltCsv -NoTypeInformation -Encoding UTF8
} catch {
  Add-Content -Path $Summary -Value "fltmc failed (are you admin?): $($_.Exception.Message)"
}

# ----------------------------- Drivers -----------------------------
Write-Host "[Drivers] Enumerating with signatures + SHA256..." -ForegroundColor Cyan
function Normalize-Path([string]$raw){
  if (-not $raw) { return $null }
  $p = $raw.Trim('"')
  $p = $p -replace '^(\\\\\?\\)',''
  $p = $p -replace '^(?i)\\SystemRoot', "$env:SystemRoot"
  if ($p -match '^(?i)\\Windows\\') { $p = "$($env:SystemDrive)$p" }
  return $p
}

$drvRows = @()
$nonMsRows = @()
$drivers = Get-CimInstance Win32_SystemDriver | Where-Object { $_.PathName -match '\\.sys' }
foreach ($d in $drivers) {
  $path = Normalize-Path $d.PathName
  $hash = $null
  if ($path -and (Test-Path $path)) { try { $hash = (Get-FileHash -Algorithm SHA256 -Path $path).Hash } catch {} }
  $sig = $null; try { if ($path) { $sig = Get-AuthenticodeSignature -FilePath $path } } catch {}
  $pub = if ($sig -and $sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { $null }
  $row = [pscustomobject]@{
    Name=$d.Name; DisplayName=$d.DisplayName; State=$d.State; StartMode=$d.StartMode; Path=$path;
    SHA256=$hash; SignatureStatus = $(if ($sig) { $sig.Status } else { 'NoSignature' }); Publisher=$pub
  }
  $drvRows += $row
  if ($row.Publisher -and $row.Publisher -notmatch 'Microsoft' -or $row.SignatureStatus -ne 'Valid') { $nonMsRows += $row }
}
$drvRows   | Export-Csv -Path $DrvCsv  -NoTypeInformation -Encoding UTF8
$nonMsRows | Export-Csv -Path $NonMsCsv -NoTypeInformation -Encoding UTF8

# ----------------------------- Finish -----------------------------
Add-Content -Path $Summary -Value "\nArtifacts:"
Add-Content -Path $Summary -Value "  - $DismChk"
if (-not $Quick) { Add-Content -Path $Summary -Value "  - $SfcPath" }
Add-Content -Path $Summary -Value "  - $FltTxt"
Add-Content -Path $Summary -Value "  - $FltCsv"
Add-Content -Path $Summary -Value "  - $DrvCsv"
Add-Content -Path $Summary -Value "  - $NonMsCsv"

Write-Host "`n[+] Host-Audit complete. Reports saved to:`n$OutDir" -ForegroundColor Green
try { Stop-Transcript | Out-Null } catch {}
if (-not $NoExplorer) { try { Start-Process explorer.exe $OutDir } catch {} }
