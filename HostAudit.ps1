<# 
.SYNOPSIS
  Host integrity + kernel/filters audit (SFC, DISM, Defender, Sysmon, fltmc, driver signatures, hashes)
  Default output path: T:\GNO-JUNGLE\Jaguar\Reports\HostAudit
  After each run, automatically opens the run folder in Explorer (can disable with -NoExplorer).

.EXAMPLE
  pwsh -File .\Host-Audit.ps1
  pwsh -File .\Host-Audit.ps1 -Quick
  pwsh -File .\Host-Audit.ps1 -NoExplorer
#>

param(
  [switch]$Quick,
  [switch]$NoExplorer
)

# ----------------------------- Elevation -----------------------------
function Assert-Admin {
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  $p  = New-Object Security.Principal.WindowsPrincipal($id)
  if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "[+] Elevation required. Relaunching ..." -ForegroundColor Yellow
    $pwshExe = Join-Path $PSHOME 'pwsh.exe'   # ensure we spawn the EXE, not pwsh.dll
    $args = @('-NoLogo','-File',$PSCommandPath)
    if ($Quick)     { $args += '-Quick' }
    if ($NoExplorer){ $args += '-NoExplorer' }
    Start-Process -FilePath $pwshExe -ArgumentList $args -Verb RunAs | Out-Null
    exit
  }
}
Assert-Admin

# ----------------------------- Paths -----------------------------
$DefaultRoot = 'T:\GNO-JUNGLE\Jaguar\Reports\HostAudit'
if (-not (Test-Path $DefaultRoot)) { New-Item -ItemType Directory -Path $DefaultRoot -Force | Out-Null }

$HostName = $env:COMPUTERNAME
$Stamp    = Get-Date -Format 'yyyy-MM-dd_HH-mm-ss'
$OutDir   = Join-Path $DefaultRoot ("{0}_{1}" -f $HostName,$Stamp)
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null

$TxtReport  = Join-Path $OutDir ("Summary_{0}_{1}.txt" -f $HostName,$Stamp)
$CsvDrivers = Join-Path $OutDir ("RunningKernelDrivers_{0}_{1}.csv" -f $HostName,$Stamp)
$CsvFilters = Join-Path $OutDir ("MiniFilters_{0}_{1}.csv" -f $HostName,$Stamp)
$CsvIssues  = Join-Path $OutDir ("NonMicrosoftDrivers_{0}_{1}.csv" -f $HostName,$Stamp)
$LogFile    = Join-Path $OutDir ("Transcript_{0}_{1}.log" -f $HostName,$Stamp)

try { Start-Transcript -Path $LogFile -Force | Out-Null } catch {}

# ----------------------------- Helpers -----------------------------
function QuickLine([string]$s){ Add-Content -Path $TxtReport -Value $s }
function Normalize-DriverPath([string]$raw) {
  if (-not $raw) { return $null }
  $p = $raw.Trim('"')
  if ($p -match '(?i)\.sys') {
    $idx = $p.ToLower().LastIndexOf('.sys')
    if ($idx -ge 0) { $p = $p.Substring(0, $idx + 4) }
  }
  $p = $p -replace '^(\\\\\?\\)',''
  $p = $p -replace '^(?i)\\SystemRoot', $env:SystemRoot
  if ($p -match '^(?i)\\Windows\\') { $p = "$($env:SystemDrive)$p" }
  return $p
}
function Try-GetSignature($path) { try { if (Test-Path $path) { Get-AuthenticodeSignature -FilePath $path } } catch {} }
function Coalesce($a,$b){ if ($null -ne $a -and "$a" -ne '') { $a } else { $b } }
function Tick($msg){ Write-Host $msg -ForegroundColor Cyan }

# ----------------------------- System snapshot -----------------------------
Tick '[Info] System snapshot...'
try { $os   = Get-CimInstance Win32_OperatingSystem } catch {}
try { $cs   = Get-CimInstance Win32_ComputerSystem } catch {}
try { $bios = Get-CimInstance Win32_BIOS } catch {}
try { $sb   = Confirm-SecureBootUEFI -ErrorAction Stop } catch { $sb = 'Unknown/Legacy or blocked' }
try { $tpm  = Get-Tpm } catch {}

QuickLine "=== Host Audit: $HostName  @ $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') ==="
QuickLine ("OS          : {0} {1} (Build {2})" -f $os.Caption,$os.Version,[System.Environment]::OSVersion.Version.Build)
QuickLine ("Edition     : {0}" -f [System.Environment]::OSVersion.VersionString)
QuickLine ("Machine     : {0} {1}" -f $cs.Manufacturer,$cs.Model)
QuickLine ("BIOS/UEFI   : {0}  (Date: {1})" -f $bios.SMBIOSBIOSVersion,$bios.ReleaseDate)
QuickLine ("Secure Boot : {0}" -f $sb)
if ($tpm) { QuickLine ("TPM         : Present={0} Ready={1} Version={2}" -f $tpm.TpmPresent,$tpm.TpmReady,$tpm.ManufacturerVersion) }
QuickLine ''

# ----------------------------- Health checks -----------------------------
if (-not $Quick) {
  Tick '[SFC] Running...'
  QuickLine '== SFC /scannow =='
  $sfcOut = cmd.exe /c 'sfc /scannow'
  $sfcPath = Join-Path $OutDir ("SFC_{0}_{1}.txt" -f $HostName,$Stamp)
  $sfcOut | Out-File -FilePath $sfcPath -Encoding UTF8
  $sfcSummary = ($sfcOut | Select-String -Pattern 'Windows Resource Protection.*' | Select-Object -First 1).Line
  QuickLine (Coalesce $sfcSummary "SFC completed. See: $sfcPath")
  QuickLine ''
} else { QuickLine '== SFC skipped (Quick mode) =='; QuickLine '' }

Tick '[DISM] CheckHealth...'
QuickLine '== DISM /Online /Cleanup-Image /CheckHealth =='
$dismOut = cmd.exe /c 'dism /online /cleanup-image /checkhealth'
$dismPath = Join-Path $OutDir ("DISM_CheckHealth_{0}_{1}.txt" -f $HostName,$Stamp)
$dismOut | Out-File -FilePath $dismPath -Encoding UTF8
$dismSummary = ($dismOut | Select-String -Pattern 'No component store corruption|The component store is repairable|repair operation' | Select-Object -First 1).Line
QuickLine (Coalesce $dismSummary "DISM completed. See: $dismPath")
QuickLine ''

# ----------------------------- Defender -----------------------------
Tick '[Defender] Status...'
QuickLine '== Microsoft Defender Status =='
try {
  $mp = Get-MpComputerStatus
  $defLine = "AMService={0}  RTP={1}  Antispyware={2}  Engine={3}" -f $mp.AMServiceEnabled,$mp.RealTimeProtectionEnabled,$mp.AntispywareEnabled,$mp.AMEngineVersion
  QuickLine $defLine
} catch { QuickLine "Defender status unavailable: $($_.Exception.Message)" }
QuickLine ''

# ----------------------------- Sysmon -----------------------------
Tick '[Sysmon] Status...'
QuickLine '== Sysmon =='
try {
  $sysmonSvc = Get-Service -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '^Sysmon(64)?$' }
  if ($sysmonSvc) {
    $state = $sysmonSvc.Status
    $ver = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Sysinternals\Sysmon' -ErrorAction SilentlyContinue).Version
    QuickLine ("Service={0}  Status={1}  Version={2}" -f $sysmonSvc.Name,$state,(Coalesce $ver 'Unknown'))
  } else {
    QuickLine 'Sysmon service not found.'
  }
} catch { QuickLine "Sysmon check failed: $($_.Exception.Message)" }
QuickLine ''

# ----------------------------- Mini-filters -----------------------------
Tick '[fltmc] Enumerating mini-filters...'
QuickLine '== Mini-Filter Drivers (fltmc) =='
try {
  $flt = fltmc
  $fltText = Join-Path $OutDir ("fltmc_{0}_{1}.txt" -f $HostName,$Stamp)
  $flt | Out-File -FilePath $fltText -Encoding UTF8

  $fltObjs = @()
  foreach ($line in $flt) {
    if ($line -match '^\s*-{5,}') { continue }
    if ($line -match '^(Filter Name)') { continue }
    if ($line.Trim() -eq '') { continue }
    if ($line -match '^\S') {
      $parts = ($line -replace '\s{2,}', '|').Split('|')
      if ($parts.Count -ge 4) {
        $fltObjs += [pscustomobject]@{
          FilterName    = $parts[0].Trim()
          NumInstances  = $parts[1].Trim()
          Altitude      = $parts[2].Trim()
          Frame         = $parts[3].Trim()
        }
      }
    }
  }
  $fltObjs | Export-Csv -Path $CsvFilters -NoTypeInformation -Encoding UTF8
  QuickLine ("Saved mini-filter table to: {0}" -f $CsvFilters)
} catch {
  QuickLine "fltmc failed: $($_.Exception.Message)"
}
QuickLine ''

# ----------------------------- Running kernel drivers -----------------------------
Tick '[Drivers] Inventory + signatures...'
QuickLine '== Running Kernel Drivers (*.sys) — Signatures & Hashes =='
try {
  $drivers = Get-CimInstance Win32_SystemDriver | Where-Object { $_.State -eq 'Running' -and $_.PathName -match '\.sys' }
} catch {
  $drivers = Get-WmiObject Win32_SystemDriver | Where-Object { $_.State -eq 'Running' -and $_.PathName -match '\.sys' }
}

$rows = foreach ($d in $drivers) {
  $path = Normalize-DriverPath $d.PathName
  $sig = $null; $hash = $null
  if ($path -and (Test-Path $path)) {
    $sig  = Try-GetSignature $path
    try { $hash = Get-FileHash -Algorithm SHA256 -Path $path } catch {}
  }

  [pscustomobject]@{
    ServiceName     = $d.Name
    DisplayName     = $d.DisplayName
    StartMode       = $d.StartMode
    State           = $d.State
    Path            = $path
    Exists          = $(if ($path) { Test-Path $path } else { $false })
    Publisher       = $(if ($sig) { $sig.SignerCertificate.Subject } else { $null })
    Issuer          = $(if ($sig) { $sig.SignerCertificate.Issuer } else { $null })
    SignatureStatus = $(if ($sig) { $sig.Status } else { 'Unknown' })
    IsOSBinary      = $(if ($sig) { $sig.IsOSBinary } else { $null })
    HashAlgorithm   = $(if ($hash) { $hash.Algorithm } else { $null })
    SHA256          = $(if ($hash) { $hash.Hash } else { $null })
  }
}

$rows | Sort-Object ServiceName | Export-Csv -Path $CsvDrivers -NoTypeInformation -Encoding UTF8
$nonMs = $rows | Where-Object { $_.Publisher -and ($_.Publisher -notmatch 'CN=Microsoft|O=Microsoft') }
$nonMs | Sort-Object Publisher,ServiceName | Export-Csv -Path $CsvIssues -NoTypeInformation -Encoding UTF8
QuickLine ("Saved running driver inventory to: {0}" -f $CsvDrivers)
QuickLine ("Saved non-Microsoft driver list to: {0}" -f $CsvIssues)
QuickLine ''

# ----------------------------- Summary -----------------------------
QuickLine '== Summary =='
QuickLine ("Drivers running: {0}" -f ($rows.Count))
QuickLine ("Non-Microsoft drivers: {0}" -f ($nonMs.Count))
QuickLine ("Output folder: {0}" -f $OutDir)

try { Stop-Transcript | Out-Null } catch {}
Write-Host "`n[+] Audit complete. Reports saved to:`n$OutDir" -ForegroundColor Green

# ----------------------------- Auto-open in Explorer -----------------------------
if (-not $NoExplorer) {
  try { Start-Process explorer.exe $OutDir } catch { Write-Host "[!] Could not open Explorer: $($_.Exception.Message)" -ForegroundColor Yellow }
}

if ($nonMs.Count -gt 0) {
  Write-Host ("[!] Non-Microsoft drivers detected: {0}. See:`n{1}" -f $nonMs.Count,$CsvIssues) -ForegroundColor Yellow
}
