# CoreKit :: Health Inspector - hardware collector (run by CoreKit.exe)
# Output protocol (one per line):  P|pct|label   L|kind|text   R|<json>

$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference    = 'SilentlyContinue'
try { [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false) } catch {}
Add-Type -AssemblyName System.Windows.Forms

$script:IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$script:Deg      = [char]0xB0
$script:Sections = New-Object System.Collections.ArrayList
$script:Quick    = [ordered]@{}
$script:IsLaptop = $false
$script:Bench    = $null
$script:DiskSpeed = $null
$script:InstallAgeDays = $null
$script:CpuGen   = $null
$script:LastPct  = 0

function Out-Line([string]$s) { [Console]::Out.WriteLine($s); [Console]::Out.Flush() }
function Emit-Log([string]$Kind, [string]$Text) { Out-Line ("L|{0}|{1}" -f $Kind, ($Text -replace '[\r\n]+', ' ')) }
function Set-Status([string]$Text, [int]$Pct = -1, [bool]$NoLog = $false) {
    if ($Pct -ge 0) { $script:LastPct = $Pct }
    Out-Line ("P|{0}|{1}" -f $script:LastPct, $Text)
}
function Clamp($v) { if ($null -eq $v) { return $null }; [int][math]::Max(0, [math]::Min(100, [math]::Round([double]$v))) }
function Grade($v) { if ($v -ge 90) { 'Excellent' } elseif ($v -ge 75) { 'Good' } elseif ($v -ge 60) { 'Fair' } elseif ($v -ge 40) { 'Poor' } else { 'Bad' } }
function WinsatToScore($x) { Clamp(((([double]$x) - 2) / 7.9) * 100) }
function New-Section([string]$Title, [string]$Kind, [int]$Weight = 0) {
    $s = [pscustomobject]@{ Title = $Title; Kind = $Kind; Weight = $Weight; Score = $null
        Rows = (New-Object System.Collections.ArrayList); Notes = (New-Object System.Collections.ArrayList) }
    [void]$script:Sections.Add($s)
    return $s
}
function Add-Row($s, [string]$Label, $Value, [string]$Status = 'info') { [void]$s.Rows.Add([pscustomobject]@{ L = $Label; V = [string]$Value; S = $Status }) }
function Add-Note($s, [string]$Text, [string]$Status = 'warn') { [void]$s.Notes.Add([pscustomobject]@{ T = $Text; S = $Status }) }

function Run-Quiet([string]$Exe, [string]$ArgList, [int]$Timeout = 180) {
    $out = Join-Path $env:TEMP ('corekit_' + [guid]::NewGuid().ToString('N') + '.txt')
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = "$env:windir\System32\cmd.exe"
    $psi.Arguments = "/c `"$Exe $ArgList > `"$out`" 2>&1`""
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $p = [System.Diagnostics.Process]::Start($psi)
    if (-not $p.WaitForExit($Timeout * 1000)) { try { $p.Kill() } catch {} }
    $txt = ''
    if (Test-Path $out) { $txt = [string](Get-Content $out -Raw); Remove-Item $out -Force }
    return $txt
}
function Get-MBs($txt) {
    if ($txt -match '([\d\.,]+)\s*MB/s') { return [math]::Round([double]($Matches[1] -replace ',', '.'), 0) }
    return $null
}

# =================================================================== CHECKS

function Run-Benchmark {
    if (-not (Test-Path "$env:windir\System32\winsat.exe")) { return }
    [void](Run-Quiet 'winsat.exe' 'formal -restart clean' 420)
    $w = Get-CimInstance Win32_WinSAT
    if ($w -and $w.WinSATAssessmentState -eq 1) { $script:Bench = $w }
}

function Run-DiskSpeed {
    if (-not (Test-Path "$env:windir\System32\winsat.exe")) { return }
    $d = $env:SystemDrive.TrimEnd(':')
    $r = Get-MBs (Run-Quiet 'winsat.exe' "disk -seq -read -drive $d" 120)
    Set-Status 'Disk speed'
    $w = Get-MBs (Run-Quiet 'winsat.exe' "disk -seq -write -drive $d" 120)
    if ($r -or $w) { $script:DiskSpeed = @{ Read = $r; Write = $w } }
}

function Check-System {
    $s = New-Section 'System Overview' 'Info'
    $cs   = Get-CimInstance Win32_ComputerSystem
    $os   = Get-CimInstance Win32_OperatingSystem
    $bios = Get-CimInstance Win32_BIOS
    $prod = Get-CimInstance Win32_ComputerSystemProduct
    $encl = Get-CimInstance Win32_SystemEnclosure
    $cv   = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'

    $laptopTypes = 8, 9, 10, 11, 12, 14, 18, 21, 30, 31, 32
    $script:IsLaptop = $false
    foreach ($t in @($encl.ChassisTypes)) { if ($laptopTypes -contains [int]$t) { $script:IsLaptop = $true } }
    if (-not $script:IsLaptop -and @(Get-CimInstance Win32_Battery).Count -gt 0) { $script:IsLaptop = $true }

    $model = [string]$cs.Model
    $pv = [string]$prod.Version
    if ($pv -and $pv -notmatch '^(None|To be filled.*|System Version|Default string|\s*)$' -and $model -notlike "*$pv*") { $model = "$model ($pv)" }

    Add-Row $s 'Manufacturer' $cs.Manufacturer
    Add-Row $s 'Model' $model
    Add-Row $s 'Serial Number' $bios.SerialNumber
    Add-Row $s 'Device Type' $(if ($script:IsLaptop) { 'Laptop / Portable' } else { 'Desktop PC' })
    $ver = $cv.DisplayVersion; if (-not $ver) { $ver = $cv.ReleaseId }
    $osName = ([string]$os.Caption) -replace 'Microsoft ', ''
    Add-Row $s 'Windows' ("{0} {1} ({2}), build {3}.{4}" -f $osName, $ver, $os.OSArchitecture, $os.BuildNumber, $cv.UBR)
    if ($os.InstallDate) {
        $age = [int]((Get-Date) - $os.InstallDate).TotalDays
        $script:InstallAgeDays = $age
        Add-Row $s 'Windows Installed On' ("{0:dd MMM yyyy} ({1} days ago)" -f $os.InstallDate, $age)
    }
    $up = (Get-Date) - $os.LastBootUpTime
    Add-Row $s 'Uptime' ("{0}d {1}h {2}m" -f $up.Days, $up.Hours, $up.Minutes)
    Add-Row $s 'BIOS' ("{0} {1} ({2:dd MMM yyyy})" -f $bios.Manufacturer, $bios.SMBIOSBIOSVersion, $bios.ReleaseDate)
    Add-Row $s 'Computer Name' $env:COMPUTERNAME
    Add-Row $s 'Checked On' (Get-Date -Format 'dd MMM yyyy, HH:mm')
    Add-Row $s 'Run Mode' $(if ($script:IsAdmin) { 'Administrator (full check)' } else { 'Limited (not Administrator) - some checks skipped' }) $(if ($script:IsAdmin) { 'ok' } else { 'warn' })
    if (-not $script:IsAdmin) { Add-Note $s 'Not running as Administrator: SSD health, TPM, Secure Boot and speed tests may be missing. Re-open and click Yes on the permission prompt.' 'warn' }

    $script:Quick['Model'] = "$($cs.Manufacturer) $model"
    $script:Quick['Windows'] = "$osName $ver"
    $script:Quick['Serial'] = $bios.SerialNumber
}

function Check-CPU {
    $s = New-Section 'Processor (CPU)' 'Performance' 35
    $cpus = @(Get-CimInstance Win32_Processor)
    $c = $cpus[0]
    $name = (([string]$c.Name) -replace '\s+', ' ').Trim()
    $cores = ($cpus | Measure-Object NumberOfCores -Sum).Sum
    $threads = ($cpus | Measure-Object NumberOfLogicalProcessors -Sum).Sum
    Add-Row $s 'Model' $name
    Add-Row $s 'Cores / Threads' "$cores cores / $threads threads"
    Add-Row $s 'Base Speed' ('{0:N2} GHz' -f ($c.MaxClockSpeed / 1000))
    if ($c.L3CacheSize) { Add-Row $s 'L3 Cache' ('{0:N0} MB' -f ($c.L3CacheSize / 1024)) }
    $load = [math]::Round(($cpus | Measure-Object LoadPercentage -Average).Average)
    Add-Row $s 'Current Load' "$load %" $(if ($load -gt 85) { 'warn' } else { 'ok' })
    Add-Row $s 'Virtualization' $(if ($c.VirtualizationFirmwareEnabled) { 'Enabled' } else { 'Disabled / not reported' })

    $tz = @(Get-CimInstance -Namespace root/wmi -ClassName MSAcpi_ThermalZoneTemperature)
    if ($tz.Count -gt 0) {
        $t = ($tz | ForEach-Object { ($_.CurrentTemperature / 10) - 273.15 } | Measure-Object -Maximum).Maximum
        if ($t -gt 5 -and $t -lt 120) {
            $st = if ($t -ge 90) { 'bad' } elseif ($t -ge 78) { 'warn' } else { 'ok' }
            Add-Row $s 'Temperature (ACPI)' ('{0:N0} {1}C' -f $t, $script:Deg) $st
            if ($t -ge 90) { Add-Note $s ("CPU is very hot ({0:N0} C). Fan / thermal paste may need cleaning or service." -f $t) 'bad' }
        }
    }

    $score = if ($threads -ge 16) { 95 } elseif ($threads -ge 12) { 88 } elseif ($threads -ge 8) { 78 } elseif ($threads -ge 6) { 66 } elseif ($threads -ge 4) { 50 } else { 30 }
    $cap = 100
    if ($name -match 'Celeron|Pentium|Atom|Athlon|AMD A\d|AMD E\d|\bE1-|\bE2-') {
        $cap = 40
        Add-Note $s 'This is an entry-level processor. Fine for basic browsing/Office, slow for heavy work.' 'warn'
    }
    if ($name -match 'i[3579]-(\d{4,5})') {
        $num = $Matches[1]
        $gen = if ($num.Length -eq 5 -or $num.StartsWith('1')) { [int]$num.Substring(0, 2) } else { [int]$num.Substring(0, 1) }
        $script:CpuGen = $gen
        Add-Row $s 'Intel Generation' "Gen $gen" $(if ($gen -ge 8) { 'ok' } else { 'warn' })
        if ($gen -le 5) { $cap = [math]::Min($cap, 35) } elseif ($gen -le 7) { $cap = [math]::Min($cap, 50) } elseif ($gen -le 9) { $cap = [math]::Min($cap, 68) } elseif ($gen -le 10) { $cap = [math]::Min($cap, 78) }
        if ($gen -le 7) { Add-Note $s "Old Intel CPU (Gen $gen). Not officially supported by Windows 11 and will feel slow for modern use." 'warn' }
    }
    elseif ($name -match 'Ryzen\s+\d\s+(?:PRO\s+)?(\d)\d{3}') {
        $ser = [int]$Matches[1]
        $script:CpuGen = 99
        if ($ser -le 2) { $cap = [math]::Min($cap, 55); $script:CpuGen = 1 } elseif ($ser -le 3) { $cap = [math]::Min($cap, 72) }
    }
    elseif ($name -match 'Core\(TM\) Ultra|Core Ultra|Ryzen AI|Snapdragon') { $script:CpuGen = 99 }
    $score = [math]::Min($score, $cap)

    if ($script:Bench -and $script:Bench.CPUScore -gt 0) {
        Add-Row $s 'Benchmark (WinSAT)' ("{0} / 9.9" -f $script:Bench.CPUScore)
        $score = 0.6 * (WinsatToScore $script:Bench.CPUScore) + 0.4 * $score
    }
    $s.Score = Clamp $score
    $script:Quick['Processor'] = "$name ($cores C / $threads T)"
}

function Check-RAM {
    $s = New-Section 'Memory (RAM)' 'Performance' 20
    $mods = @(Get-CimInstance Win32_PhysicalMemory)
    $os = Get-CimInstance Win32_OperatingSystem
    $totalBytes = ($mods | Measure-Object Capacity -Sum).Sum
    if (-not $totalBytes) { $totalBytes = (Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory }
    $gb = [math]::Round($totalBytes / 1GB)
    $slots = (Get-CimInstance Win32_PhysicalMemoryArray | Measure-Object MemoryDevices -Sum).Sum
    $types = @{ 20 = 'DDR'; 21 = 'DDR2'; 24 = 'DDR3'; 26 = 'DDR4'; 27 = 'LPDDR'; 28 = 'LPDDR2'; 29 = 'LPDDR3'; 30 = 'LPDDR4'; 34 = 'DDR5'; 35 = 'LPDDR5' }
    $t = ''
    if ($mods.Count -gt 0) { $t = $types[[int]$mods[0].SMBIOSMemoryType] }
    $speed = $null
    if ($mods.Count -gt 0) { $speed = $mods[0].ConfiguredClockSpeed; if (-not $speed) { $speed = $mods[0].Speed } }

    Add-Row $s 'Installed' "$gb GB $t" $(if ($gb -ge 8) { 'ok' } elseif ($gb -ge 6) { 'warn' } else { 'bad' })
    if ($speed) { Add-Row $s 'Speed' "$speed MT/s" }
    if ($slots) { Add-Row $s 'Slots Used' "$($mods.Count) of $slots" }
    if ($os.TotalVisibleMemorySize) {
        $used = [math]::Round((1 - $os.FreePhysicalMemory / $os.TotalVisibleMemorySize) * 100)
        Add-Row $s 'Current Usage' "$used %" $(if ($used -gt 85) { 'warn' } else { 'ok' })
    }
    $i = 1
    foreach ($m in $mods) {
        Add-Row $s ("  Stick {0}" -f $i) ("{0} GB - {1} {2} [{3}]" -f [math]::Round($m.Capacity / 1GB), ([string]$m.Manufacturer).Trim(), ([string]$m.PartNumber).Trim(), $m.DeviceLocator)
        $i++
    }

    $score = if ($gb -ge 32) { 100 } elseif ($gb -ge 16) { 90 } elseif ($gb -ge 12) { 78 } elseif ($gb -ge 8) { 65 } elseif ($gb -ge 6) { 45 } elseif ($gb -ge 4) { 30 } else { 15 }
    if ($gb -lt 8) { Add-Note $s "Only $gb GB RAM. 8 GB is the minimum for smooth Windows 10/11; 16 GB is recommended." 'warn' }
    if ($slots -gt $mods.Count -and $mods.Count -gt 0) { Add-Note $s ("Upgradeable: {0} empty RAM slot(s) available." -f ($slots - $mods.Count)) 'ok' }
    if ($mods.Count -eq 1 -and $slots -gt 1) { Add-Note $s 'Single RAM stick (single-channel). Adding a matching stick improves speed, especially graphics.' 'info' }

    if ($script:Bench -and $script:Bench.MemoryScore -gt 0) {
        Add-Row $s 'Benchmark (WinSAT)' ("{0} / 9.9" -f $script:Bench.MemoryScore)
        $score = 0.5 * (WinsatToScore $script:Bench.MemoryScore) + 0.5 * $score
    }
    $s.Score = Clamp $score
    $script:Quick['Memory'] = "$gb GB $t"
}

function Check-GPU {
    $s = New-Section 'Graphics (GPU)' 'Performance' 20
    $gpus = @(Get-CimInstance Win32_VideoController)
    $reg = @(Get-ItemProperty 'HKLM:\SYSTEM\ControlSet001\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0*')
    $best = 0; $names = @()
    foreach ($g in $gpus) {
        $name = [string]$g.Name
        $names += $name
        $vram = 0
        $r = $reg | Where-Object { $_.DriverDesc -eq $name } | Select-Object -First 1
        if ($r) {
            $q = $r.'HardwareInformation.qwMemorySize'
            if ($q -is [byte[]]) { if ($q.Length -ge 8) { $q = [BitConverter]::ToUInt64($q, 0) } else { $q = $null } }
            if ($q) { $vram = [double]$q }
            else {
                $m = $r.'HardwareInformation.MemorySize'
                if ($m -is [byte[]]) { if ($m.Length -ge 4) { $m = [BitConverter]::ToUInt32($m, 0) } else { $m = $null } }
                if ($m) { $vram = [double]$m }
            }
        }
        if (-not $vram -and $g.AdapterRAM) { $vram = [double][uint32]$g.AdapterRAM }

        $dedicated = $name -match 'NVIDIA|GeForce|Quadro|RTX|GTX|Radeon RX|Radeon Pro|FirePro|Arc\(TM\) A\d|Arc A\d|Arc B\d'
        $basic = $name -match 'Microsoft Basic Display|Basic Render'
        Add-Row $s $name $(if ($dedicated) { 'Dedicated GPU' } elseif ($basic) { 'NO DRIVER INSTALLED' } else { 'Integrated GPU' }) 'head'
        if ($vram -gt 0) { Add-Row $s '  Video Memory' ('{0:N1} GB' -f ($vram / 1GB)) }
        Add-Row $s '  Driver' ("{0} ({1:dd MMM yyyy})" -f $g.DriverVersion, $g.DriverDate)
        if ($g.CurrentHorizontalResolution) { Add-Row $s '  Current Mode' ("{0} x {1} @ {2} Hz" -f $g.CurrentHorizontalResolution, $g.CurrentVerticalResolution, $g.CurrentRefreshRate) }
        Add-Row $s '  Status' $g.Status $(if ($g.Status -eq 'OK') { 'ok' } else { 'warn' })
        if ($basic) { Add-Note $s 'Graphics driver is NOT installed (Microsoft Basic Display Adapter). Install the driver and check again - a missing driver can hide a faulty GPU.' 'bad' }
        if ($g.ConfigManagerErrorCode -and $g.ConfigManagerErrorCode -ne 0) {
            Add-Note $s ("GPU '{0}' has a device error (code {1}). Code 43 often means a faulty graphics chip." -f $name, $g.ConfigManagerErrorCode) 'bad'
        }

        $gbv = $vram / 1GB
        if ($dedicated) {
            $sc = if ($gbv -ge 8) { 95 } elseif ($gbv -ge 6) { 88 } elseif ($gbv -ge 4) { 80 } elseif ($gbv -ge 2) { 65 } else { 55 }
            if ($name -match 'GT ?\d{3,4}|MX ?\d{3}|Quadro K|GTX [6-9]\d0\b') { $sc = [math]::Min($sc, 50) }
        }
        elseif ($name -match '780M|880M|890M|680M|Arc\(TM\) Graphics|Arc Graphics|Radeon\(TM\) 8\d0M') { $sc = 62 }
        elseif ($name -match 'Iris|Vega|Radeon') { $sc = 45 }
        elseif ($basic) { $sc = 10 }
        else { $sc = 30 }
        if ($sc -gt $best) { $best = $sc }
    }

    $smi = (Get-Command nvidia-smi.exe).Source
    if (-not $smi -and (Test-Path "$env:ProgramFiles\NVIDIA Corporation\NVSMI\nvidia-smi.exe")) { $smi = "$env:ProgramFiles\NVIDIA Corporation\NVSMI\nvidia-smi.exe" }
    if ($smi) {
        $o = & $smi --query-gpu=temperature.gpu,utilization.gpu --format=csv,noheader,nounits 2>$null
        if ($o) {
            $p = ([string]($o | Select-Object -First 1)).Split(',')
            if ($p.Count -ge 2) {
                $tt = [int]$p[0].Trim()
                Add-Row $s 'NVIDIA GPU Temperature' ("{0} {1}C" -f $tt, $script:Deg) $(if ($tt -ge 87) { 'bad' } elseif ($tt -ge 78) { 'warn' } else { 'ok' })
                Add-Row $s 'NVIDIA GPU Load' ("{0} %" -f $p[1].Trim())
            }
        }
    }

    if ($script:Bench -and $script:Bench.GraphicsScore -gt 0) {
        Add-Row $s 'Benchmark (WinSAT)' ("Desktop {0} / Gaming {1} (out of 9.9)" -f $script:Bench.GraphicsScore, $script:Bench.D3DScore)
        $b = ([double]$script:Bench.GraphicsScore + [double]$script:Bench.D3DScore) / 2
        $best = 0.5 * (WinsatToScore $b) + 0.5 * $best
    }
    $s.Score = Clamp $best
    $script:Quick['Graphics'] = ($names -join ' + ')
}

function Check-Storage {
    $s = New-Section 'Storage Health' 'Health' 35
    $sp = New-Section 'Storage Speed' 'Performance' 25
    $disks = @(Get-PhysicalDisk | Sort-Object { [int]$_.DeviceId })
    if ($disks.Count -eq 0) { Add-Note $s 'Could not read disk information (run as Administrator).' 'warn'; return }
    $sysDisk = $null
    try { $sysDisk = (Get-Partition -DriveLetter ($env:SystemDrive.Substring(0, 1)) -ErrorAction Stop).DiskNumber } catch {}
    $pred = @(Get-CimInstance -Namespace root/wmi -ClassName MSStorageDriver_FailurePredictStatus | Where-Object { $_.PredictFailure })
    $scores = @(); $sysKind = $null; $quick = @()

    foreach ($d in $disks) {
        $num = [int]$d.DeviceId
        if ([string]$d.BusType -eq 'USB') { Add-Row $s "Disk $num" "$($d.FriendlyName) - USB external drive (not scored)" 'head'; continue }
        $isHDD = [string]$d.MediaType -eq 'HDD'
        $isNVMe = [string]$d.BusType -eq 'NVMe'
        $isSSD = $isNVMe -or ([string]$d.MediaType -eq 'SSD')
        $kind = if ($isNVMe) { 'NVMe SSD' } elseif ($isSSD) { 'SATA SSD' } elseif ($isHDD) { 'Hard Disk (HDD)' } else { "$($d.BusType) disk" }
        $isSys = ($null -ne $sysDisk -and $num -eq [int]$sysDisk)
        $hdr = "Disk $num" + $(if ($isSys) { ' - Windows drive' } else { '' })
        Add-Row $s $hdr ("{0}  |  {1}  |  {2:N0} GB" -f $d.FriendlyName, $kind, ($d.Size / 1GB)) 'head'
        $quick += ("{0:N0} GB {1}" -f ($d.Size / 1GB), $kind)

        $sc = 100
        $hs = [string]$d.HealthStatus
        Add-Row $s '  Windows Health Status' $hs $(if ($hs -eq 'Healthy') { 'ok' } elseif ($hs -eq 'Warning') { 'warn' } else { 'bad' })
        if ($hs -eq 'Warning') { $sc = [math]::Min($sc, 50); Add-Note $s "Disk $num ($($d.FriendlyName)) reports WARNING health status." 'bad' }
        elseif ($hs -and $hs -ne 'Healthy') { $sc = 10; Add-Note $s "Disk $num ($($d.FriendlyName)) is UNHEALTHY. It may fail soon." 'bad' }

        $rc = $null
        try { $rc = $d | Get-StorageReliabilityCounter -ErrorAction Stop } catch {}
        if ($rc) {
            if ($null -ne $rc.Wear -and $isSSD) {
                $life = 100 - [int]$rc.Wear
                Add-Row $s '  SSD Life Remaining' "$life %" $(if ($life -ge 80) { 'ok' } elseif ($life -ge 50) { 'warn' } else { 'bad' })
                $sc = [math]::Min($sc, $life)
                if ($life -lt 50) { Add-Note $s "SSD on Disk $num has only $life% life left." 'bad' } elseif ($life -lt 80) { Add-Note $s "SSD on Disk $num is $([int]$rc.Wear)% worn." 'warn' }
            }
            if ($rc.PowerOnHours) {
                $hrs = [double]$rc.PowerOnHours
                $hst = 'info'
                if ($isHDD -and $hrs -gt 35000) { $hst = 'warn'; $sc -= 15; Add-Note $s "Hard disk $num has run $([math]::Round($hrs)) hours - it is old." 'warn' }
                Add-Row $s '  Power-On Hours' ("{0:N0} hours (about {1:N1} years of use)" -f $hrs, ($hrs / 8760)) $hst
            }
            if ($rc.Temperature) {
                $tt = [int]$rc.Temperature
                $tst = if ($tt -ge 70) { 'bad' } elseif ($tt -ge 60) { 'warn' } else { 'ok' }
                if ($tt -ge 70) { $sc -= 15 } elseif ($tt -ge 60) { $sc -= 5 }
                Add-Row $s '  Temperature' ("{0} {1}C" -f $tt, $script:Deg) $tst
            }
            if ($null -ne $rc.ReadErrorsUncorrected -or $null -ne $rc.WriteErrorsUncorrected -or $null -ne $rc.ReadErrorsTotal) {
                $unc = [int]$rc.ReadErrorsUncorrected + [int]$rc.WriteErrorsUncorrected
                $tot = [int]$rc.ReadErrorsTotal + [int]$rc.WriteErrorsTotal
                Add-Row $s '  Read / Write Errors' ("{0} uncorrected, {1} total" -f $unc, $tot) $(if ($unc -gt 0) { 'bad' } elseif ($tot -gt 0) { 'warn' } else { 'ok' })
                if ($unc -gt 0) { $sc -= 25; Add-Note $s "Disk $num has $unc uncorrected read/write errors." 'bad' }
            }
            if ($rc.StartStopCycleCount) { Add-Row $s '  Power Cycles' ("{0:N0}" -f $rc.StartStopCycleCount) }
        }
        else { Add-Row $s '  Detailed SMART data' $(if ($script:IsAdmin) { 'Not reported by this drive' } else { 'Needs Administrator' }) }

        $vols = @(Get-Partition -DiskNumber $num | Where-Object { [string]$_.DriveLetter -match '[A-Za-z]' } | ForEach-Object { Get-Volume -DriveLetter $_.DriveLetter })
        foreach ($v in $vols) {
            if ($v.Size -gt 0) {
                $fp = $v.SizeRemaining / $v.Size * 100
                Add-Row $s ("  Drive {0}:" -f $v.DriveLetter) ("{0:N0} GB free of {1:N0} GB ({2:N0}% free)" -f ($v.SizeRemaining / 1GB), ($v.Size / 1GB), $fp) $(if ($fp -lt 10) { 'warn' } else { 'ok' })
            }
        }
        if ($isSys) { $sysKind = $kind }
        $scores += (Clamp $sc)
    }
    if ($pred.Count -gt 0) {
        Add-Note $s 'SMART FAILURE PREDICTED on a drive! The drive is likely to fail. Do not buy without replacing it.' 'bad'
        $scores += 5
    }
    if ($scores.Count) { $s.Score = ($scores | Measure-Object -Minimum).Minimum }
    $script:Quick['Storage'] = ($quick -join ' + ')

    # ---- speed
    if (-not $sysKind) { $sysKind = 'Unknown' }
    Add-Row $sp 'Windows Drive Type' $sysKind $(if ($sysKind -like '*SSD*') { 'ok' } else { 'warn' })
    $perf = if ($sysKind -eq 'NVMe SSD') { 100 } elseif ($sysKind -eq 'SATA SSD') { 82 } elseif ($sysKind -like '*HDD*') { 30 } else { 60 }
    if ($sysKind -like '*HDD*') { Add-Note $sp 'Windows is on a hard disk (HDD). The PC will feel slow. An SSD upgrade is strongly recommended.' 'warn' }
    if ($script:DiskSpeed) {
        $rd = $script:DiskSpeed.Read; $wr = $script:DiskSpeed.Write
        $expect = if ($sysKind -eq 'NVMe SSD') { 1000 } elseif ($sysKind -eq 'SATA SSD') { 300 } else { 80 }
        if ($rd) { Add-Row $sp 'Sequential Read' "$rd MB/s" $(if ($rd -ge $expect) { 'ok' } else { 'warn' }) }
        if ($wr) { Add-Row $sp 'Sequential Write' "$wr MB/s" $(if ($wr -ge ($expect * 0.5)) { 'ok' } else { 'warn' }) }
        if ($rd -and $rd -lt $expect) { Add-Note $sp "Read speed is lower than normal for a $sysKind (expected $expect+ MB/s). Drive may be worn, nearly full or throttling." 'warn'; $perf -= 15 }
        if ($rd) {
            $sp2 = if ($rd -ge 3000) { 100 } elseif ($rd -ge 1500) { 92 } elseif ($rd -ge 450) { 80 } elseif ($rd -ge 250) { 62 } elseif ($rd -ge 100) { 40 } else { 25 }
            $perf = [math]::Round(($perf + $sp2) / 2)
        }
    }
    else { Add-Row $sp 'Speed Test' 'Not run (tick "Disk speed test" and run again)' }
    if ($script:Bench -and $script:Bench.DiskScore -gt 0) { Add-Row $sp 'Benchmark (WinSAT)' ("{0} / 9.9" -f $script:Bench.DiskScore) }
    $sp.Score = Clamp $perf
}

function Check-Battery {
    $s = New-Section 'Battery' 'Health' 25
    $wb = @(Get-CimInstance Win32_Battery)
    if ($wb.Count -eq 0) {
        if ($script:IsLaptop) {
            Add-Row $s 'Battery' 'NOT DETECTED' 'bad'
            Add-Note $s 'This is a laptop but no battery was detected. The battery may be dead, disconnected or removed.' 'bad'
            $s.Score = 0
        }
        else { Add-Row $s 'Battery' 'No battery - desktop PC (not scored)' }
        $script:Quick['Battery'] = 'No battery'
        return
    }

    $bats = @()
    $xml = Join-Path $env:TEMP 'pchc_battery.xml'
    Remove-Item $xml -Force
    & "$env:windir\System32\powercfg.exe" /batteryreport /xml /output "$xml" | Out-Null
    if (Test-Path $xml) {
        [xml]$x = Get-Content $xml -Raw
        foreach ($b in @($x.BatteryReport.Batteries.Battery | Where-Object { $_ })) {
            $bats += [pscustomobject]@{ Name = ("{0} {1}" -f $b.Manufacturer, $b.Id).Trim(); Chem = [string]$b.Chemistry
                Design = [double]$b.DesignCapacity; Full = [double]$b.FullChargeCapacity; Cycles = $b.CycleCount }
        }
        Remove-Item $xml -Force
    }
    if ($bats.Count -eq 0) {
        $ds = @(Get-CimInstance -Namespace root/wmi -ClassName BatteryStaticData)
        $fc = @(Get-CimInstance -Namespace root/wmi -ClassName BatteryFullChargedCapacity)
        $cc = @(Get-CimInstance -Namespace root/wmi -ClassName BatteryCycleCount)
        for ($i = 0; $i -lt $fc.Count; $i++) {
            $bats += [pscustomobject]@{ Name = "Battery $($i + 1)"; Chem = ''; Design = [double]$ds[$i].DesignedCapacity; Full = [double]$fc[$i].FullChargedCapacity; Cycles = $cc[$i].CycleCount }
        }
    }

    $scores = @(); $qh = @()
    foreach ($b in $bats) {
        $nm = $b.Name; if (-not $nm) { $nm = 'Battery' }
        Add-Row $s $nm $b.Chem 'head'
        if ($b.Design -gt 0 -and $b.Full -gt 0) {
            $hp = [math]::Round($b.Full / $b.Design * 100, 1)
            Add-Row $s '  Battery Health' "$hp %" $(if ($hp -ge 80) { 'ok' } elseif ($hp -ge 60) { 'warn' } else { 'bad' })
            Add-Row $s '  Reading' 'Real - measured by the battery chip' 'ok'
            Add-Row $s '  Original (Design) Capacity' ('{0:N0} mWh' -f $b.Design)
            Add-Row $s '  Current Full Charge Capacity' ('{0:N0} mWh' -f $b.Full)
            $scores += [math]::Min(100, $hp)
            $qh += "$hp% health"
            if ($hp -lt 60) { Add-Note $s "Battery is badly worn ($hp% health). Backup time will be short - budget for a new battery." 'bad' }
            elseif ($hp -lt 80) { Add-Note $s "Battery has noticeable wear ($hp% health). Backup time is reduced." 'warn' }
        }
        else { Add-Row $s '  Battery Health' 'Could not be read' 'warn' }
        $cy = [int]$b.Cycles
        if ($cy -gt 0) {
            Add-Row $s '  Charge Cycles' $cy $(if ($cy -gt 1000) { 'bad' } elseif ($cy -gt 500) { 'warn' } else { 'ok' })
            if ($cy -gt 1000) { Add-Note $s "Battery has $cy charge cycles - most laptop batteries are rated for 300-1000." 'warn' }
        }
        else { Add-Row $s '  Charge Cycles' 'Not reported by this battery' }
    }

    $w0 = $wb[0]
    Add-Row $s 'Current Charge' "$($w0.EstimatedChargeRemaining) %"
    $stMap = @{ 1 = 'On battery (discharging)'; 2 = 'Plugged in (AC power)'; 3 = 'Fully charged'; 4 = 'Low'; 5 = 'Critical'; 6 = 'Charging'; 7 = 'Charging (high)'; 8 = 'Charging (low)'; 9 = 'Charging (critical)'; 11 = 'Partially charged' }
    $pst = $stMap[[int]$w0.BatteryStatus]; if (-not $pst) { $pst = "Status $($w0.BatteryStatus)" }
    Add-Row $s 'Power Status' $pst
    if ([int]$w0.BatteryStatus -eq 1 -and $w0.EstimatedRunTime -and $w0.EstimatedRunTime -lt 71582788) {
        Add-Row $s 'Estimated Time Left' ("{0}h {1}m" -f [math]::Floor($w0.EstimatedRunTime / 60), ($w0.EstimatedRunTime % 60))
    }
    if ([int]$w0.BatteryStatus -ne 1) { Add-Note $s 'Tip: unplug the charger - the laptop must stay ON and show "discharging". Then plug it back in and check the % goes up.' 'info' }
    if ($scores.Count) { $s.Score = Clamp (($scores | Measure-Object -Average).Average) }
    $script:Quick['Battery'] = if ($qh.Count) { $qh -join ', ' } else { 'Health unknown' }
}

function Check-Display {
    $s = New-Section 'Display' 'Info'
    $ids = @(Get-CimInstance -Namespace root/wmi -ClassName WmiMonitorID)
    $prm = @(Get-CimInstance -Namespace root/wmi -ClassName WmiMonitorBasicDisplayParams)
    foreach ($p in $prm) {
        $id = $ids | Where-Object { $_.InstanceName -eq $p.InstanceName } | Select-Object -First 1
        $nm = ''; $mf = ''
        if ($id) {
            $nm = (($id.UserFriendlyName | Where-Object { $_ -ne 0 } | ForEach-Object { [char]$_ }) -join '').Trim()
            $mf = (($id.ManufacturerName | Where-Object { $_ -ne 0 } | ForEach-Object { [char]$_ }) -join '').Trim()
        }
        if (-not $nm) { $nm = 'Built-in / generic panel' }
        $size = ''
        if ($p.MaxHorizontalImageSize -gt 0) {
            $diag = [math]::Sqrt([math]::Pow($p.MaxHorizontalImageSize, 2) + [math]::Pow($p.MaxVerticalImageSize, 2)) / 2.54
            $size = '{0:N1} inch' -f $diag
        }
        $label = ("$mf $nm").Trim()
        Add-Row $s $label $size 'head'
    }
    Add-Row $s 'Screens Connected' ([System.Windows.Forms.Screen]::AllScreens.Count)
    Add-Row $s 'Resolution' 'See "Current Mode" in the Graphics section'
    $br = Get-CimInstance -Namespace root/wmi -ClassName WmiMonitorBrightness | Select-Object -First 1
    if ($br) { Add-Row $s 'Brightness' "$($br.CurrentBrightness) %" }
    $touch = @(Get-PnpDevice -PresentOnly | Where-Object { $_.FriendlyName -match 'touch screen' })
    Add-Row $s 'Touch Screen' $(if ($touch.Count) { 'Yes' } else { 'No' })
    Add-Note $s 'Use "Screen / Dead Pixel Test" on the left to check for dead pixels, backlight bleed and spots.' 'info'
}

function Check-Devices {
    $s = New-Section 'Devices & Drivers' 'Health' 10
    $pnp = @(Get-PnpDevice -PresentOnly)
    $na = @(Get-NetAdapter -Physical)
    $sc = 100

    function Found($label, $items, $missStatus, $penalty) {
        if ($items.Count -gt 0) { Add-Row $s $label ($items[0]) 'ok' }
        else { Add-Row $s $label 'Not found' $missStatus; if ($missStatus -ne 'info') { $script:devPenalty += $penalty } }
    }
    $script:devPenalty = 0
    $wifi = @($na | Where-Object { $_.InterfaceDescription -match 'Wi-?Fi|Wireless|WLAN|802\.11' -or [string]$_.PhysicalMediaType -match '802\.11' } | ForEach-Object { $_.InterfaceDescription })
    $eth  = @($na | Where-Object { [string]$_.PhysicalMediaType -eq '802.3' } | ForEach-Object { $_.InterfaceDescription })
    $bt   = @($pnp | Where-Object { $_.Class -eq 'Bluetooth' -and $_.FriendlyName -match 'Bluetooth|Wireless|Radio|Adapter' } | ForEach-Object { $_.FriendlyName })
    $cam  = @($pnp | Where-Object { ($_.Class -eq 'Camera' -or $_.Class -eq 'Image') -and $_.FriendlyName -notmatch 'scan|print' } | ForEach-Object { $_.FriendlyName })
    $spk  = @($pnp | Where-Object { $_.Class -eq 'AudioEndpoint' -and $_.FriendlyName -match 'Speaker|Headphone|Realtek|Audio' -and $_.FriendlyName -notmatch 'Microphone|Mic' } | ForEach-Object { $_.FriendlyName })
    $mic  = @($pnp | Where-Object { $_.Class -eq 'AudioEndpoint' -and $_.FriendlyName -match 'Microphone|Mic' } | ForEach-Object { $_.FriendlyName })
    $tpad = @($pnp | Where-Object { $_.FriendlyName -match 'touch ?pad|Precision Touch|Synaptics|ELAN|Alps' } | ForEach-Object { $_.FriendlyName })
    $fp   = @($pnp | Where-Object { $_.Class -eq 'Biometric' } | ForEach-Object { $_.FriendlyName })
    $card = @($pnp | Where-Object { $_.FriendlyName -match 'card reader|SD Host|SDXC|SDHC' } | ForEach-Object { $_.FriendlyName })
    if (-not $spk.Count) { $spk = @(Get-CimInstance Win32_SoundDevice | ForEach-Object { $_.Name }) }

    $L = $script:IsLaptop
    Found 'Wi-Fi'       $wifi $(if ($L) { 'bad' } else { 'info' }) 25
    Found 'Bluetooth'   $bt   $(if ($L) { 'warn' } else { 'info' }) 5
    Found 'Ethernet'    $eth  'info' 0
    Found 'Webcam'      $cam  $(if ($L) { 'warn' } else { 'info' }) 10
    Found 'Speakers / Audio' $spk 'bad' 15
    Found 'Microphone'  $mic  $(if ($L) { 'warn' } else { 'info' }) 5
    if ($L) { Found 'Touchpad' $tpad 'info' 0 }
    Found 'Fingerprint Reader' $fp 'info' 0
    Found 'SD Card Reader' $card 'info' 0
    $sc -= $script:devPenalty
    if ($L -and -not $wifi.Count) { Add-Note $s 'No Wi-Fi adapter found on a laptop. The Wi-Fi card or its driver is missing/faulty.' 'bad' }

    $codes = @{ 1 = 'not configured'; 3 = 'driver corrupted / low memory'; 10 = 'cannot start'; 12 = 'resource conflict'; 14 = 'needs restart'; 18 = 'reinstall driver'; 19 = 'registry problem'; 22 = 'DISABLED'; 24 = 'not present / not working'; 28 = 'DRIVER NOT INSTALLED'; 31 = 'not working properly'; 39 = 'driver corrupted or missing'; 43 = 'STOPPED - reported a problem'; 45 = 'not connected'; 52 = 'unsigned driver' }
    $prob = @($pnp | Where-Object { $_.ConfigManagerErrorCode -and $_.ConfigManagerErrorCode -ne 0 -and $_.ConfigManagerErrorCode -ne 45 })
    if ($prob.Count -eq 0) { Add-Row $s 'Problem Devices' 'None - all drivers OK' 'ok' }
    else {
        Add-Row $s 'Problem Devices' ("{0} found (see Device Manager)" -f $prob.Count) 'head'
        foreach ($p in $prob) {
            $c = [int]$p.ConfigManagerErrorCode
            $m = $codes[$c]; if (-not $m) { $m = 'error' }
            $nm = $p.FriendlyName; if (-not $nm) { $nm = $p.InstanceId }
            if ($c -eq 22) { Add-Row $s '  Disabled' "$nm" 'warn'; $sc -= 3 }
            else { Add-Row $s ("  Code {0}" -f $c) "$nm - $m" 'bad'; $sc -= 15 }
        }
        $bad = @($prob | Where-Object { $_.ConfigManagerErrorCode -ne 22 }).Count
        if ($bad -gt 0) { Add-Note $s "$bad device(s) have driver/hardware errors. Install drivers and re-check; if the error stays, the part may be faulty." 'bad' }
    }
    $s.Score = Clamp $sc
}

function Check-Stability {
    $s = New-Section 'System Stability' 'Health' 20
    $since = (Get-Date).AddDays(-30)
    Add-Row $s 'Period' 'Last 30 days'
    function CountEv($h) { @(Get-WinEvent -FilterHashtable $h -ErrorAction SilentlyContinue).Count }

    $shut = CountEv @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-Kernel-Power'; Id = 41; StartTime = $since }
    $bsod = CountEv @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-WER-SystemErrorReporting'; Id = 1001; StartTime = $since }
    $whea = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-WHEA-Logger'; StartTime = $since } -ErrorAction SilentlyContinue)
    $wheaErr = @($whea | Where-Object { $_.Level -le 2 }).Count
    $wheaWarn = $whea.Count - $wheaErr
    $badBlock = CountEv @{ LogName = 'System'; ProviderName = 'disk'; Id = 7; StartTime = $since }
    $ioWarn = CountEv @{ LogName = 'System'; ProviderName = 'disk'; Id = 51, 153; StartTime = $since }
    $ntfs = CountEv @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-Ntfs'; Id = 55; StartTime = $since }

    Add-Row $s 'Unexpected Shutdowns / Power Loss' $shut $(if ($shut -ge 5) { 'bad' } elseif ($shut -gt 0) { 'warn' } else { 'ok' })
    Add-Row $s 'Blue Screen Crashes (BSOD)' $bsod $(if ($bsod -ge 2) { 'bad' } elseif ($bsod -gt 0) { 'warn' } else { 'ok' })
    Add-Row $s 'Hardware Errors (WHEA)' ("{0} errors, {1} corrected warnings" -f $wheaErr, $wheaWarn) $(if ($wheaErr -gt 0) { 'bad' } elseif ($wheaWarn -gt 20) { 'warn' } else { 'ok' })
    Add-Row $s 'Disk Bad Blocks' $badBlock $(if ($badBlock -gt 0) { 'bad' } else { 'ok' })
    Add-Row $s 'Disk I/O Warnings' $ioWarn $(if ($ioWarn -gt 5) { 'warn' } else { 'ok' })
    Add-Row $s 'File System Corruption' $ntfs $(if ($ntfs -gt 0) { 'warn' } else { 'ok' })

    $md = Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-MemoryDiagnostics-Results' } -MaxEvents 1 -ErrorAction SilentlyContinue
    $mdPenalty = 0
    if ($md) {
        if ($md.Id -eq 1202) { Add-Row $s 'Last Memory (RAM) Test' ("ERRORS FOUND ({0:dd MMM yyyy})" -f $md.TimeCreated) 'bad'; Add-Note $s 'Windows Memory Diagnostic found RAM errors. A RAM stick is faulty.' 'bad'; $mdPenalty = 40 }
        else { Add-Row $s 'Last Memory (RAM) Test' ("Passed ({0:dd MMM yyyy})" -f $md.TimeCreated) 'ok' }
    }
    else { Add-Row $s 'Last Memory (RAM) Test' 'Never run (use "RAM Test" button - needs restart)' }

    $rel = Get-CimInstance Win32_ReliabilityStabilityMetrics | Sort-Object TimeGenerated -Descending | Select-Object -First 1
    if ($rel) {
        $ri = [math]::Round([double]$rel.SystemStabilityIndex, 1)
        Add-Row $s 'Windows Reliability Index' "$ri / 10" $(if ($ri -ge 7) { 'ok' } elseif ($ri -ge 4) { 'warn' } else { 'bad' })
    }

    $sc = 100 - [math]::Min(30, 6 * $shut) - [math]::Min(45, 15 * $bsod) - [math]::Min(30, 10 * $wheaErr) - [math]::Min(40, 20 * $badBlock) - [math]::Min(10, 2 * $ioWarn) - [math]::Min(20, 10 * $ntfs) - $mdPenalty
    if ($bsod -gt 0) { Add-Note $s "$bsod blue-screen crash(es) in the last 30 days. Can be drivers, RAM, disk or overheating." $(if ($bsod -ge 2) { 'bad' } else { 'warn' }) }
    if ($wheaErr -gt 0) { Add-Note $s "$wheaErr hardware error(s) logged by the CPU/chipset (WHEA). This points to a hardware fault." 'bad' }
    if ($badBlock -gt 0) { Add-Note $s 'Disk bad-block errors found. The drive has damaged areas.' 'bad' }
    if ($shut -gt 0) { Add-Note $s "$shut unexpected shutdown(s). Can be a power cut / holding power button, or a battery/overheating problem." 'warn' }
    if ($null -ne $script:InstallAgeDays -and $script:InstallAgeDays -lt 30) {
        Add-Note $s ("Windows was installed only {0} days ago, so there is little history. Normal for a reset/refurbished PC, but past problems may be hidden." -f $script:InstallAgeDays) 'info'
    }
    $s.Score = Clamp $sc
}

function Check-Security {
    $s = New-Section 'Security & Ownership' 'Health' 10
    $sc = 0

    $lic = @(Get-CimInstance SoftwareLicensingProduct -Filter "ApplicationID='55c92734-d682-4d71-983e-d6ec3f16059f' AND PartialProductKey IS NOT NULL")
    $act = $lic | Where-Object { $_.LicenseStatus -eq 1 } | Select-Object -First 1
    $lsMap = @{ 0 = 'Not activated'; 1 = 'Activated'; 2 = 'Grace period'; 3 = 'Grace period'; 4 = 'NOT GENUINE'; 5 = 'Not activated (notification)'; 6 = 'Extended grace' }
    if ($act) { Add-Row $s 'Windows Activation' "Activated ($($act.Name -replace '^Windows\(R\), ', ''))" 'ok'; $sc += 30 }
    elseif ($lic.Count) { Add-Row $s 'Windows Activation' $lsMap[[int]$lic[0].LicenseStatus] 'bad'; Add-Note $s 'Windows is NOT activated. Ask the seller for a genuine licence.' 'bad' }
    else { Add-Row $s 'Windows Activation' 'Unknown' 'warn'; $sc += 15 }
    $oem = (Get-CimInstance SoftwareLicensingService).OA3xOriginalProductKey
    Add-Row $s 'Original Licence in BIOS' $(if ($oem) { 'Yes (OEM key embedded - Windows reinstalls activate free)' } else { 'No' })

    $tpm = Get-CimInstance -Namespace root/cimv2/Security/MicrosoftTpm -ClassName Win32_Tpm
    if ($tpm) {
        $tv = ([string]$tpm.SpecVersion -split ',')[0].Trim()
        $en = $tpm.IsEnabled_InitialValue
        Add-Row $s 'TPM Security Chip' ("Version {0}, {1}" -f $tv, $(if ($en) { 'enabled' } else { 'disabled' })) $(if ($tv -like '2*' -and $en) { 'ok' } else { 'warn' })
        if ($tv -like '2*' -and $en) { $sc += 25 } else { $sc += 10 }
    }
    elseif ($script:IsAdmin) { Add-Row $s 'TPM Security Chip' 'Not found / disabled in BIOS' 'warn'; Add-Note $s 'No TPM 2.0 detected - needed for Windows 11. It may be disabled in BIOS.' 'warn' }
    else { Add-Row $s 'TPM Security Chip' 'Needs Administrator'; $sc += 15 }

    $sbText = ''; $sbSt = 'info'
    try {
        $sb = Confirm-SecureBootUEFI -ErrorAction Stop
        if ($sb) { $sbText = 'Enabled (UEFI)'; $sbSt = 'ok'; $sc += 20 } else { $sbText = 'Off (UEFI mode)'; $sbSt = 'warn'; $sc += 10 }
    }
    catch {
        if ($_.Exception.Message -match 'not supported|platform') { $sbText = 'Not supported - Legacy BIOS mode'; $sbSt = 'warn' }
        else { $sbText = 'Unknown (needs Administrator)'; $sc += 10 }
    }
    Add-Row $s 'Secure Boot' $sbText $sbSt

    try {
        $bl = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop
        Add-Row $s 'BitLocker (drive encryption)' ("{0} - {1}" -f $bl.ProtectionStatus, $bl.VolumeStatus)
        if ([string]$bl.ProtectionStatus -eq 'On') { Add-Note $s 'BitLocker is ON. Make sure the recovery key is NOT tied to the seller''s Microsoft account (or do a full reset before buying).' 'info' }
    }
    catch { Add-Row $s 'BitLocker (drive encryption)' 'Not available / not used' }

    $cs = Get-CimInstance Win32_ComputerSystem
    $ds = [string](& "$env:windir\System32\dsregcmd.exe" /status 2>$null | Out-String)
    $aad = $ds -match 'AzureAdJoined\s*:\s*YES'
    $ent = $ds -match 'EnterpriseJoined\s*:\s*YES'
    $mdm = @(Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Enrollments' | ForEach-Object { Get-ItemProperty $_.PSPath } | Where-Object { $_.ProviderID -eq 'MS DM Server' }).Count -gt 0
    $managed = @()
    if ($cs.PartOfDomain) { $managed += "Domain: $($cs.Domain)" }
    if ($aad) { $managed += 'Azure AD (company account)' }
    if ($ent) { $managed += 'Enterprise joined' }
    if ($mdm) { $managed += 'MDM / Intune managed' }
    if ($managed.Count) {
        Add-Row $s 'Company / School Management' ($managed -join ', ') 'bad'
        Add-Note $s 'This PC is managed by a company or school. After a reset it may lock itself to that organisation (Autopilot / MDM). Only buy if the seller proves it was released.' 'bad'
    }
    else { Add-Row $s 'Company / School Management' 'None - personal device' 'ok'; $sc += 25 }

    $av = @(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct | ForEach-Object { $_.displayName })
    if ($av.Count) { Add-Row $s 'Antivirus' ($av -join ', ') }

    $osCap = [string](Get-CimInstance Win32_OperatingSystem).Caption
    if ($osCap -match 'Windows 10') {
        $ok11 = ($tpm -and ([string]$tpm.SpecVersion).StartsWith('2')) -and ($sbText -notmatch 'Legacy') -and ($null -eq $script:CpuGen -or $script:CpuGen -ge 8)
        Add-Row $s 'Windows 11 Upgrade' $(if ($ok11) { 'Likely supported' } else { 'Probably NOT supported' }) $(if ($ok11) { 'ok' } else { 'warn' })
        if (-not $ok11) { Add-Note $s 'Windows 10 support has ended (Oct 2025) and this PC may not meet Windows 11 requirements.' 'warn' }
    }
    $s.Score = Clamp $sc
}


# =================================================================== MAIN

Emit-Log '#' ("Scan started on {0}" -f $env:COMPUTERNAME)
if ($script:IsAdmin) {
    Set-Status 'Disk speed' 3
    Run-DiskSpeed
    if ($script:DiskSpeed) { Emit-Log '+' ("Disk read {0} MB/s  ::  write {1} MB/s" -f $script:DiskSpeed.Read, $script:DiskSpeed.Write) }
}
else { Emit-Log '~' 'Not Administrator - disk speed test skipped.' }

$steps = @(
    @('System', { Check-System }),
    @('Processor', { Check-CPU }),
    @('Memory', { Check-RAM }),
    @('Graphics', { Check-GPU }),
    @('Storage', { Check-Storage }),
    @('Battery', { Check-Battery }),
    @('Display', { Check-Display }),
    @('Devices', { Check-Devices }),
    @('Stability', { Check-Stability }),
    @('Security', { Check-Security })
)
$i = 0
foreach ($st in $steps) {
    $i++
    $before = $script:Sections.Count
    Set-Status $st[0] ([int](12 + 86 * ($i - 1) / $steps.Count))
    try { $null = & $st[1] }
    catch { $e = New-Section $st[0] 'Info'; Add-Note $e ("This check failed: " + $_.Exception.Message) 'warn' }
    for ($j = $before; $j -lt $script:Sections.Count; $j++) {
        $sec = $script:Sections[$j]
        $name = $sec.Title.ToUpper()
        $dots = '.' * [int][math]::Max(3, 34 - $name.Length)
        if ($null -ne $sec.Score) {
            $k = if ($sec.Score -ge 70) { '+' } elseif ($sec.Score -ge 50) { '~' } else { '!' }
            Emit-Log $k ("{0} {1} {2,3}/100  {3}" -f $name, $dots, $sec.Score, (Grade $sec.Score).ToUpper())
        }
        else { Emit-Log '+' ("{0} {1} OK" -f $name, $dots) }
        foreach ($n in $sec.Notes) {
            if ($n.S -eq 'bad') { Emit-Log '!' ('   ' + $n.T) }
            elseif ($n.S -eq 'warn') { Emit-Log '~' ('   ' + $n.T) }
        }
    }
}
Set-Status 'Finalizing' 99
$res = [ordered]@{
    version  = '1.0'
    admin    = [bool]$script:IsAdmin
    host     = $env:COMPUTERNAME
    time     = (Get-Date -Format 'dd MMM yyyy, HH:mm')
    quick    = $script:Quick
    sections = @($script:Sections)
}
Out-Line ('R|' + ($res | ConvertTo-Json -Depth 8 -Compress))
