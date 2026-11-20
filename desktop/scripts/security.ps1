# CoreKit :: Security - Windows collector (run by CoreKit.exe)
# Collects raw facts only; CoreKit scores them (desktop/sec_rules.go).
# Output protocol (one per line):  P|pct|label   L|kind|text   R|<json>

$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference    = 'SilentlyContinue'
try { [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false) } catch {}

function Out-Line([string]$s) { [Console]::Out.WriteLine($s); [Console]::Out.Flush() }
function Emit-Log([string]$Kind, [string]$Text) { Out-Line ("L|{0}|{1}" -f $Kind, ($Text -replace '[\r\n]+', ' ')) }
function Set-Status([string]$Text, [int]$Pct) { Out-Line ("P|{0}|{1}" -f $Pct, $Text) }
function U($d) { if (-not $d) { return 0 }; try { [int64]([math]::Floor(([datetime]$d).ToUniversalTime().Subtract([datetime]'1970-01-01T00:00:00Z').TotalSeconds)) } catch { 0 } }
function S($v) { if ($null -eq $v) { '' } else { [string]$v } }

$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$WinDir = $env:SystemRoot
$Notes = New-Object System.Collections.ArrayList
if (-not $IsAdmin) { [void]$Notes.Add('Run CoreKit as administrator for a complete scan (other users'' programs, services and Defender settings).') }

# Extract the program path from a command line ("C:\a b\x.exe" -arg / C:\x.exe -arg / rundll32 x.dll,Entry)
function Get-Target([string]$cmd) {
    if (-not $cmd) { return '' }
    $c = [Environment]::ExpandEnvironmentVariables($cmd.Trim())
    if ($c.StartsWith('"')) { $e = $c.IndexOf('"', 1); if ($e -gt 1) { $p = $c.Substring(1, $e - 1) } else { $p = $c.Trim('"') } }
    else {
        $p = $null
        $m = [regex]::Match($c, '^(.+?\.(exe|com|bat|cmd|scr|pif|vbs|vbe|js|jse|wsf|hta|ps1|msi|dll|cpl|lnk))(\s|,|$)', 'IgnoreCase')
        if ($m.Success) { $p = $m.Groups[1].Value } else { $p = ($c -split '\s+')[0] }
    }
    if ($p -match '^\\\?\?\\') { $p = $p.Substring(4) }
    if ($p -match '^\\SystemRoot\\') { $p = Join-Path $WinDir $p.Substring(12) }
    if ($p -match '^(?i)system32\\') { $p = Join-Path $WinDir $p }
    if ($p -and -not [IO.Path]::IsPathRooted($p)) {
        foreach ($d in @("$WinDir\System32", $WinDir, "$WinDir\SysWOW64")) { $t = Join-Path $d $p; if (Test-Path -LiteralPath $t) { return $t }; if (Test-Path -LiteralPath "$t.exe") { return "$t.exe" } }
    }
    # script hosts: the real target is the script they run
    $leaf = [IO.Path]::GetFileName($p).ToLower()
    if ($leaf -in @('wscript.exe', 'cscript.exe', 'mshta.exe')) {
        $m = [regex]::Match($c, '([A-Za-z]:\\[^"]+?\.(vbs|vbe|js|jse|wsf|hta))', 'IgnoreCase')
        if ($m.Success) { return $m.Groups[1].Value }
    }
    if ($leaf -eq 'rundll32.exe') {
        $m = [regex]::Match($c, '([A-Za-z]:\\[^",]+?\.(dll|cpl|ocx|tmp|dat))', 'IgnoreCase')
        if ($m.Success) { return $m.Groups[1].Value }
    }
    return $p
}

$Paths = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
function Add-Path([string]$p) { if ($p -and $p.Length -gt 3 -and [IO.Path]::IsPathRooted($p)) { [void]$Paths.Add($p) } }

# ---------------------------------------------------------------- protection
Set-Status 'Checking Windows protection' 3
$def = [ordered]@{ present = $false; rtp = $false; av = $false; tamper = $false; sigAge = 0; passive = $false; otherAV = @(); exclPath = @(); exclProc = @(); exclExt = @(); pua = 0; netProt = 0; cfa = 0; cloud = 0; asr = @{}; readable = $false }
$st = Get-MpComputerStatus
if ($st) {
    $def.present = $true
    $def.rtp = [bool]$st.RealTimeProtectionEnabled
    $def.av = [bool]$st.AntivirusEnabled
    $def.tamper = [bool]$st.IsTamperProtected
    $def.sigAge = [int]$st.AntivirusSignatureAge
    $def.passive = ((S $st.AMRunningMode) -match 'Passive')
}
$pref = Get-MpPreference
if ($pref) {
    $def.readable = $IsAdmin -and -not (@($pref.ExclusionPath) -match '^N/A')
    $def.exclPath = @(@($pref.ExclusionPath) | Where-Object { $_ -and ($_ -notmatch '^N/A') })
    $def.exclProc = @(@($pref.ExclusionProcess) | Where-Object { $_ -and ($_ -notmatch '^N/A') })
    $def.exclExt = @(@($pref.ExclusionExtension) | Where-Object { $_ -and ($_ -notmatch '^N/A') })
    $def.pua = [int]$pref.PUAProtection
    $def.netProt = [int]$pref.EnableNetworkProtection
    $def.cfa = [int]$pref.EnableControlledFolderAccess
    $def.cloud = [int]$pref.MAPSReporting
    $ids = @($pref.AttackSurfaceReductionRules_Ids); $acts = @($pref.AttackSurfaceReductionRules_Actions)
    $map = @{}
    for ($i = 0; $i -lt $ids.Count; $i++) {
        $a = S $acts[$i]
        $name = switch ($a) { '0' { 'Disabled' } '1' { 'Enabled' } '2' { 'AuditMode' } '6' { 'Warn' } default { $a } }
        if ($ids[$i]) { $map[(S $ids[$i]).ToLower()] = $name }
    }
    $def.asr = $map
}
$av = Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct
$def.otherAV = @($av | Where-Object { $_.displayName -and $_.displayName -notmatch 'Windows Defender|Microsoft Defender' } | ForEach-Object { $_.displayName } | Select-Object -Unique)

$fw = @(Get-NetFirewallProfile | ForEach-Object { [ordered]@{ profile = (S $_.Name); enabled = ([string]$_.Enabled -eq 'True') } })
$uac = -1
$v = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name EnableLUA
if ($v) { $uac = [int]$v.EnableLUA }
$smart = 'Warn'
$p1 = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name EnableSmartScreen
if ($p1 -and [int]$p1.EnableSmartScreen -eq 0) { $smart = 'Off' } else {
    $p2 = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' -Name SmartScreenEnabled
    if ($p2 -and $p2.SmartScreenEnabled) { $smart = S $p2.SmartScreenEnabled }
}
$sac = -1
$v = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy' -Name VerifiedAndReputablePolicyState
if ($v) { $sac = [int]$v.VerifiedAndReputablePolicyState }

# ---------------------------------------------------------------- running programs
Set-Status 'Reading running programs' 10
$procs = New-Object System.Collections.ArrayList
foreach ($p in (Get-CimInstance Win32_Process)) {
    $path = S $p.ExecutablePath
    Add-Path $path
    [void]$procs.Add([ordered]@{ pid = [int]$p.ProcessId; ppid = [int]$p.ParentProcessId; name = (S $p.Name); path = $path; cmd = (S $p.CommandLine); start = (U $p.CreationDate); exists = ($path -ne '' -and (Test-Path -LiteralPath $path)) })
}
Emit-Log '+' ("{0} programs running" -f $procs.Count)

# ---------------------------------------------------------------- auto-start places
Set-Status 'Checking start-up entries' 18
$auto = New-Object System.Collections.ArrayList
function Add-Auto($kind, $where, $name, $value, $key, [bool]$hidden = $false, [string]$author = '', [bool]$off = $false, [string]$target = $null) {
    if ($null -eq $target) { $target = Get-Target $value }
    Add-Path $target
    $ex = $false; if ($target) { $ex = Test-Path -LiteralPath $target }
    [void]$auto.Add([ordered]@{ kind = $kind; where = $where; name = (S $name); value = (S $value); target = (S $target); exists = $ex; hidden = $hidden; author = $author; key = $key; off = $off })
}
function Approved([string]$hive, [string]$sub, [string]$name) {
    $k = "$hive\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\$sub"
    $v = (Get-ItemProperty -LiteralPath $k -Name $name -ErrorAction SilentlyContinue).$name
    if ($v -is [byte[]] -and $v.Length -gt 0) { return (($v[0] -band 1) -eq 0) } # 02/06 = on, 03/07 = off
    return $true
}
$hives = @(@{ h = 'HKLM:'; n = 'All users' }, @{ h = 'HKCU:'; n = 'This user' })
foreach ($sid in (Get-ChildItem 'Registry::HKEY_USERS' | Where-Object { $_.PSChildName -match '^S-1-5-21-[\d-]+$' })) {
    $u = "Registry::HKEY_USERS\$($sid.PSChildName)"
    if ($u -ne 'Registry::HKEY_USERS\' + ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value)) { $hives += @{ h = $u; n = 'User ' + $sid.PSChildName } }
}
foreach ($hv in $hives) {
    foreach ($sub in @('Run', 'RunOnce', 'Policies\Explorer\Run')) {
        foreach ($wow in @('SOFTWARE\Microsoft', 'SOFTWARE\WOW6432Node\Microsoft')) {
            $k = "$($hv.h)\$wow\Windows\CurrentVersion\$sub"
            $item = Get-Item -LiteralPath $k -ErrorAction SilentlyContinue
            if (-not $item) { continue }
            foreach ($n in $item.GetValueNames()) {
                if (-not $n) { continue }
                $val = S $item.GetValue($n)
                $apSub = 'Run'; if ($wow -match 'WOW') { $apSub = 'Run32' }
                $on = Approved $hv.h $apSub $n
                Add-Auto 'run' ("{0} · {1}" -f $hv.n, $sub) $n $val ("reg|$k|$n") $false '' (-not $on)
            }
        }
    }
}
foreach ($dir in @([Environment]::GetFolderPath('Startup'), [Environment]::GetFolderPath('CommonStartup'))) {
    if (-not $dir) { continue }
    foreach ($f in (Get-ChildItem -LiteralPath $dir -File -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne 'desktop.ini' })) {
        $val = $f.FullName; $tgt = $f.FullName
        if ($f.Extension -eq '.lnk') {
            try { $sh = (New-Object -ComObject WScript.Shell).CreateShortcut($f.FullName); $val = ($sh.TargetPath + ' ' + $sh.Arguments).Trim(); $tgt = Get-Target $val; if (-not $tgt) { $tgt = $f.FullName } } catch {}
        }
        $on = Approved 'HKCU:' 'StartupFolder' $f.Name
        Add-Auto 'startup' 'Startup folder' $f.Name $val ("file|" + $f.FullName) $false '' (-not $on) $tgt
    }
}

Set-Status 'Checking scheduled tasks' 24
foreach ($t in (Get-ScheduledTask)) {
    foreach ($a in @($t.Actions)) {
        $exe = S $a.Execute
        if (-not $exe) { continue }
        $val = ($exe + ' ' + (S $a.Arguments)).Trim()
        $tgt = Get-Target $val
        $ms = ($t.TaskPath -like '\Microsoft\*')
        if ($ms -and $tgt -like "$WinDir\*" -and $val -notmatch '(?i)-enc|downloadstring|frombase64|http') { continue }
        Add-Auto 'task' ("Task Scheduler" + $t.TaskPath) $t.TaskName $val ("task|" + $t.TaskPath + $t.TaskName) ([bool]$t.Settings.Hidden) (S $t.Author) ((S $t.State) -eq 'Disabled') $tgt
    }
}

Set-Status 'Checking services' 30
foreach ($s in (Get-CimInstance Win32_Service)) {
    $pn = S $s.PathName
    $tgt = Get-Target $pn
    $dll = ''
    if ($tgt -match '(?i)\\svchost\.exe$') {
        $dll = S (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\$($s.Name)\Parameters" -Name ServiceDll -ErrorAction SilentlyContinue).ServiceDll
        if (-not $dll) { $dll = S (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\$($s.Name)" -Name ServiceDll -ErrorAction SilentlyContinue).ServiceDll }
        $dll = [Environment]::ExpandEnvironmentVariables($dll)
        if (-not $dll -or $dll -like "$WinDir\*") { continue }
        $tgt = $dll
    } elseif ($tgt -like "$WinDir\*" -and $tgt -notlike "$WinDir\Temp\*") { continue }
    if ((S $s.StartMode) -eq 'Disabled' -and (S $s.State) -ne 'Running') { continue }
    $val = $pn; if ($dll) { $val = "$pn  (ServiceDll: $dll)" }
    Add-Auto 'service' ("Service · " + (S $s.StartMode) + " · " + (S $s.State)) (S $s.Name) $val ("svc|" + $s.Name) $false (S $s.DisplayName) ((S $s.StartMode) -eq 'Disabled') $tgt
}

Set-Status 'Checking hidden triggers (WMI, IFEO, sign-in hooks)' 36
foreach ($c in (Get-CimInstance -Namespace root/subscription -ClassName CommandLineEventConsumer)) {
    $val = (S $c.CommandLineTemplate); if (-not $val) { $val = S $c.ExecutablePath }
    Add-Auto 'wmi' 'WMI event subscription' (S $c.Name) $val ("wmi|CommandLineEventConsumer|" + $c.Name)
}
foreach ($c in (Get-CimInstance -Namespace root/subscription -ClassName ActiveScriptEventConsumer)) {
    $val = (S $c.ScriptFileName); if (-not $val) { $val = ((S $c.ScriptingEngine) + ': ' + ((S $c.ScriptText) -replace '\s+', ' ')) }
    Add-Auto 'wmi' 'WMI event subscription (script)' (S $c.Name) $val ("wmi|ActiveScriptEventConsumer|" + $c.Name) $false '' $false (S $c.ScriptFileName)
}
foreach ($base in @('HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options')) {
    foreach ($k in (Get-ChildItem -LiteralPath $base -ErrorAction SilentlyContinue)) {
        $d = S (Get-ItemProperty -LiteralPath $k.PSPath -Name Debugger -ErrorAction SilentlyContinue).Debugger
        if ($d) { Add-Auto 'ifeo' 'Image File Execution Options' $k.PSChildName $d ("ifeo|" + $k.PSPath.Replace('Microsoft.PowerShell.Core\Registry::', 'Registry::') + "|Debugger") }
    }
}
foreach ($k in (Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit' -ErrorAction SilentlyContinue)) {
    $m = S (Get-ItemProperty -LiteralPath $k.PSPath -Name MonitorProcess -ErrorAction SilentlyContinue).MonitorProcess
    if ($m) { Add-Auto 'ifeo' 'Silent process exit monitor' $k.PSChildName $m ("ifeo|" + $k.PSPath.Replace('Microsoft.PowerShell.Core\Registry::', 'Registry::') + "|MonitorProcess") }
}
$wl = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
$sh = S (Get-ItemProperty $wl -Name Shell).Shell
if ($sh -and $sh.Trim().ToLower() -notin @('explorer.exe', 'explorer.exe,')) { Add-Auto 'winlogon' 'Winlogon (all users)' 'Shell' $sh ("winlogon|$wl|Shell") }
$ui = S (Get-ItemProperty $wl -Name Userinit).Userinit
if ($ui -and ($ui.Trim().TrimEnd(',').ToLower() -ne "$($WinDir.ToLower())\system32\userinit.exe")) { Add-Auto 'winlogon' 'Winlogon (all users)' 'Userinit' $ui ("winlogon|$wl|Userinit") }
$hsh = S (Get-ItemProperty 'HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name Shell -ErrorAction SilentlyContinue).Shell
if ($hsh) { Add-Auto 'winlogon' 'Winlogon (this user)' 'Shell' $hsh ("winlogon|HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon|Shell") }
foreach ($wk in @('HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows')) {
    $ai = Get-ItemProperty $wk -ErrorAction SilentlyContinue
    if ($ai -and (S $ai.AppInit_DLLs).Trim() -and [int]$ai.LoadAppInit_DLLs -eq 1) {
        foreach ($d in ((S $ai.AppInit_DLLs) -split '[,\s]+' | Where-Object { $_ })) { Add-Auto 'appinit' 'AppInit_DLLs' ([IO.Path]::GetFileName($d)) $d ("appinit|$wk|$d") $false '' $false $d }
    }
}
$lsa = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
foreach ($vn in @('Authentication Packages', 'Notification Packages', 'Security Packages')) {
    foreach ($pkg in @($lsa.$vn)) {
        $pkg = (S $pkg).Trim('"').Trim()
        if (-not $pkg) { continue }
        $dll = Join-Path "$WinDir\System32" ($pkg + '.dll')
        if (Test-Path -LiteralPath $dll) {
            $sg = Get-AuthenticodeSignature -LiteralPath $dll
            if ($sg.Status -eq 'Valid' -and ($sg.SignerCertificate.Subject -match 'O=Microsoft Corporation')) { continue }
        }
        Add-Auto 'lsa' ("LSA · " + $vn) $pkg $dll ("lsa|$vn|$pkg") $false '' $false $dll
    }
}

# browser policies set from outside (hijackers and forced extensions)
$policies = New-Object System.Collections.ArrayList
$domain = $false; try { $domain = [bool](Get-CimInstance Win32_ComputerSystem).PartOfDomain } catch {}
foreach ($root in @('HKLM:', 'HKCU:')) {
    foreach ($b in @(@{ p = 'SOFTWARE\Policies\Google\Chrome'; n = 'Chrome' }, @{ p = 'SOFTWARE\Policies\Microsoft\Edge'; n = 'Edge' }, @{ p = 'SOFTWARE\Policies\BraveSoftware\Brave'; n = 'Brave' })) {
        $k = "$root\$($b.p)"
        $fl = Get-Item -LiteralPath "$k\ExtensionInstallForcelist" -ErrorAction SilentlyContinue
        if ($fl) { foreach ($n in $fl.GetValueNames()) { [void]$policies.Add([ordered]@{ browser = $b.n; name = 'ExtensionInstallForcelist'; value = (S $fl.GetValue($n)); key = "$k\ExtensionInstallForcelist|$n" }) } }
        $it = Get-Item -LiteralPath $k -ErrorAction SilentlyContinue
        if ($it) {
            foreach ($n in @('HomepageLocation', 'NewTabPageLocation', 'DefaultSearchProviderSearchURL', 'DefaultSearchProviderName', 'ProxyServer', 'ProxyPacUrl')) {
                $v = $it.GetValue($n)
                if ($v) { [void]$policies.Add([ordered]@{ browser = $b.n; name = $n; value = (S $v); key = $k }) }
            }
        }
    }
}
if ($domain -and $policies.Count -gt 0) { [void]$Notes.Add('This PC is managed by an organisation, so browser policies are probably set by your IT team.') }

# ---------------------------------------------------------------- Downloads (programs waiting to be opened)
Set-Status 'Checking downloaded programs' 42
$downloads = New-Object System.Collections.ArrayList
$dl = Join-Path $env:USERPROFILE 'Downloads'
try { $sf = (Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' -Name '{374DE290-123F-4565-9164-39C4925E467B}').'{374DE290-123F-4565-9164-39C4925E467B}'; if ($sf) { $dl = [Environment]::ExpandEnvironmentVariables($sf) } } catch {}
$since = (Get-Date).AddDays(-45)
$cands = Get-ChildItem -LiteralPath $dl -File -Recurse -Depth 1 -Force -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -gt $since -and $_.Extension -match '^\.(exe|scr|com|pif|msi|bat|cmd|vbs|vbe|js|jse|wsf|hta|ps1|lnk|cpl|jar)$' } | Sort-Object LastWriteTime -Descending | Select-Object -First 60
foreach ($f in $cands) { [void]$downloads.Add($f.FullName); Add-Path $f.FullName }

# ---------------------------------------------------------------- signatures and file details
Set-Status 'Verifying digital signatures' 48
$sigs = @{}
$files = @{}
$all = @($Paths)
$i = 0
foreach ($p in $all) {
    $i++
    if ($i % 25 -eq 0) { Set-Status ("Verifying digital signatures ({0}/{1})" -f $i, $all.Count) ([int](48 + 30 * $i / [math]::Max(1, $all.Count))) }
    if (-not (Test-Path -LiteralPath $p -PathType Leaf)) { continue }
    $sg = Get-AuthenticodeSignature -LiteralPath $p
    $subj = S $sg.SignerCertificate.Subject
    $cn = ''
    if ($subj -match 'CN="?([^",]+)') { $cn = $Matches[1] }
    $ms = ($sg.Status -eq 'Valid') -and (($subj -match 'O=Microsoft Corporation') -or $sg.IsOSBinary)
    $sigs[$p] = [ordered]@{ st = (S $sg.Status); signer = $cn; ms = $ms }
    $inWin = $p -like "$WinDir\*"
    if ($ms -and $inWin) { continue }
    $fi = Get-Item -LiteralPath $p -Force
    $rec = [ordered]@{ size = [int64]$fi.Length; ctime = (U $fi.CreationTime); mtime = (U $fi.LastWriteTime); hidden = [bool]($fi.Attributes -band [IO.FileAttributes]::Hidden); zone = -1; host = ''; ref = ''; sha256 = ''; desc = ''; company = ''; orig = '' }
    $z = Get-Content -LiteralPath $p -Stream Zone.Identifier -ErrorAction SilentlyContinue
    if ($z) {
        foreach ($l in $z) {
            if ($l -match '^ZoneId=(\d+)') { $rec.zone = [int]$Matches[1] }
            elseif ($l -match '^HostUrl=(.+)$') { $rec.host = $Matches[1] }
            elseif ($l -match '^ReferrerUrl=(.+)$') { $rec.ref = $Matches[1] }
        }
    }
    $vi = $fi.VersionInfo
    if ($vi) { $rec.desc = S $vi.FileDescription; $rec.company = S $vi.CompanyName; $rec.orig = S $vi.OriginalFilename }
    if (-not $ms -and $fi.Length -lt 150MB) { $rec.sha256 = (Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLower() }
    $files[$p] = $rec
}
Emit-Log '+' ("{0} files verified" -f $sigs.Count)

# ---------------------------------------------------------------- network
Set-Status 'Reading network connections' 80
$conns = @(Get-NetTCPConnection -State Established, SynSent | ForEach-Object { [ordered]@{ pid = [int]$_.OwningProcess; raddr = (S $_.RemoteAddress); rport = [int]$_.RemotePort; lport = [int]$_.LocalPort; state = (S $_.State) } })

# ---------------------------------------------------------------- Defender history
Set-Status 'Reading Windows Defender history' 84
$threats = New-Object System.Collections.ArrayList
$names = @{}
foreach ($t in (Get-MpThreat)) { $names[[string]$t.ThreatID] = @{ n = (S $t.ThreatName); sev = [int]$t.SeverityID; active = [bool]$t.IsActive } }
$statusMap = @{ 0 = 'Unknown'; 1 = 'Detected'; 2 = 'Cleaned'; 3 = 'Quarantined'; 4 = 'Removed'; 5 = 'Allowed'; 6 = 'Blocked'; 102 = 'Quarantine failed'; 103 = 'Remove failed'; 104 = 'Allow failed'; 105 = 'Abandoned'; 107 = 'Block failed' }
$cut = (Get-Date).AddDays(-60)
foreach ($d in (Get-MpThreatDetection | Where-Object { $_.InitialDetectionTime -gt $cut } | Sort-Object InitialDetectionTime -Descending | Select-Object -First 40)) {
    $n = $names[[string]$d.ThreatID]
    $res = @($d.Resources) | Where-Object { $_ -match '^(file|process):_' } | Select-Object -First 1
    $path = ''; if ($res) { $path = $res -replace '^(file|process):_', '' }
    $stt = $statusMap[[int]$d.ThreatStatusID]; if (-not $stt) { $stt = 'Status ' + $d.ThreatStatusID }
    $act = ''; if ($n -and $n.active) { $act = 'still active' }
    [void]$threats.Add([ordered]@{ name = $(if ($n) { $n.n } else { 'Threat ' + $d.ThreatID }); path = $path; t = (U $d.InitialDetectionTime); action = $act; status = $stt; sev = $(if ($n) { [string]$n.sev } else { '' }); id = [string]$d.ThreatID })
}

# ---------------------------------------------------------------- hosts file, proxy, certificates
Set-Status 'Checking hosts file, proxy and certificates' 88
$hostsBad = New-Object System.Collections.ArrayList
$hostsN = 0
$watch = '(?i)(microsoft\.com|windowsupdate|update\.microsoft|msftncsi|msftconnecttest|defender|smartscreen|avast|avg\.com|kaspersky|eset|bitdefender|malwarebytes|norton|mcafee|sophos|trendmicro|virustotal|abuse\.ch|google\.com|gmail\.com|facebook\.com|paypal\.com|apple\.com|icloud\.com|bank)'
foreach ($l in (Get-Content "$WinDir\System32\drivers\etc\hosts" -ErrorAction SilentlyContinue)) {
    $t = ($l -replace '#.*$', '').Trim()
    if (-not $t) { continue }
    $hostsN++
    $parts = $t -split '\s+'
    if ($parts.Count -lt 2) { continue }
    $ip = $parts[0]
    foreach ($h in $parts[1..($parts.Count - 1)]) {
        if ($h -match $watch -and $h -notmatch '^(localhost|localhost\.localdomain)$') {
            if ($hostsN -lt 2000 -and $hostsBad.Count -lt 30) { [void]$hostsBad.Add("$ip $h") }
        }
    }
}
if ($hostsN -gt 2000) { $hostsBad.Clear() } # a large ad-block list, not a redirect
$is = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
$proxy = [ordered]@{ on = ([int]$is.ProxyEnable -eq 1); server = (S $is.ProxyServer); pac = (S $is.AutoConfigURL) }
$knownCA = '(?i)(microsoft|digicert|globalsign|sectigo|comodo|usertrust|isrg|let.s encrypt|google trust|gts root|amazon|entrust|godaddy|starfield|baltimore|certum|buypass|ssl\.com|actalis|quovadis|identrust|thawte|verisign|geotrust|symantec|network solutions|secom|swisssign|t-telesec|telia|hongkong post|izenpe|firmaprofesional|atos|d-trust|certigna|harica|emsign|e-tugra|trustwave|xramp|affirmtrust|cfca|twca|naver|microsec|netlock|autoridad|ac raiz|staat der nederlanden|apple|cisco|vodafone|deutsche telekom|chunghwa|teliasonera|opentrust|wisekey|oiste|camerfirma|anf|accv|certsign|digital signature trust|dst root|equifax|valicert|addtrust|utn|class 3 public primary|copyright \(c\) 1997 microsoft)'
$roots = New-Object System.Collections.ArrayList
$recent = (Get-Date).AddDays(-400)
foreach ($store in @('LocalMachine', 'CurrentUser')) {
    foreach ($c in (Get-ChildItem "Cert:\$store\Root" -ErrorAction SilentlyContinue)) {
        if ($c.Subject -match $knownCA -or $c.Issuer -match $knownCA) { continue }
        if ($c.NotBefore -lt $recent) { continue }
        $cn = $c.Subject; if ($c.Subject -match 'CN=([^,]+)') { $cn = $Matches[1] }
        [void]$roots.Add([ordered]@{ subject = $cn; thumb = $c.Thumbprint; from = (U $c.NotBefore); store = $store })
    }
}

# ---------------------------------------------------------------- installed apps (for the bloatware list)
Set-Status 'Listing installed apps' 92
$appx = New-Object System.Collections.ArrayList
foreach ($a in (Get-AppxPackage)) {
    if ($a.IsFramework -or $a.IsResourcePackage -or (S $a.SignatureKind) -eq 'System') { continue }
    $pub = ''; if ((S $a.Publisher) -match 'CN=([^,]+)') { $pub = $Matches[1] }
    [void]$appx.Add([ordered]@{ name = (S $a.Name); id = (S $a.PackageFamilyName); publisher = $pub; size = 0; uninstall = (S $a.PackageFullName); removable = (-not $a.NonRemovable) })
}
$programs = New-Object System.Collections.ArrayList
$seenP = @{}
foreach ($k in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*')) {
    foreach ($e in (Get-ItemProperty $k -ErrorAction SilentlyContinue)) {
        $n = S $e.DisplayName
        if (-not $n -or [int]$e.SystemComponent -eq 1 -or $seenP[$n]) { continue }
        $seenP[$n] = $true
        $un = S $e.QuietUninstallString; if (-not $un) { $un = S $e.UninstallString }
        [void]$programs.Add([ordered]@{ name = $n; id = $e.PSChildName; publisher = (S $e.Publisher); size = ([int64]$e.EstimatedSize * 1024); uninstall = $un; removable = [bool]$un })
    }
}

Set-Status 'Packing results' 97
$os = ''
try { $o = Get-CimInstance Win32_OperatingSystem; $os = "$($o.Caption) $($o.Version)" } catch {}
$out = [ordered]@{
    admin = $IsAdmin; os = $os; host = $env:COMPUTERNAME; defender = $def; fw = $fw; uac = $uac; smartscreen = $smart; sac = $sac
    procs = $procs; sigs = $sigs; files = $files; autoruns = $auto; conns = $conns; threats = $threats
    hosts = $hostsBad; hostsN = $hostsN; proxy = $proxy; roots = $roots; policies = $policies; appx = $appx; programs = $programs
    downloads = $downloads; notes = $Notes
}
Out-Line ('R|' + ($out | ConvertTo-Json -Depth 6 -Compress))
