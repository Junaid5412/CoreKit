# CoreKit :: Activity Log - Windows audit collector (run by CoreKit.exe)
# Reads only records Windows already keeps about this PC, so you can see who used
# it and when. Output protocol (one per line):  P|pct|label   L|kind|text   R|<json>
#
# Event object: { k=type, t=unixSeconds, ti=title, d=detail, s=severity, u=user, r=restoreToken }
# types: signin signin-fail unlock lock signout boot shutdown shutdown-bad sleep wake
#        program file-new file-mod file-del usb

$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference    = 'SilentlyContinue'
try { [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false) } catch {}

$script:Days = 7
for ($i = 0; $i -lt $args.Count; $i++) { if ($args[$i] -eq '-days' -and $i + 1 -lt $args.Count) { [void][int]::TryParse($args[$i + 1], [ref]$script:Days) } }
if ($script:Days -lt 1) { $script:Days = 1 }
if ($script:Days -gt 90) { $script:Days = 90 }
$script:Since = (Get-Date).AddDays(-$script:Days)

$script:IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$script:Events = New-Object System.Collections.ArrayList
$script:LastPct = 0

function Out-Line([string]$s) { [Console]::Out.WriteLine($s); [Console]::Out.Flush() }
function Emit-Log([string]$Kind, [string]$Text) { Out-Line ("L|{0}|{1}" -f $Kind, ($Text -replace '[\r\n]+', ' ')) }
function Set-Status([string]$Text, [int]$Pct = -1) { if ($Pct -ge 0) { $script:LastPct = $Pct }; Out-Line ("P|{0}|{1}" -f $script:LastPct, $Text) }
function U([datetime]$d) { [int64]([math]::Floor(($d.ToUniversalTime() - [datetime]'1970-01-01T00:00:00Z').TotalSeconds)) }

function Add-Ev([string]$Kind, [datetime]$When, [string]$Title, [string]$Detail, [string]$Sev = 'info', [string]$User = '', [string]$Restore = '') {
    if ($When -lt $script:Since) { return }
    [void]$script:Events.Add([pscustomobject]@{ k = $Kind; t = (U $When); ti = $Title; d = $Detail; s = $Sev; u = $User; r = $Restore })
}

# ---------------------------------------------------------------- sign-ins, lock / unlock (Security log, needs admin + audit)
function Collect-Logons {
    Set-Status 'Reading sign-in history' 12
    if (-not $script:IsAdmin) { Emit-Log '!' 'Sign-in history needs administrator rights'; return }
    $ids = 4624, 4625, 4634, 4647, 4800, 4801
    $ev = @()
    try { $ev = Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = $ids; StartTime = $script:Since } -ErrorAction Stop } catch { Emit-Log '!' 'Security log unavailable (sign-in auditing may be off)'; return }
    $seen = 0
    foreach ($e in $ev) {
        if ($seen -ge 2000) { break }
        $seen++
        $x = [xml]$e.ToXml()
        $d = @{}
        foreach ($n in $x.Event.EventData.Data) { $d[$n.Name] = $n.'#text' }
        $user = $d['TargetUserName']
        $type = $d['LogonType']
        switch ([int]$e.Id) {
            4624 {
                if ($user -in @('SYSTEM', 'ANONYMOUS LOGON', 'DWM-1', 'DWM-2', 'UMFD-0', 'UMFD-1', 'LOCAL SERVICE', 'NETWORK SERVICE') -or $user -like '*$') { continue }
                if ($type -in @('2', '7', '10', '11')) {
                    $how = @{ '2' = 'Signed in at the keyboard'; '7' = 'Unlocked the screen'; '10' = 'Remote Desktop sign-in'; '11' = 'Signed in (cached)' }[$type]
                    $k = if ($type -eq '7') { 'unlock' } else { 'signin' }
                    $s = if ($type -eq '10') { 'warn' } else { 'info' }
                    Add-Ev $k $e.TimeCreated $how ("User " + $user) $s $user
                }
            }
            4625 { Add-Ev 'signin-fail' $e.TimeCreated 'Failed sign-in (wrong password or account)' ("Tried user " + $user) 'bad' $user }
            4647 { Add-Ev 'signout' $e.TimeCreated 'Signed out' ("User " + $user) 'info' $user }
            4634 { if ($type -in @('2', '10', '11')) { Add-Ev 'signout' $e.TimeCreated 'Session ended' ("User " + $user) 'info' $user } }
            4800 { Add-Ev 'lock' $e.TimeCreated 'Locked the screen' ("User " + $user) 'info' $user }
            4801 { Add-Ev 'unlock' $e.TimeCreated 'Unlocked the screen' ("User " + $user) 'info' $user }
        }
    }
}

# ---------------------------------------------------------------- power: boot / shutdown / sleep / wake (System log)
function Collect-Power {
    Set-Status 'Reading power history' 30
    $ev = @()
    try { $ev = Get-WinEvent -FilterHashtable @{ LogName = 'System'; Id = 6005, 6006, 6008, 1074, 1, 42, 107; StartTime = $script:Since } -ErrorAction Stop } catch { return }
    foreach ($e in $ev) {
        switch ([int]$e.Id) {
            6005 { Add-Ev 'boot' $e.TimeCreated 'PC turned on' 'Windows started' 'info' }
            6006 { Add-Ev 'shutdown' $e.TimeCreated 'PC shut down' 'Windows stopped cleanly' 'info' }
            6008 { Add-Ev 'shutdown-bad' $e.TimeCreated 'Unexpected shutdown' 'Power loss or forced off' 'warn' }
            1074 { Add-Ev 'shutdown' $e.TimeCreated 'Shutdown / restart started' (($e.Message -split "`n")[0]) 'info' }
            42   { Add-Ev 'sleep' $e.TimeCreated 'Went to sleep' 'Display/standby' 'info' }
            1    { if ($e.ProviderName -like '*Power-Troubleshooter*') { Add-Ev 'wake' $e.TimeCreated 'Woke from sleep' 'Someone woke the PC' 'info' } }
            107  { Add-Ev 'wake' $e.TimeCreated 'Woke from sleep' 'Resumed' 'info' }
        }
    }
}

# ---------------------------------------------------------------- programs launched (UserAssist, no admin needed)
function Rot13([string]$s) {
    $o = New-Object System.Text.StringBuilder
    foreach ($c in $s.ToCharArray()) {
        $n = [int][char]$c
        if ($n -ge 65 -and $n -le 90) { $n = 65 + (($n - 65 + 13) % 26) }
        elseif ($n -ge 97 -and $n -le 122) { $n = 97 + (($n - 97 + 13) % 26) }
        [void]$o.Append([char]$n)
    }
    $o.ToString()
}
function Collect-Programs {
    Set-Status 'Reading programs that were run' 48
    $base = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist'
    $guids = Get-ChildItem $base
    $found = New-Object System.Collections.ArrayList
    foreach ($g in $guids) {
        $count = Join-Path $g.PSPath 'Count'
        $k = Get-Item $count
        if (-not $k) { continue }
        foreach ($name in $k.GetValueNames()) {
            $path = Rot13 $name
            if ($path -notmatch '\.exe') { continue }
            if ($path -like 'Microsoft.Windows.*' -or $path -like '*UEME_*') { continue }
            $data = $k.GetValue($name)
            if (-not $data -or $data.Length -lt 68) { continue }
            try {
                $ft = [BitConverter]::ToInt64($data, 60)
                if ($ft -le 0) { continue }
                $when = [datetime]::FromFileTime($ft)
            } catch { continue }
            if ($when -lt $script:Since) { continue }
            $runs = [BitConverter]::ToInt32($data, 4)
            [void]$found.Add([pscustomobject]@{ When = $when; Path = $path; Runs = $runs })
        }
    }
    foreach ($p in ($found | Sort-Object When -Descending | Select-Object -First 600)) {
        Add-Ev 'program' $p.When (Split-Path $p.Path -Leaf) ($p.Path + '  -  run ' + $p.Runs + ' time(s) in total') 'info'
    }
}

# ---------------------------------------------------------------- recently opened documents (Recent shortcuts)
function Collect-Recent {
    Set-Status 'Reading recently opened files' 62
    $recent = [Environment]::GetFolderPath('Recent')
    if (-not (Test-Path $recent)) { return }
    $sh = New-Object -ComObject WScript.Shell
    foreach ($lnk in (Get-ChildItem $recent -Filter *.lnk | Where-Object { $_.LastWriteTime -ge $script:Since } | Sort-Object LastWriteTime -Descending | Select-Object -First 500)) {
        $target = ''
        try { $target = $sh.CreateShortcut($lnk.FullName).TargetPath } catch {}
        $name = [IO.Path]::GetFileNameWithoutExtension($lnk.Name)
        Add-Ev 'file-open' $lnk.LastWriteTime ('Opened: ' + $name) ($target) 'info'
    }
}

# ---------------------------------------------------------------- new / changed files in the usual folders
function Collect-Files {
    Set-Status 'Scanning your folders for changes' 74
    $roots = @('Desktop', 'MyDocuments', 'MyPictures') | ForEach-Object { [Environment]::GetFolderPath($_) }
    $roots += (Join-Path $env:USERPROFILE 'Downloads')
    $all = New-Object System.Collections.ArrayList
    foreach ($root in ($roots | Select-Object -Unique)) {
        if (-not $root -or -not (Test-Path $root)) { continue }
        foreach ($f in (Get-ChildItem -LiteralPath $root -Recurse -File -Depth 3 -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -ge $script:Since -and $_.Name -notlike '~$*' -and $_.Name -ne 'desktop.ini' })) { [void]$all.Add($f) }
    }
    foreach ($f in ($all | Sort-Object LastWriteTime -Descending | Select-Object -First 800)) {
        $new = $f.CreationTime -ge $script:Since
        Add-Ev ($(if ($new) { 'file-new' } else { 'file-mod' })) $f.LastWriteTime ($(if ($new) { 'Created: ' } else { 'Changed: ' }) + $f.Name) $f.FullName 'info'
    }
}

# ---------------------------------------------------------------- deleted files (Recycle Bin) - with restore token
function Collect-Deleted {
    Set-Status 'Reading the Recycle Bin' 86
    $del = New-Object System.Collections.ArrayList
    foreach ($d in [IO.DriveInfo]::GetDrives()) {
        if (-not $d.IsReady) { continue }
        $rb = Join-Path $d.RootDirectory.FullName '$Recycle.Bin'
        if (-not (Test-Path $rb)) { continue }
        foreach ($sidDir in (Get-ChildItem -LiteralPath $rb -Directory -Force -ErrorAction SilentlyContinue)) {
            foreach ($meta in (Get-ChildItem -LiteralPath $sidDir.FullName -Filter '$I*' -File -Force -ErrorAction SilentlyContinue)) {
                try {
                    $bytes = [IO.File]::ReadAllBytes($meta.FullName)
                    if ($bytes.Length -lt 24) { continue }
                    $ver = [BitConverter]::ToInt64($bytes, 0)
                    $ft = [BitConverter]::ToInt64($bytes, 16)
                    $when = [datetime]::FromFileTime($ft)
                    if ($when -lt $script:Since) { continue }
                    if ($ver -ge 2) {
                        $len = [BitConverter]::ToInt32($bytes, 24)
                        $orig = [Text.Encoding]::Unicode.GetString($bytes, 28, ($len - 1) * 2)
                    } else {
                        $orig = [Text.Encoding]::Unicode.GetString($bytes, 24, 520).Trim([char]0)
                    }
                    $token = $d.Name.Substring(0, 1) + '|' + $sidDir.Name + '|' + $meta.Name
                    [void]$del.Add([pscustomobject]@{ When = $when; Orig = $orig; Token = $token })
                } catch {}
            }
        }
    }
    foreach ($x in ($del | Sort-Object When -Descending | Select-Object -First 600)) {
        Add-Ev 'file-del' $x.When ('Deleted: ' + (Split-Path $x.Orig -Leaf)) $x.Orig 'warn' '' $x.Token
    }
}

# ---------------------------------------------------------------- USB storage plugged in (System log, best effort)
function Collect-Usb {
    Set-Status 'Reading USB device history' 94
    $ev = @()
    try { $ev = Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-Partition/Diagnostic'; Id = 1006; StartTime = $script:Since } -ErrorAction Stop } catch {}
    $n = 0
    foreach ($e in $ev) {
        if ($n -ge 80) { break }
        $x = [xml]$e.ToXml(); $d = @{}
        foreach ($nn in $x.Event.EventData.Data) { $d[$nn.Name] = $nn.'#text' }
        $model = ($d['Manufacturer'], $d['Model'] -join ' ').Trim()
        if (-not $model) { $model = 'Storage device' }
        if ([int64]$d['Capacity'] -le 0) { continue }
        $n++
        Add-Ev 'usb' $e.TimeCreated ('USB storage connected: ' + $model) ('Capacity ' + [math]::Round([int64]$d['Capacity'] / 1GB, 1) + ' GB') 'warn'
    }
}

# ---------------------------------------------------------------- run
Emit-Log '*' ("Collecting the last " + $script:Days + " day(s) of activity")
Collect-Logons
Collect-Power
Collect-Programs
Collect-Recent
Collect-Files
Collect-Deleted
Collect-Usb
Set-Status 'Sorting events' 98

$sorted = $script:Events | Sort-Object -Property t -Descending
$res = [pscustomobject]@{
    admin   = $script:IsAdmin
    days    = $script:Days
    now     = (U (Get-Date))
    user    = $env:USERNAME
    pc      = $env:COMPUTERNAME
    events  = @($sorted)
}
Emit-Log '#' ("Found " + $script:Events.Count + " events")
Out-Line ('R|' + ($res | ConvertTo-Json -Depth 6 -Compress))
