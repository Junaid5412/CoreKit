# CoreKit :: Security - Windows fixer (run by CoreKit.exe)
# One request (JSON file given with -req) -> one result:  R|{"ok":true,"msg":"...","undo":{...}}
# Everything removed is backed up in "undo" so CoreKit can put it back.

$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'SilentlyContinue'
try { [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false) } catch {}
function Out-Line([string]$s) { [Console]::Out.WriteLine($s); [Console]::Out.Flush() }
function Done($msg, $undo = $null) { Out-Line ('R|' + ([ordered]@{ ok = $true; msg = $msg; undo = $undo } | ConvertTo-Json -Depth 6 -Compress)); exit 0 }
function Fail($msg) { Out-Line ('R|' + ([ordered]@{ ok = $false; msg = [string]$msg } | ConvertTo-Json -Compress)); exit 0 }

$reqFile = ''
for ($i = 0; $i -lt $args.Count; $i++) { if ($args[$i] -eq '-req' -and $i + 1 -lt $args.Count) { $reqFile = $args[$i + 1] } }
if (-not $reqFile -or -not (Test-Path -LiteralPath $reqFile)) { Fail 'no request' }
$q = Get-Content -LiteralPath $reqFile -Raw -Encoding UTF8 | ConvertFrom-Json
$WinDir = $env:SystemRoot

function RegPath([string]$p) {
    # accept HKLM:\, HKCU:\, Registry::HKEY_USERS\... and Microsoft.PowerShell.Core\Registry::...
    $p = $p -replace '^Microsoft\.PowerShell\.Core\\Registry::', 'Registry::'
    if ($p -notmatch '^(HKLM:|HKCU:|Registry::)') { throw "unexpected registry path: $p" }
    if ($p -notmatch '(?i)(\\Run|\\RunOnce|Image File Execution Options|SilentProcessExit|\\Winlogon|\\Windows NT\\CurrentVersion\\Windows|\\Control\\Lsa|\\Policies\\|Internet Settings|StartupApproved)') { throw "CoreKit only changes start-up, policy and security keys" }
    return $p
}

function Backup-Value([string]$path, [string]$name) {
    $k = Get-Item -LiteralPath $path
    $kind = $k.GetValueKind($name).ToString()
    $data = $k.GetValue($name, $null, 'DoNotExpandEnvironmentNames')
    if ($data -is [byte[]]) { $data = [Convert]::ToBase64String($data); $kind = 'Binary' }
    return [ordered]@{ op = 'reg-set'; path = $path; name = $name; type = $kind; data = $data }
}

function Set-Value($u) {
    $path = RegPath $u.path
    if (-not (Test-Path -LiteralPath $path)) { New-Item -Path $path -Force | Out-Null }
    $data = $u.data
    switch ($u.type) {
        'Binary' { $data = [Convert]::FromBase64String([string]$u.data) }
        'MultiString' { $data = [string[]]@($u.data) }
        'DWord' { $data = [int]$u.data }
        'QWord' { $data = [int64]$u.data }
    }
    New-ItemProperty -LiteralPath $path -Name $u.name -PropertyType $u.type -Value $data -Force | Out-Null
}

function Approved-Key([string]$entryKey) {
    # the StartupApproved value that Task Manager uses to switch a start-up item off
    $parts = $entryKey -split '\|'
    if ($parts[0] -eq 'file') { return @{ path = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder'; name = [IO.Path]::GetFileName($parts[1]) } }
    $rp = $parts[1]
    $hive = ($rp -split '\\')[0]
    if ($rp -like 'Registry::HKEY_USERS\*') { $hive = ($rp -split '\\')[0..1] -join '\' }
    $sub = 'Run'; if ($rp -match 'WOW6432Node') { $sub = 'Run32' }
    return @{ path = "$hive\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\$sub"; name = $parts[2] }
}

try {
    switch ($q.op) {

        'autorun-remove' {
            $parts = ([string]$q.key) -split '\|'
            switch ($parts[0]) {
                'reg' {
                    $path = RegPath $parts[1]; $name = $parts[2]
                    $u = Backup-Value $path $name
                    Remove-ItemProperty -LiteralPath $path -Name $name -Force
                    Done "Removed '$name' from start-up" $u
                }
                'task' {
                    $full = $parts[1]
                    $idx = $full.LastIndexOf('\')
                    $tp = $full.Substring(0, $idx + 1); $tn = $full.Substring($idx + 1)
                    $xml = Export-ScheduledTask -TaskPath $tp -TaskName $tn
                    Unregister-ScheduledTask -TaskPath $tp -TaskName $tn -Confirm:$false
                    Done "Deleted scheduled task $tn" ([ordered]@{ op = 'task-import'; path = $tp; name = $tn; xml = $xml })
                }
                'svc' {
                    $n = $parts[1]
                    $k = "HKLM:\SYSTEM\CurrentControlSet\Services\$n"
                    $start = [int](Get-ItemProperty -LiteralPath $k -Name Start).Start
                    try { Stop-Service -Name $n -Force -ErrorAction Stop } catch {}
                    Set-ItemProperty -LiteralPath $k -Name Start -Value 4
                    Done "Stopped and disabled service $n" ([ordered]@{ op = 'svc-start'; name = $n; start = $start })
                }
                'wmi' {
                    $cls = $parts[1]; $n = $parts[2]
                    if ($cls -notin @('CommandLineEventConsumer', 'ActiveScriptEventConsumer')) { Fail 'unexpected WMI class' }
                    $c = Get-CimInstance -Namespace root/subscription -ClassName $cls | Where-Object { $_.Name -eq $n }
                    if (-not $c) { Done 'Already gone' }
                    $kept = [ordered]@{ class = $cls; name = $n; command = [string]$c.CommandLineTemplate; script = [string]$c.ScriptText; filters = @() }
                    foreach ($b in (Get-CimInstance -Namespace root/subscription -ClassName __FilterToConsumerBinding)) {
                        if ([string]$b.Consumer.Name -eq $n) {
                            $f = $b.Filter
                            $kept.filters += [ordered]@{ name = [string]$f.Name; query = [string](Get-CimInstance -Namespace root/subscription -ClassName __EventFilter | Where-Object { $_.Name -eq $f.Name }).Query }
                            $b | Remove-CimInstance
                            Get-CimInstance -Namespace root/subscription -ClassName __EventFilter | Where-Object { $_.Name -eq $f.Name } | Remove-CimInstance
                        }
                    }
                    $c | Remove-CimInstance
                    Done "Removed the WMI trigger $n" ([ordered]@{ op = 'note'; kept = $kept })
                }
                { $_ -in @('ifeo') } {
                    $path = RegPath $parts[1]; $name = $parts[2]
                    $u = Backup-Value $path $name
                    Remove-ItemProperty -LiteralPath $path -Name $name -Force
                    Done 'Removed the program hijack' $u
                }
                'winlogon' {
                    $path = RegPath $parts[1]; $name = $parts[2]
                    $u = Backup-Value $path $name
                    if ($path -like 'HKCU:*') { Remove-ItemProperty -LiteralPath $path -Name $name -Force }
                    elseif ($name -eq 'Shell') { Set-ItemProperty -LiteralPath $path -Name Shell -Value 'explorer.exe' }
                    else { Set-ItemProperty -LiteralPath $path -Name Userinit -Value "$WinDir\system32\userinit.exe," }
                    Done "Restored the Windows default for $name" $u
                }
                'appinit' {
                    $path = RegPath $parts[1]; $dll = $parts[2]
                    $u = Backup-Value $path 'AppInit_DLLs'
                    $rest = ((Get-ItemProperty -LiteralPath $path).AppInit_DLLs -split '[,\s]+' | Where-Object { $_ -and $_ -ne $dll }) -join ' '
                    Set-ItemProperty -LiteralPath $path -Name AppInit_DLLs -Value $rest
                    if (-not $rest) { Set-ItemProperty -LiteralPath $path -Name LoadAppInit_DLLs -Value 0 -Type DWord }
                    Done "Stopped loading $dll into every program" $u
                }
                'lsa' {
                    $path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; $vn = $parts[1]; $pkg = $parts[2]
                    if ($vn -notin @('Authentication Packages', 'Notification Packages', 'Security Packages')) { Fail 'unexpected value' }
                    $u = Backup-Value $path $vn
                    $rest = [string[]]@((Get-ItemProperty -LiteralPath $path).$vn | Where-Object { $_ -and $_.Trim('"') -ne $pkg })
                    New-ItemProperty -LiteralPath $path -Name $vn -PropertyType MultiString -Value $rest -Force | Out-Null
                    Done "Removed $pkg from the sign-in system (restart to finish)" $u
                }
                default { Fail ('unknown entry type ' + $parts[0]) }
            }
        }

        'fixsetting' {
            $parts = ([string]$q.key) -split '\|'
            switch ($parts[0]) {
                'exclpath' { Remove-MpPreference -ExclusionPath $parts[1]; Done 'Exclusion removed' ([ordered]@{ op = 'mp-add'; kind = 'ExclusionPath'; value = $parts[1] }) }
                'exclproc' { Remove-MpPreference -ExclusionProcess $parts[1]; Done 'Exclusion removed' ([ordered]@{ op = 'mp-add'; kind = 'ExclusionProcess'; value = $parts[1] }) }
                'exclext' { Remove-MpPreference -ExclusionExtension $parts[1]; Done 'Exclusion removed' ([ordered]@{ op = 'mp-add'; kind = 'ExclusionExtension'; value = $parts[1] }) }
                'hosts' {
                    $hf = "$WinDir\System32\drivers\etc\hosts"
                    $orig = Get-Content -LiteralPath $hf -Raw
                    $bad = $parts[1] -split '\s+'
                    $lines = Get-Content -LiteralPath $hf | Where-Object {
                        $t = ($_ -replace '#.*$', '').Trim() -split '\s+'
                        -not ($t.Count -ge 2 -and $t[0] -eq $bad[0] -and ($t[1..($t.Count - 1)] -contains $bad[1]))
                    }
                    Set-Content -LiteralPath $hf -Value $lines -Encoding ASCII
                    ipconfig /flushdns | Out-Null
                    Done 'Redirect removed from the hosts file' ([ordered]@{ op = 'hosts-restore'; content = $orig })
                }
                'pac' {
                    $p = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
                    $u = Backup-Value $p 'AutoConfigURL'
                    Remove-ItemProperty -LiteralPath $p -Name AutoConfigURL -Force
                    Done 'Automatic proxy script removed' $u
                }
                'proxy' {
                    $p = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
                    $u = Backup-Value $p 'ProxyEnable'
                    Set-ItemProperty -LiteralPath $p -Name ProxyEnable -Value 0 -Type DWord
                    Done 'Proxy turned off' $u
                }
                'root' {
                    $store = $parts[1]; $thumb = $parts[2]
                    if ($store -notin @('LocalMachine', 'CurrentUser') -or $thumb -notmatch '^[0-9A-Fa-f]{40}$') { Fail 'unexpected certificate' }
                    $c = Get-Item -LiteralPath "Cert:\$store\Root\$thumb"
                    $b64 = [Convert]::ToBase64String($c.RawData)
                    Remove-Item -LiteralPath "Cert:\$store\Root\$thumb" -Force
                    Done 'Certificate removed' ([ordered]@{ op = 'cert-add'; store = $store; b64 = $b64 })
                }
                'policy' {
                    $path = RegPath $parts[1]; $name = $parts[2]
                    $u = Backup-Value $path $name
                    Remove-ItemProperty -LiteralPath $path -Name $name -Force
                    Done 'Browser policy removed (restart the browser)' $u
                }
                'prot' {
                    switch ($parts[1]) {
                        'rtp' { Set-MpPreference -DisableRealtimeMonitoring $false; Done 'Real-time protection turned on' }
                        'av' { Start-Service WinDefend -ErrorAction SilentlyContinue; Set-MpPreference -DisableRealtimeMonitoring $false; Done 'Windows Defender turned on' }
                        'sigs' { Update-MpSignature; Done 'Virus definitions updated' }
                        'firewall' { Set-NetFirewallProfile -All -Enabled True; Done 'Firewall turned on for all networks' }
                        'uac' { Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name EnableLUA -Value 1 -Type DWord; Done 'Admin prompts turned on (restart to finish)' }
                        'tamper' { Start-Process 'windowsdefender://threatsettings'; Done 'Opened Windows Security: switch on Tamper Protection there' }
                        'smartscreen' { Remove-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name EnableSmartScreen -ErrorAction SilentlyContinue; Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' -Name SmartScreenEnabled -Value 'Warn'; Done 'SmartScreen turned on' }
                        default { Fail 'unknown setting' }
                    }
                }
                default { Fail 'unknown setting' }
            }
        }

        'defender-remove' { Remove-MpThreat; Done 'Windows Defender removed the active threats' }

        'harden' {
            $did = @()
            foreach ($id in @($q.ids)) {
                switch ($id) {
                    'rtp' { Set-MpPreference -DisableRealtimeMonitoring $false; $did += 'real-time protection' }
                    'sigs' { Update-MpSignature; $did += 'virus definitions' }
                    'pua' { Set-MpPreference -PUAProtection Enabled; $did += 'unwanted-app blocking' }
                    'netprot' { Set-MpPreference -EnableNetworkProtection Enabled; $did += 'network protection' }
                    'cfa' { Set-MpPreference -EnableControlledFolderAccess Enabled; $did += 'ransomware folder guard' }
                    'cloud' { Set-MpPreference -MAPSReporting Advanced -SubmitSamplesConsent SendSafeSamples -CloudBlockLevel High; $did += 'cloud protection (high)' }
                    'firewall' { Set-NetFirewallProfile -All -Enabled True; $did += 'firewall' }
                    'smartscreen' { Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' -Name SmartScreenEnabled -Value 'Warn'; $did += 'SmartScreen' }
                    'asr' {
                        $ids = @($q.asr | ForEach-Object { $_.ID })
                        $acts = @($q.asr | ForEach-Object { $_.Mode })
                        Add-MpPreference -AttackSurfaceReductionRules_Ids $ids -AttackSurfaceReductionRules_Actions $acts
                        $did += ("{0} attack blocking rules" -f $ids.Count)
                    }
                    'asr-off' {
                        $ids = @($q.asr | ForEach-Object { $_.ID })
                        Add-MpPreference -AttackSurfaceReductionRules_Ids $ids -AttackSurfaceReductionRules_Actions (@($ids | ForEach-Object { 'Disabled' }))
                        $did += 'attack blocking rules switched off'
                    }
                    'tamper' { Start-Process 'windowsdefender://threatsettings'; $did += 'opened Tamper Protection settings' }
                }
            }
            Done ('Turned on: ' + ($did -join ', '))
        }

        'bloat' {
            $kind = [string]$q.kind
            $parts = ([string]$q.key) -split '\|'
            switch ($kind) {
                'store' {
                    $full = $parts[1]
                    if (-not $full) { Fail 'unknown app' }
                    Remove-AppxPackage -Package $full
                    Done 'Removed. You can reinstall it from the Microsoft Store.'
                }
                'program' {
                    $un = ($parts[1..($parts.Count - 1)] -join '|')
                    if (-not $un) { Fail 'This program has no uninstaller' }
                    if ($un -match '^(?i)msiexec') { $un = $un -replace '(?i)/I\{', '/X{' }
                    Start-Process -FilePath "$WinDir\System32\cmd.exe" -ArgumentList ('/c "' + $un + '"') -WindowStyle Hidden
                    Done "Its uninstaller has opened: follow the steps on screen"
                }
                'startup' {
                    $entry = ($parts[0..($parts.Count - 2)] -join '|')
                    $ak = Approved-Key $entry
                    $path = RegPath $ak.path
                    $u = $null
                    try { $u = Backup-Value $path $ak.name } catch { $u = [ordered]@{ op = 'reg-del'; path = $path; name = $ak.name } }
                    if (-not (Test-Path -LiteralPath $path)) { New-Item -Path $path -Force | Out-Null }
                    $val = [byte[]](3, 0, 0, 0) + [BitConverter]::GetBytes([DateTime]::Now.ToFileTime())
                    New-ItemProperty -LiteralPath $path -Name $ak.name -PropertyType Binary -Value $val -Force | Out-Null
                    Done 'Will no longer start with Windows' $u
                }
                default { Fail 'unknown kind' }
            }
        }

        'undo' {
            $u = $q.undo
            switch ($u.op) {
                'reg-set' { Set-Value $u; Done 'Setting put back' }
                'reg-del' { Remove-ItemProperty -LiteralPath (RegPath $u.path) -Name $u.name -Force -ErrorAction SilentlyContinue; Done 'Setting put back' }
                'task-import' { Register-ScheduledTask -TaskPath $u.path -TaskName $u.name -Xml ([string]$u.xml) -Force | Out-Null; Done 'Scheduled task put back' }
                'svc-start' { Set-ItemProperty -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\$($u.name)" -Name Start -Value ([int]$u.start); Done 'Service put back' }
                'mp-add' {
                    switch ($u.kind) {
                        'ExclusionPath' { Add-MpPreference -ExclusionPath $u.value }
                        'ExclusionProcess' { Add-MpPreference -ExclusionProcess $u.value }
                        'ExclusionExtension' { Add-MpPreference -ExclusionExtension $u.value }
                    }
                    Done 'Exclusion put back'
                }
                'hosts-restore' { Set-Content -LiteralPath "$WinDir\System32\drivers\etc\hosts" -Value ([string]$u.content) -NoNewline -Encoding ASCII; Done 'Hosts file put back' }
                'cert-add' {
                    $c = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 (, [Convert]::FromBase64String([string]$u.b64))
                    $s = New-Object System.Security.Cryptography.X509Certificates.X509Store('Root', [string]$u.store)
                    $s.Open('ReadWrite'); $s.Add($c); $s.Close()
                    Done 'Certificate put back'
                }
                'note' { Done 'This item cannot be put back automatically (details are kept in the record)' }
                default { Fail 'nothing to undo' }
            }
        }

        default { Fail 'unknown operation' }
    }
} catch {
    Fail $_.Exception.Message
}
