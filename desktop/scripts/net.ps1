# CoreKit :: Internet Troubleshooter - diagnostic + fix engine (run by CoreKit.exe)
# Output protocol (one per line):  P|pct|label   L|kind|text   R|<json>
param(
    [string]$Mode = 'scan',
    [string]$Sites = '',
    [string]$Actions = '',
    [string]$Keep = ''
)

$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference    = 'SilentlyContinue'
try { [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false) } catch {}
try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]'Tls12, Tls13' }
catch { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 }

function Out-Line([string]$s) { [Console]::Out.WriteLine($s); [Console]::Out.Flush() }
function Log([string]$Kind, [string]$Text) { Out-Line ("L|{0}|{1}" -f $Kind, ($Text -replace '[\r\n]+', ' ')) }
function Prog([int]$Pct, [string]$Label) { Out-Line ("P|{0}|{1}" -f $Pct, $Label) }
function Ms($sw) { return [int]$sw.Elapsed.TotalMilliseconds }
function Inner($e) { while ($e.InnerException) { $e = $e.InnerException }; return $e }
# HTTP 'Date' headers are always GMT: parse as UTC (never via local time)
function Parse-HttpDate([string]$d) {
    if (-not $d) { return $null }
    try { return [DateTime]::ParseExact($d.Trim(), 'r', [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]'AssumeUniversal, AdjustToUniversal') } catch { return $null }
}
function Skew-From([string]$d) { $t = Parse-HttpDate $d; if ($t) { return [int]([DateTime]::UtcNow - $t).TotalSeconds }; return $null }
function Run-Exe([string]$Exe, [string]$ArgLine, [int]$Sec = 45) {
    $p = Start-Process -FilePath $Exe -ArgumentList $ArgLine -WindowStyle Hidden -PassThru
    if (-not $p.WaitForExit($Sec * 1000)) { try { $p.Kill() } catch {}; return $false }
    return $true
}

$DnsProviders = [ordered]@{
    cloudflare = @{ name = 'Cloudflare'; v4 = @('1.1.1.1', '1.0.0.1'); v6 = @('2606:4700:4700::1111', '2606:4700:4700::1001'); doh = 'https://cloudflare-dns.com/dns-query' }
    google     = @{ name = 'Google'; v4 = @('8.8.8.8', '8.8.4.4'); v6 = @('2001:4860:4860::8888', '2001:4860:4860::8844'); doh = 'https://dns.google/dns-query' }
    quad9      = @{ name = 'Quad9'; v4 = @('9.9.9.9', '149.112.112.112'); v6 = @('2620:fe::fe', '2620:fe::9'); doh = 'https://dns.quad9.net/dns-query' }
    opendns    = @{ name = 'OpenDNS'; v4 = @('208.67.222.222', '208.67.220.220'); v6 = @('2620:119:35::35', '2620:119:53::53'); doh = 'https://doh.opendns.com/dns-query' }
}

# ============================================================== probes

function Ping-Host([string]$Target, [int]$Count = 8, [int]$Timeout = 1000) {
    $p = New-Object System.Net.NetworkInformation.Ping
    $times = @(); $lost = 0
    for ($i = 0; $i -lt $Count; $i++) {
        try { $r = $p.Send($Target, $Timeout); if ($r.Status -eq 'Success') { $times += [int]$r.RoundtripTime } else { $lost++ } } catch { $lost++ }
        Start-Sleep -Milliseconds 40
    }
    $avg = $null; $jit = $null; $min = $null
    if ($times.Count) {
        $avg = [math]::Round(($times | Measure-Object -Average).Average, 1)
        $min = ($times | Measure-Object -Minimum).Minimum
        $jit = 0
        if ($times.Count -gt 1) { $d = 0; for ($i = 1; $i -lt $times.Count; $i++) { $d += [math]::Abs($times[$i] - $times[$i - 1]) }; $jit = [math]::Round($d / ($times.Count - 1), 1) }
    }
    return [ordered]@{ target = $Target; ok = ($times.Count -gt 0); avg = $avg; min = $min; jitter = $jit; loss = [int][math]::Round($lost * 100 / $Count) }
}

function Dns-Query([string]$Name, [string]$Server) {
    $sw = [Diagnostics.Stopwatch]::StartNew()
    try {
        $r = @(Resolve-DnsName -Name $Name -Server $Server -Type A -DnsOnly -NoHostsFile -QuickTimeout -ErrorAction Stop | Where-Object { [string]$_.Type -eq 'A' })
        return [ordered]@{ ok = ($r.Count -gt 0); ms = (Ms $sw); ips = @($r | ForEach-Object { [string]$_.IPAddress }); nx = $false; err = $null }
    }
    catch {
        $m = [string]$_.Exception.Message
        return [ordered]@{ ok = $false; ms = (Ms $sw); ips = @(); nx = ($m -match 'does not exist'); err = $m }
    }
}

function Os-Resolve([string]$Name) {
    $sw = [Diagnostics.Stopwatch]::StartNew()
    try {
        $t = [System.Net.Dns]::GetHostAddressesAsync($Name)
        if (-not $t.Wait(6000)) { return [ordered]@{ ok = $false; ms = (Ms $sw); ips = @(); err = 'Timed out' } }
        $ips = @($t.Result | Where-Object { $_.AddressFamily -eq 'InterNetwork' } | ForEach-Object { $_.IPAddressToString })
        $ip6 = @($t.Result | Where-Object { $_.AddressFamily -eq 'InterNetworkV6' } | ForEach-Object { $_.IPAddressToString })
        return [ordered]@{ ok = (($ips.Count + $ip6.Count) -gt 0); ms = (Ms $sw); ips = $ips; ip6 = $ip6; err = $null }
    }
    catch { return [ordered]@{ ok = $false; ms = (Ms $sw); ips = @(); err = [string](Inner $_.Exception).Message } }
}

function Tls-Probe([string]$HostName, [string]$Ip) {
    $res = [ordered]@{ ok = $false; tcpOk = $false; tcpMs = $null; tlsMs = $null; protocol = $null; subject = $null; issuer = $null; issuerOrg = $null
        validFrom = $null; validTo = $null; daysLeft = $null; errors = $null; chain = @(); chainNames = @(); root = $null; error = $null; revocation = @() }
    $c = New-Object System.Net.Sockets.TcpClient
    try {
        $sw = [Diagnostics.Stopwatch]::StartNew()
        $ar = $c.BeginConnect($Ip, 443, $null, $null)
        if (-not $ar.AsyncWaitHandle.WaitOne(5000)) { $res.error = 'Connection to port 443 timed out'; return $res }
        $c.EndConnect($ar)
        $res.tcpOk = $true; $res.tcpMs = Ms $sw
        $script:tlsCap = $null
        $cb = [System.Net.Security.RemoteCertificateValidationCallback] {
            param($s, $cert, $chain, $errs)
            $st = @(); foreach ($x in $chain.ChainStatus) { $st += [string]$x.Status }
            $els = @(); foreach ($el in $chain.ChainElements) { $els += [string]$el.Certificate.Subject }
            $script:tlsCap = @{ cert = (New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList $cert); errs = [string]$errs; st = $st; els = $els }
            return $true
        }
        $ssl = New-Object System.Net.Security.SslStream -ArgumentList $c.GetStream(), $false, $cb
        $ssl.ReadTimeout = 6000; $ssl.WriteTimeout = 6000
        $sw2 = [Diagnostics.Stopwatch]::StartNew()
        $ssl.AuthenticateAsClient($HostName)
        $res.tlsMs = Ms $sw2
        $res.protocol = ([string]$ssl.SslProtocol) -replace 'Tls', 'TLS ' -replace 'TLS 1(\d)', 'TLS 1.$1' -replace 'TLS $', 'TLS 1.0'
        $ssl.Dispose()
    }
    catch { $res.error = [string](Inner $_.Exception).Message }
    finally { $c.Close() }
    if ($script:tlsCap) {
        $x = $script:tlsCap.cert
        $res.subject = $x.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false)
        $res.issuer = $x.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $true)
        if ($x.Issuer -match 'O=("?)([^,"]+)\1') { $res.issuerOrg = $Matches[2] } else { $res.issuerOrg = $res.issuer }
        $res.validFrom = $x.NotBefore.ToString('dd MMM yyyy')
        $res.validTo = $x.NotAfter.ToString('dd MMM yyyy')
        $res.daysLeft = [int]($x.NotAfter - (Get-Date)).TotalDays
        $res.errors = $script:tlsCap.errs
        $res.chain = @($script:tlsCap.st | Where-Object { $_ -and $_ -ne 'NoError' })
        $res.chainNames = @($script:tlsCap.els)
        if ($res.chainNames.Count) { $res.root = ($res.chainNames[-1] -replace '^CN=', '' -replace ',.*$', '') }
        $res.ok = ($res.errors -eq 'None') -and -not $res.error
        $script:lastCert = $x
    }
    return $res
}

function Rev-Check($cert) {
    try {
        $ch = New-Object System.Security.Cryptography.X509Certificates.X509Chain
        $ch.ChainPolicy.RevocationMode = 'Online'
        $ch.ChainPolicy.RevocationFlag = 'ExcludeRoot'
        $ch.ChainPolicy.UrlRetrievalTimeout = [TimeSpan]::FromSeconds(6)
        [void]$ch.Build($cert)
        return @($ch.ChainStatus | ForEach-Object { [string]$_.Status } | Where-Object { $_ -match 'Revo|Offline' })
    }
    catch { return @() }
}

function Http-Probe([string]$Url, [int]$Timeout = 9000) {
    $r = [ordered]@{ ok = $false; status = $null; ms = $null; final = $null; server = $null; date = $null; body = $null; error = $null; webStatus = $null }
    $sw = [Diagnostics.Stopwatch]::StartNew()
    try {
        $req = [System.Net.HttpWebRequest]::Create($Url)
        $req.Method = 'GET'; $req.Timeout = $Timeout; $req.ReadWriteTimeout = $Timeout; $req.AllowAutoRedirect = $true
        $req.UserAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0'
        $req.Accept = 'text/html,application/xhtml+xml,*/*'
        $resp = $req.GetResponse()
        $r.ms = Ms $sw
        $r.status = [int]$resp.StatusCode
        $r.final = [string]$resp.ResponseUri
        $r.server = $resp.Headers['Server']
        $r.date = $resp.Headers['Date']
        $rs = $resp.GetResponseStream(); $buf = New-Object byte[] 4096; $n = $rs.Read($buf, 0, 4096)
        $r.body = [System.Text.Encoding]::UTF8.GetString($buf, 0, [math]::Max(0, $n))
        $resp.Close()
        $r.ok = ($r.status -lt 400)
    }
    catch {
        $e = $_.Exception
        while ($e -and -not ($e -is [System.Net.WebException]) -and $e.InnerException) { $e = $e.InnerException }
        if ($e -is [System.Net.WebException]) {
            $r.webStatus = [string]$e.Status
            if ($e.Response) { $r.status = [int]$e.Response.StatusCode; $r.date = $e.Response.Headers['Date']; $r.final = [string]$e.Response.ResponseUri; $e.Response.Close() }
        }
        $r.ms = Ms $sw
        $r.error = [string](Inner $_.Exception).Message
    }
    return $r
}

function Clean-Site([string]$s) {
    $s = $s.Trim().ToLower() -replace '^[a-z]+://', '' -replace '[/?#:].*$', ''
    if ($s -match '^[a-z0-9]([a-z0-9\-\.]{0,251}[a-z0-9])?$' -and $s.Contains('.')) { return $s }
    return $null
}

# ============================================================== scan

function Run-Scan {
    $out = [ordered]@{ version = '1.0'; time = (Get-Date -Format 'dd MMM yyyy, HH:mm'); host = $env:COMPUTERNAME }
    $issues = New-Object System.Collections.ArrayList
    function Issue($id, $sev, $layer, $title, $detail, $fixes) { [void]$issues.Add([ordered]@{ id = $id; sev = $sev; layer = $layer; title = $title; detail = $detail; fixes = @($fixes) }) }

    # ---------------------------------------------------------- adapters
    Prog 4 'Network adapters'
    Log '#' 'Network diagnosis started'
    $script:VirtRe = 'Loopback|Npcap|WinPcap|Virtual|VMware|VirtualBox|Hyper-V|vEthernet|TAP-|Wintun|WireGuard|Bluetooth|Kernel Debug|WAN Miniport|Teredo|ISATAP'
    $phys = @(Get-NetAdapter -Physical | Where-Object { $_.InterfaceDescription -notmatch $script:VirtRe -and $_.Name -notmatch $script:VirtRe } | Sort-Object ifIndex)
    $adapters = @()
    foreach ($a in $phys) {
        $kind = if ($a.InterfaceDescription -match 'Wi-?Fi|Wireless|WLAN|802\.11' -or [string]$a.PhysicalMediaType -match '802\.11') { 'Wi-Fi' } elseif ([string]$a.PhysicalMediaType -eq '802.3') { 'Ethernet' } else { 'Other' }
        $adapters += [ordered]@{ name = $a.Name; desc = $a.InterfaceDescription; status = [string]$a.Status; kind = $kind; speed = $a.LinkSpeed; mac = $a.MacAddress
            driver = ("{0} ({1:dd MMM yyyy})" -f $a.DriverVersion, $a.DriverDate); disabled = ([string]$a.Status -eq 'Disabled') }
    }
    $out.adapters = $adapters
    $cfgs = @(Get-NetIPConfiguration -Detailed)
    $act = $cfgs | Where-Object { $_.IPv4DefaultGateway -and [string]$_.NetAdapter.Status -eq 'Up' } | Sort-Object { $_.NetIPv4Interface.InterfaceMetric } | Select-Object -First 1
    if (-not $act) {
        $rt = Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Sort-Object { $_.RouteMetric + $_.InterfaceMetric } | Select-Object -First 1
        if ($rt) { $act = $cfgs | Where-Object { $_.InterfaceIndex -eq $rt.ifIndex } | Select-Object -First 1 }
    }
    $active = $null
    if ($act) {
        $dnsV4 = @($act.DNSServer | Where-Object { $_.AddressFamily -eq 2 } | ForEach-Object { $_.ServerAddresses } | Select-Object -Unique)
        $dnsV6 = @($act.DNSServer | Where-Object { $_.AddressFamily -eq 23 } | ForEach-Object { $_.ServerAddresses } | Where-Object { $_ -notmatch '^fe[c-f]0:' } | Select-Object -Unique)
        $na = $act.NetAdapter
        $kind = if ($na.InterfaceDescription -match 'Wi-?Fi|Wireless|WLAN|802\.11' -or [string]$na.PhysicalMediaType -match '802\.11') { 'Wi-Fi' } elseif ([string]$na.PhysicalMediaType -eq '802.3') { 'Ethernet' } else { [string]$na.MediaType }
        $dhcp = [string]$act.NetIPv4Interface.Dhcp -eq 'Enabled'
        $provs = @()
        foreach ($d in $dnsV4) {
            $m = $null; foreach ($k in $DnsProviders.Keys) { if ($DnsProviders[$k].v4 -contains $d) { $m = $DnsProviders[$k].name } }
            if (-not $m) { $m = 'Router / ISP' }
            if ($provs -notcontains $m) { $provs += $m }
        }
        $prov = if (-not $provs.Count) { 'None' } elseif ($provs.Count -eq 1 -and $provs[0] -eq 'Router / ISP') { 'Automatic (router / ISP)' } else { $provs -join ' + ' }
        $active = [ordered]@{ name = $act.InterfaceAlias; desc = $act.InterfaceDescription; kind = $kind; index = $act.InterfaceIndex
            ipv4 = @($act.IPv4Address | ForEach-Object { $_.IPAddress })[0]; prefix = @($act.IPv4Address | ForEach-Object { $_.PrefixLength })[0]
            gateway = @($act.IPv4DefaultGateway | ForEach-Object { $_.NextHop })[0]; dns = $dnsV4; dns6 = $dnsV6; dnsProvider = $prov
            dhcp = $dhcp; speed = $na.LinkSpeed; mac = $na.MacAddress; connectivity = [string]$act.NetProfile.IPv4Connectivity; network = $act.NetProfile.Name
            ipv6 = @($act.IPv6Address | ForEach-Object { $_.IPAddress })[0] }
        Log '+' ("Active connection: {0} ({1})  IP {2}  Gateway {3}" -f $active.name, $kind, $active.ipv4, $active.gateway)
    }
    $out.active = $active
    $apipa = @(Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -like '169.254.*' -and $_.InterfaceAlias -in @($phys | Where-Object { $_.Status -eq 'Up' } | ForEach-Object { $_.Name }) })

    # ---------------------------------------------------------- wi-fi
    Prog 9 'Wi-Fi'
    $wifi = $null
    $wr = (& "$env:windir\System32\netsh.exe" wlan show interfaces 2>$null) -join "`n"
    if ($wr -match '(?m)^\s*Name\s*:') {
        function WV([string]$k) { if ($wr -match "(?m)^\s*$k\s*:\s*(.+?)\s*$") { return $Matches[1] } return $null }
        $sig = WV 'Signal'; $sigN = $null; if ($sig -match '(\d+)') { $sigN = [int]$Matches[1] }
        $wifi = [ordered]@{ state = (WV 'State'); ssid = (WV 'SSID'); signal = $sigN; radio = (WV 'Radio type'); band = (WV 'Band'); channel = (WV 'Channel')
            rx = (WV 'Receive rate \(Mbps\)'); tx = (WV 'Transmit rate \(Mbps\)'); auth = (WV 'Authentication'); cipher = (WV 'Cipher')
            radioOff = ($wr -match 'Software Off|Hardware Off') }
        if (-not $wifi.band -and $wifi.channel -match '^\d+$') { $wifi.band = $(if ([int]$wifi.channel -le 14) { '2.4 GHz' } elseif ([int]$wifi.channel -le 177) { '5 GHz' } else { '6 GHz' }) }
        if ($wifi.signal) { Log $(if ($wifi.signal -ge 60) { '+' } else { '~' }) ("Wi-Fi '{0}' signal {1}%  {2}  ch {3}" -f $wifi.ssid, $wifi.signal, $wifi.radio, $wifi.channel) }
    }
    $out.wifi = $wifi

    # ---------------------------------------------------------- reachability
    Prog 14 'Router'
    $gw = $null; if ($active -and $active.gateway) { $gw = Ping-Host $active.gateway 10 1000 }
    $out.pingGateway = $gw
    Prog 20 'Internet'
    $p1 = Ping-Host '1.1.1.1' 8 1500
    $p2 = Ping-Host '8.8.8.8' 8 1500
    $out.pingCloudflare = $p1; $out.pingGoogle = $p2
    $p6 = Ping-Host '2606:4700:4700::1111' 3 1500
    $out.ipv6 = [ordered]@{ ok = $p6.ok; avg = $p6.avg }
    $ipOnline = $p1.ok -or $p2.ok
    Log $(if ($ipOnline) { '+' } else { '!' }) ("Internet ping: 1.1.1.1 {0}  8.8.8.8 {1}" -f $(if ($p1.ok) { "$($p1.avg) ms" } else { 'no reply' }), $(if ($p2.ok) { "$($p2.avg) ms" } else { 'no reply' }))

    # ---------------------------------------------------------- NCSI / captive portal / clock
    Prog 26 'Captive portal & clock'
    $nc = Http-Probe 'http://www.msftconnecttest.com/connecttest.txt' 7000
    $ncOk = ($nc.body -like 'Microsoft Connect Test*')
    $portal = ($nc.status -and -not $ncOk) -or ($nc.final -and $nc.final -notmatch 'msftconnecttest\.com')
    $out.ncsi = [ordered]@{ ok = $ncOk; portal = [bool]$portal; status = $nc.status; final = $nc.final; error = $nc.error }
    $skews = @()
    $s1 = Skew-From $nc.date; if ($null -ne $s1) { $skews += $s1 }
    $g204 = Http-Probe 'http://www.google.com/generate_204' 6000
    $s2 = Skew-From $g204.date; if ($null -ne $s2) { $skews += $s2 }
    $skew = $null
    if ($skews.Count) { $skew = @($skews | Sort-Object { [math]::Abs($_) })[0] }
    $w32 = Get-Service w32time
    $tz = (Get-TimeZone).Id
    $out.clock = [ordered]@{ skew = $skew; local = (Get-Date -Format 'dd MMM yyyy HH:mm:ss'); tz = $tz; service = [string]$w32.Status; startup = [string]$w32.StartType }
    if ($null -ne $skew) { Log $(if ([math]::Abs($skew) -lt 120) { '+' } else { '!' }) ("Clock offset: {0} s" -f $skew) }

    # ---------------------------------------------------------- proxy, hosts, vpn, firewall
    Prog 30 'Proxy, hosts & VPN'
    $is = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
    $wh = (& "$env:windir\System32\netsh.exe" winhttp show proxy 2>$null) -join ' '
    $out.proxy = [ordered]@{ enabled = ($is.ProxyEnable -eq 1); server = $is.ProxyServer; pac = $is.AutoConfigURL; winhttpDirect = ($wh -match 'Direct access'); winhttp = (($wh -replace '\s+', ' ').Trim()) }
    $hostsPath = "$env:windir\System32\drivers\etc\hosts"
    $hosts = @()
    foreach ($ln in @(Get-Content $hostsPath)) {
        $t = ($ln -replace '#.*$', '').Trim()
        if ($t) { $parts = $t -split '\s+'; if ($parts.Count -ge 2) { $hosts += [ordered]@{ ip = $parts[0]; names = @($parts[1..($parts.Count - 1)]) } } }
    }
    $out.hosts = $hosts
    $vpn = @(Get-NetAdapter | Where-Object { $_.Status -eq 'Up' -and $_.InterfaceDescription -match 'TAP|TUN|WireGuard|Wintun|VPN|Fortinet|AnyConnect|OpenVPN|Tailscale|ZeroTier|Proton|Nord|Express|Pulse|GlobalProtect|Hamachi|Radmin' } | ForEach-Object { $_.InterfaceDescription })
    $out.vpn = $vpn
    $out.firewall = @(Get-NetFirewallProfile | ForEach-Object { [ordered]@{ name = [string]$_.Name; on = [bool]$_.Enabled } })
    $out.av = @(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct | ForEach-Object { $_.displayName })

    # ---------------------------------------------------------- DNS benchmark
    Prog 36 'DNS benchmark'
    $names = @('google.com', 'youtube.com', 'facebook.com', 'microsoft.com', 'wikipedia.org', 'amazon.com')
    $servers = @()
    $known = @(); foreach ($k in $DnsProviders.Keys) { $known += $DnsProviders[$k].v4 }
    if ($active) { foreach ($d in $active.dns) { if ($known -notcontains $d) { $servers += [ordered]@{ key = 'current'; name = 'Current'; ip = $d } } } }
    foreach ($k in $DnsProviders.Keys) { $servers += [ordered]@{ key = $k; name = $DnsProviders[$k].name; ip = $DnsProviders[$k].v4[0] } }
    $bench = @(); $si = 0
    foreach ($s in $servers) {
        $si++
        Prog ([int](36 + 16 * $si / [math]::Max(1, $servers.Count))) ("DNS benchmark: " + $s.name)
        $times = @(); $fail = 0
        foreach ($n in $names) { $q = Dns-Query $n $s.ip; if ($q.ok) { $times += $q.ms } else { $fail++ } }
        $med = $null
        if ($times.Count) { $sorted = @($times | Sort-Object); $med = $sorted[[int][math]::Floor(($sorted.Count - 1) / 2)] }
        $isCur = ($s.key -eq 'current') -or ($active -and @($active.dns | Where-Object { $DnsProviders[$s.key] -and $DnsProviders[$s.key].v4 -contains $_ }).Count -gt 0)
        $bench += [ordered]@{ key = $s.key; name = $s.name; ip = $s.ip; current = [bool]$isCur; ms = $med; fail = $fail; total = $names.Count }
        Log $(if ($fail -eq 0) { '+' } elseif ($fail -lt $names.Count) { '~' } else { '!' }) ("DNS {0} ({1}): {2}" -f $s.name, $s.ip, $(if ($null -ne $med) { "$med ms, $fail failed" } else { 'NO ANSWER' }))
    }
    $out.dnsBench = $bench
    # NXDOMAIN hijack (ISP redirecting unknown names to ads)
    $hijack = $false
    if ($active) {
        $rnd = 'corekit-nx-' + ([guid]::NewGuid().ToString('N').Substring(0, 12)) + '.com'
        foreach ($d in $active.dns) { $q = Dns-Query $rnd $d; if ($q.ok -and $q.ips.Count) { $hijack = $true } }
    }
    $out.dnsHijack = $hijack
    # DoH state (Windows 11)
    $doh = $null
    $out.dohSupported = [bool](Get-Command Get-DnsClientDohServerAddress -ErrorAction SilentlyContinue)
    if ($out.dohSupported) {
        $doh = @(Get-DnsClientDohServerAddress | Where-Object { $_.AutoUpgrade } | ForEach-Object { [string]$_.ServerAddress })
    }
    $out.doh = $doh

    # ---------------------------------------------------------- site tests
    $list = @()
    foreach ($s in @('www.google.com', 'www.cloudflare.com', 'www.microsoft.com')) { $list += [ordered]@{ host = $s; custom = $false } }
    foreach ($s in @($Sites -split ',')) { $c = Clean-Site $s; if ($c -and -not ($list | Where-Object { $_.host -eq $c })) { $list = @([ordered]@{ host = $c; custom = $true }) + $list } }
    $siteRes = @(); $k = 0
    foreach ($st in $list) {
        $k++
        $h = $st.host
        Prog ([int](54 + 26 * $k / $list.Count)) ("Testing " + $h)
        $r = [ordered]@{ host = $h; custom = $st.custom; status = 'ok'; cause = $null; fixes = @() }
        $hostsHit = @($hosts | Where-Object { $_.names -contains $h -or $_.names -contains ($h -replace '^www\.', '') })
        $r.hostsOverride = if ($hostsHit.Count) { $hostsHit[0].ip } else { $null }
        $r.dnsSys = Os-Resolve $h
        $r.dnsPub = Dns-Query $h '1.1.1.1'
        $ip = $null
        if ($r.dnsSys.ok -and $r.dnsSys.ips.Count) { $ip = $r.dnsSys.ips[0] } elseif ($r.dnsPub.ok) { $ip = $r.dnsPub.ips[0] }
        $r.ip = $ip
        $r.tls = $null; $r.http = $null
        if ($ip) {
            $r.tls = Tls-Probe $h $ip
            if ($st.custom -or $h -eq 'www.google.com') { if ($script:lastCert -and $r.tls.subject) { $r.tls.revocation = @(Rev-Check $script:lastCert) } }
            $script:lastCert = $null
            if ($r.dnsSys.ok) { $r.http = Http-Probe ("https://" + $h + "/") }
        }
        # ---- verdict for this site
        $t = $r.tls
        if ($r.hostsOverride) { $r.status = 'fail'; $r.cause = "Your hosts file forces this site to $($r.hostsOverride)."; $r.fixes = @('reset-hosts', 'flushdns') }
        elseif (-not $r.dnsSys.ok -and $r.dnsPub.ok) { $r.status = 'fail'; $r.cause = 'Your current DNS server cannot find this site, but public DNS can. Your DNS is failing or blocking it.'; $r.fixes = @('dns:cloudflare', 'flushdns') }
        elseif (-not $r.dnsSys.ok -and -not $r.dnsPub.ok) { $r.status = 'fail'; $r.cause = $(if ($ipOnline) { 'This domain does not exist or its DNS is down (not a problem with this PC).' } else { 'No internet connection, so the name cannot be looked up.' }) }
        elseif ($t -and -not $t.tcpOk) { $r.status = 'fail'; $r.cause = 'Cannot connect to the site on port 443. It is blocked (firewall / VPN / ISP) or the site is down.' ; $r.fixes = @('flushdns') }
        elseif ($t -and $t.subject -and -not $t.ok) {
            $r.status = 'fail'
            $ch = ($t.chain -join ',')
            if ($t.errors -eq 'None' -and $t.error) { $r.cause = "Secure connection failed: $($t.error)"; $r.fixes = @('sync-time', 'clear-cert-cache') }
            elseif ($ch -match 'NotTimeValid' -and $null -ne $skew -and [math]::Abs($skew) -gt 300) { $r.cause = 'Connection not secure because your PC clock is wrong.'; $r.fixes = @('sync-time') }
            elseif ($t.errors -match 'NameMismatch') { $r.cause = "Certificate name mismatch: you are receiving '$($t.subject)' instead of this site. Usually a Wi-Fi login page, DNS hijack or blocking filter."; $r.fixes = @('dns:cloudflare', 'flushdns') }
            elseif ($ch -match 'NotTimeValid') { $r.cause = "The site's certificate has expired (site problem, not your PC)." }
            elseif ($ch -match 'UntrustedRoot|PartialChain') { $r.cause = "Your PC does not trust this certificate (issuer: $($t.issuerOrg)). Root certificates are missing or outdated, or something is intercepting HTTPS."; $r.fixes = @('update-roots', 'clear-cert-cache') }
            elseif ($ch -match 'Revoked') { $r.cause = 'The certificate has been revoked by its issuer (site problem).' }
            else { $r.cause = "Certificate problem: $($t.errors) $ch"; $r.fixes = @('clear-cert-cache', 'update-roots') }
        }
        elseif ($t -and $t.error -and -not $t.subject) { $r.status = 'fail'; $r.cause = "Secure connection failed: $($t.error)"; $r.fixes = @('sync-time', 'clear-cert-cache') }
        elseif ($t -and $t.revocation.Count) { $r.status = 'warn'; $r.cause = 'Certificate revocation could not be checked (CRL/OCSP servers unreachable). Some browsers may warn.'; $r.fixes = @('clear-cert-cache') }
        elseif ($r.http -and $r.http.status -ge 500) { $r.status = 'warn'; $r.cause = "The website's server returned error $($r.http.status). Problem is on the site, not your PC." }
        elseif ($r.http -and $r.http.status -in 401, 403, 429) { $r.status = 'warn'; $r.cause = "The site refused automated access ($($r.http.status)); it may still open in a browser." }
        elseif ($r.http -and -not $r.http.ok -and $r.http.error) { $r.status = 'warn'; $r.cause = "HTTP request failed: $($r.http.error)" }
        if ($h -eq 'www.google.com' -and $t -and $t.issuerOrg -and $t.issuerOrg -notmatch 'Google') {
            $r.status = 'fail'; $r.cause = "HTTPS traffic is being intercepted: Google's certificate is issued by '$($t.issuerOrg)' instead of Google. Usually antivirus 'HTTPS scanning', a proxy or a monitoring tool."; $out.intercept = $t.issuerOrg
        }
        Log $(switch ($r.status) { 'ok' { '+' } 'warn' { '~' } default { '!' } }) ("{0}: {1}" -f $h, $(if ($r.cause) { $r.cause } else { "OK  ({0} ms)" -f $(if ($r.http) { $r.http.ms } else { '-' }) }))
        $siteRes += $r
    }
    $out.sites = $siteRes

    # ---------------------------------------------------------- analysis
    Prog 82 'Analysing'
    $google = $siteRes | Where-Object { $_.host -eq 'www.google.com' } | Select-Object -First 1
    $webOk = @($siteRes | Where-Object { -not $_.custom -and $_.status -eq 'ok' }).Count
    $httpOnline = @($siteRes | Where-Object { $_.http -and $_.http.status }).Count -gt 0
    $online = $ipOnline -or $httpOnline -or $ncOk
    $out.online = $online
    $sysDnsOk = $google -and $google.dnsSys.ok
    $curBench = @($bench | Where-Object { $_.current })
    $curMs = $null; $okCur = @($curBench | Where-Object { $null -ne $_.ms } | Sort-Object { $_.ms }); if ($okCur.Count) { $curMs = $okCur[0].ms }
    $pub = @($bench | Where-Object { $_.key -ne 'current' -and -not $_.current -and $null -ne $_.ms -and $_.fail -eq 0 } | Sort-Object { $_.ms })
    $fastest = if ($pub.Count) { $pub[0] } else { $null }
    $out.fastestDns = if ($fastest) { $fastest.key } else { 'cloudflare' }
    $fx = 'dns:' + $out.fastestDns

    $disabled = @($adapters | Where-Object { $_.disabled })
    if (-not $active -and -not $online) {
        if ($wifi -and $wifi.radioOff) { Issue 'wifi-off' 'critical' 'adapter' 'Wi-Fi is turned off' 'The Wi-Fi radio is off (airplane mode or Wi-Fi switch). Turn it on in Settings.' @('open:wifi') }
        elseif ($disabled.Count) { Issue 'adapter-disabled' 'critical' 'adapter' 'Network adapter is disabled' ("Disabled: " + (($disabled | ForEach-Object { $_.name }) -join ', ')) @('enable-adapters') }
        elseif ($wifi -and $wifi.state -match 'disconnected') { Issue 'wifi-disconnected' 'critical' 'adapter' 'Wi-Fi is not connected' 'Connect to a Wi-Fi network first.' @('open:wifi') }
        elseif ($phys.Count -eq 0) { Issue 'no-adapter' 'critical' 'adapter' 'No network adapter found' 'No physical network adapter was detected. The driver may be missing.' @('open:devmgmt') }
        else { Issue 'no-connection' 'critical' 'adapter' 'No active network connection' 'The adapter has no default gateway. Renewing the IP address usually fixes this.' @('renew-ip', 'restart-adapter') }
    }
    if ($apipa.Count -and -not $online -and -not ($active -and $active.ipv4 -and $active.ipv4 -notlike '169.254.*')) { Issue 'apipa' 'critical' 'adapter' 'No IP address from the router' 'The PC got a 169.254.x.x address, meaning the router (DHCP) did not answer.' @('renew-ip', 'restart-adapter') }
    if ($wifi -and $wifi.signal -and $wifi.signal -lt 45) { Issue 'weak-signal' 'warning' 'adapter' ("Weak Wi-Fi signal ({0}%)" -f $wifi.signal) 'Move closer to the router or use the 5 GHz band. Weak signal causes drops and slow speed.' @() }
    if ($active -and $gw) {
        if (-not $gw.ok -and -not $online) { Issue 'gateway-down' 'critical' 'router' 'Router is not responding' "The router ($($active.gateway)) does not answer. Restart the adapter or the router." @('restart-adapter', 'renew-ip') }
        elseif ($gw.ok -and $gw.loss -ge 10) { Issue 'gateway-loss' 'warning' 'router' ("Packet loss to router ({0}%)" -f $gw.loss) 'Data is lost between this PC and the router (interference or weak signal).' @('restart-adapter') }
        elseif ($gw.ok -and $gw.avg -gt 30) { Issue 'gateway-slow' 'warning' 'router' ("High latency to router ({0} ms)" -f $gw.avg) 'Normal is under 5 ms on cable and under 15 ms on Wi-Fi.' @() }
    }
    if ($active -and -not $online) { Issue 'no-internet' 'critical' 'internet' 'No internet access' 'The local network works but nothing on the internet answers. Check the router / ISP, or reset the network stack.' @('renew-ip', 'flushdns', 'reset-stack') }
    if ($portal) { Issue 'captive-portal' 'critical' 'internet' 'Wi-Fi login page detected' 'This network needs you to sign in (hotel / office / cafe Wi-Fi). Open the login page.' @('open:portal') }
    if ($online -and ($p1.loss -ge 10 -or $p2.loss -ge 10)) { Issue 'internet-loss' 'warning' 'internet' ("Packet loss to the internet ({0}%)" -f [math]::Max($p1.loss, $p2.loss)) 'Some data is lost on the way to the internet. Causes video calls and games to stutter.' @() }
    if ($active -and $online -and -not $sysDnsOk) { Issue 'dns-fail' 'critical' 'dns' 'DNS is not working' 'The internet works but website names cannot be looked up. Switch to a public DNS.' @($fx, 'flushdns') }
    elseif ($active -and $null -ne $curMs -and $fastest -and $curMs -gt 120 -and $curMs -gt ($fastest.ms * 3) -and -not @($curBench | Where-Object { $_.key -ne 'current' }).Count) { Issue 'dns-slow' 'warning' 'dns' ("Slow DNS ({0} ms)" -f $curMs) ("{0} answers in {1} ms. A faster DNS makes every website open quicker." -f $fastest.name, $fastest.ms) @($fx, 'flushdns') }
    if ($hijack) { Issue 'dns-hijack' 'warning' 'dns' 'Your DNS redirects unknown websites' 'Your ISP DNS answers for websites that do not exist (ad redirection). This can break some sites and is a privacy risk.' @($fx, 'flushdns') }
    if ($curBench.Count -and @($curBench | Where-Object { $_.fail -eq 0 }).Count -eq 0 -and $curBench[0].fail -lt $names.Count) { Issue 'dns-unreliable' 'warning' 'dns' ("DNS failed {0} of {1} lookups" -f $curBench[0].fail, $names.Count) 'Your current DNS server is unreliable.' @($fx, 'flushdns') }
    if ($null -ne $skew -and [math]::Abs($skew) -gt 120) { Issue 'clock' $(if ([math]::Abs($skew) -gt 3600) { 'critical' } else { 'warning' }) 'web' ("PC clock is wrong by {0}" -f $(if ([math]::Abs($skew) -ge 3600) { "{0:N1} hours" -f ([math]::Abs($skew) / 3600) } else { "$([math]::Abs($skew)) seconds" })) 'A wrong date/time is the most common cause of "Your connection is not private".' @('sync-time') }
    if ($out.proxy.enabled -or $out.proxy.pac) { Issue 'proxy' 'warning' 'web' 'A proxy is configured' ("Proxy: " + $(if ($out.proxy.server) { $out.proxy.server } else { $out.proxy.pac }) + ". Old or broken proxy settings stop websites from loading.") @('reset-proxy') }
    if (-not $out.proxy.winhttpDirect -and $out.proxy.winhttp) { Issue 'winhttp-proxy' 'warning' 'web' 'System (WinHTTP) proxy is set' 'Windows Update and apps use this proxy. Remove it if you did not set it.' @('reset-proxy') }
    if ($out.intercept) { Issue 'intercept' 'critical' 'web' 'HTTPS is being intercepted' ("Secure traffic is decrypted by '{0}'. Disable HTTPS / web scanning in your antivirus, or remove the monitoring software." -f $out.intercept) @('clear-cert-cache') }
    $badHosts = @($hosts | Where-Object { $_.ip -notmatch '^(127\.0\.0\.1|0\.0\.0\.0|::1)$' -or ($_.names | Where-Object { $_ -match 'google|microsoft|windowsupdate|facebook|youtube|apple|cloudflare' }) })
    if ($badHosts.Count) { Issue 'hosts' 'warning' 'web' ("Hosts file has {0} redirect(s)" -f $badHosts.Count) (($badHosts | Select-Object -First 3 | ForEach-Object { "$($_.ip) -> $($_.names -join ' ')" }) -join '; ') @('reset-hosts') }
    if ($vpn.Count) { Issue 'vpn' 'info' 'internet' 'VPN is active' ("Traffic goes through: " + ($vpn -join ', ') + '. Disconnect it if sites fail only with the VPN on.') @() }
    foreach ($s in @($siteRes | Where-Object { $_.custom -and $_.status -ne 'ok' })) { Issue ('site:' + $s.host) $(if ($s.status -eq 'fail') { 'critical' } else { 'warning' }) 'web' ("{0} is not working" -f $s.host) $s.cause $s.fixes }
    foreach ($s in @($siteRes | Where-Object { -not $_.custom -and $_.status -eq 'fail' -and $_.host -ne 'www.google.com' })) {
        if (-not ($issues | Where-Object { $_.layer -eq 'web' -and $_.sev -eq 'critical' })) { Issue ('site:' + $s.host) 'warning' 'web' ("{0} failed" -f $s.host) $s.cause $s.fixes }
    }
    $out.issues = @($issues)

    # ---------------------------------------------------------- layer summary
    function Lay($st, $txt) { return [ordered]@{ status = $st; text = $txt } }
    $L = [ordered]@{}
    $L.adapter = if (-not $active -and -not $online) { Lay 'fail' 'Not connected' } elseif (-not $active) { Lay 'ok' 'Connected' } elseif ($active.ipv4 -like '169.254.*') { Lay 'fail' 'No IP address' } elseif ($wifi -and $wifi.signal -and $wifi.signal -lt 45) { Lay 'warn' ("Signal {0}%" -f $wifi.signal) } else { Lay 'ok' $(if ($active.kind -eq 'Wi-Fi' -and $wifi -and $wifi.signal) { "Wi-Fi {0}%" -f $wifi.signal } else { [string]$active.kind }) }
    $L.router = if (-not $active) { Lay 'idle' '-' } elseif ($gw -and $gw.ok) { Lay $(if ($gw.loss -ge 10 -or $gw.avg -gt 30) { 'warn' } else { 'ok' }) ("{0} ms" -f $gw.avg) } elseif ($online) { Lay 'ok' 'No ping reply' } else { Lay 'fail' 'No reply' }
    $L.internet = if (-not $active) { Lay 'idle' '-' } elseif ($portal) { Lay 'warn' 'Login required' } elseif ($ipOnline) { $pm = @(@($p1, $p2) | Where-Object { $_.ok } | ForEach-Object { $_.avg } | Measure-Object -Minimum)[0].Minimum; Lay $(if ($p1.loss -ge 10 -or $p2.loss -ge 10) { 'warn' } else { 'ok' }) ("{0} ms" -f $pm) } elseif ($online) { Lay 'ok' 'Online' } else { Lay 'fail' 'Offline' }
    $L.dns = if (-not $active) { Lay 'idle' '-' } elseif (-not $sysDnsOk) { Lay 'fail' 'Failing' } elseif ($issues | Where-Object { $_.layer -eq 'dns' }) { Lay 'warn' $(if ($null -ne $curMs) { "$curMs ms" } else { 'Issues' }) } else { Lay 'ok' $(if ($null -ne $curMs) { "$curMs ms" } else { 'OK' }) }
    $webCrit = @($issues | Where-Object { $_.layer -eq 'web' -and $_.sev -eq 'critical' }).Count
    $webWarn = @($issues | Where-Object { $_.layer -eq 'web' -and $_.sev -eq 'warning' }).Count
    $L.web = if (-not $online) { Lay 'idle' '-' } elseif ($webCrit) { Lay 'fail' 'Not secure' } elseif ($webWarn) { Lay 'warn' 'Issues' } else { Lay 'ok' $(if ($google -and $google.http -and $google.http.ms) { "{0} ms" -f $google.http.ms } else { 'Secure' }) }
    $out.layers = $L
    $nc2 = @($issues | Where-Object { $_.sev -eq 'critical' }).Count; $nw = @($issues | Where-Object { $_.sev -eq 'warning' }).Count
    Log $(if ($nc2) { '!' } elseif ($nw) { '~' } else { '+' }) ("Diagnosis complete: {0} critical, {1} warnings" -f $nc2, $nw)
    Prog 84 'Speed test'
    Out-Line ('R|' + ($out | ConvertTo-Json -Depth 10 -Compress))
}

# ============================================================== fixes

function Active-Adapters {
    $re = 'Loopback|Npcap|WinPcap|Virtual|VMware|VirtualBox|Hyper-V|vEthernet|TAP-|Wintun|WireGuard|Bluetooth|Kernel Debug|WAN Miniport|Teredo|ISATAP'
    $real = @(Get-NetAdapter -Physical | Where-Object { $_.InterfaceDescription -notmatch $re -and $_.Name -notmatch $re })
    $gwIf = @(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | ForEach-Object { $_.ifIndex })
    $up = @($real | Where-Object { [string]$_.Status -eq 'Up' -and $gwIf -contains $_.ifIndex })
    if (-not $up.Count) { $up = @($real | Where-Object { [string]$_.Status -eq 'Up' }) }
    if (-not $up.Count) { $up = @($real | Where-Object { [string]$_.Status -ne 'Disabled' }) }
    return $up
}

function Run-Fix([string]$id) {
    switch -Regex ($id) {
        '^flushdns$' {
            Clear-DnsClientCache
            $o = & "$env:windir\System32\ipconfig.exe" /flushdns 2>&1 | Out-String
            return @($true, 'DNS cache cleared')
        }
        '^dns:(\w+)$' {
            $k = $Matches[1]
            $ads = Active-Adapters
            if ($k -eq 'auto') {
                foreach ($a in $ads) { Set-DnsClientServerAddress -InterfaceIndex $a.ifIndex -ResetServerAddresses }
                Clear-DnsClientCache
                return @($true, ("DNS set back to automatic on " + (($ads | ForEach-Object { $_.Name }) -join ', ')))
            }
            $p = $DnsProviders[$k]
            if (-not $p) { return @($false, 'Unknown DNS provider') }
            $ok = $true
            foreach ($a in $ads) {
                try { Set-DnsClientServerAddress -InterfaceIndex $a.ifIndex -ServerAddresses (@($p.v4) + @($p.v6)) -ErrorAction Stop }
                catch { try { Set-DnsClientServerAddress -InterfaceIndex $a.ifIndex -ServerAddresses @($p.v4) -ErrorAction Stop } catch { $ok = $false } }
            }
            $msg = "DNS set to $($p.name) ($($p.v4 -join ', ')) on " + (($ads | ForEach-Object { $_.Name }) -join ', ')
            if (Get-Command Set-DnsClientDohServerAddress -ErrorAction SilentlyContinue) {
                $dohOk = $true
                foreach ($ip in (@($p.v4) + @($p.v6))) {
                    try { Set-DnsClientDohServerAddress -ServerAddress $ip -DohTemplate $p.doh -AllowFallbackToUdp $true -AutoUpgrade $true -ErrorAction Stop | Out-Null }
                    catch { try { Add-DnsClientDohServerAddress -ServerAddress $ip -DohTemplate $p.doh -AllowFallbackToUdp $true -AutoUpgrade $true -ErrorAction Stop | Out-Null } catch { $dohOk = $false } }
                }
                if ($dohOk) { $msg += ' + encrypted DNS (DoH) enabled' }
            }
            Clear-DnsClientCache
            return @($ok, $msg)
        }
        '^renew-ip$' {
            $ads = @(Active-Adapters | Where-Object { [string]$_.Status -eq 'Up' })
            if (-not $ads.Count) { $ads = @(Active-Adapters) }
            $ip = "$env:windir\System32\ipconfig.exe"
            $done = @()
            foreach ($a in $ads) {
                [void](Run-Exe $ip ('/release "' + $a.Name + '"') 20)
                $ok = Run-Exe $ip ('/renew "' + $a.Name + '"') 40
                $new = @(Get-NetIPAddress -InterfaceIndex $a.ifIndex -AddressFamily IPv4 | Where-Object { $_.IPAddress -notlike '169.254.*' } | ForEach-Object { $_.IPAddress })[0]
                $done += $(if ($new) { "$($a.Name): $new" } elseif ($ok) { "$($a.Name): no address yet" } else { "$($a.Name): router did not answer" })
            }
            Clear-DnsClientCache
            return @(($done -notmatch 'did not answer').Count -gt 0, ('IP renewed - ' + ($done -join ', ')))
        }
        '^restart-adapter$' {
            $ads = Active-Adapters
            foreach ($a in $ads) { Restart-NetAdapter -Name $a.Name -Confirm:$false }
            $t0 = Get-Date
            do { Start-Sleep -Seconds 1; $gw = Get-NetRoute -DestinationPrefix '0.0.0.0/0' } while (-not $gw -and ((Get-Date) - $t0).TotalSeconds -lt 25)
            return @($true, ("Restarted " + (($ads | ForEach-Object { $_.Name }) -join ', ') + $(if ($gw) { ' - connected again' } else { ' - waiting for Wi-Fi to reconnect' })))
        }
        '^enable-adapters$' {
            $d = @(Get-NetAdapter -Physical | Where-Object { [string]$_.Status -eq 'Disabled' -and $_.InterfaceDescription -notmatch 'Loopback|Npcap|WinPcap|Virtual|VMware|VirtualBox|Hyper-V|vEthernet|TAP-|Wintun|WireGuard|Bluetooth|Kernel Debug|WAN Miniport|Teredo|ISATAP' })
            foreach ($a in $d) { Enable-NetAdapter -Name $a.Name -Confirm:$false }
            Start-Sleep -Seconds 5
            return @($true, $(if ($d.Count) { "Enabled " + (($d | ForEach-Object { $_.Name }) -join ', ') } else { 'No disabled adapters' }))
        }
        '^sync-time$' {
            Set-Service w32time -StartupType Automatic
            Start-Service w32time
            $msg = ''
            $a1 = Skew-From (Http-Probe 'http://www.msftconnecttest.com/connecttest.txt' 7000).date
            $a2 = Skew-From (Http-Probe 'http://www.google.com/generate_204' 7000).date
            if ($null -ne $a1 -and $null -ne $a2 -and [math]::Abs($a1) -gt 300 -and [math]::Abs($a1 - $a2) -lt 60) {
                Set-Date -Adjust ([TimeSpan]::FromSeconds(-$a1)) | Out-Null
                $msg = ("Clock corrected by {0:N0} s. " -f $a1)
            }
            & "$env:windir\System32\w32tm.exe" /config /manualpeerlist:"time.windows.com,0x9 time.cloudflare.com,0x9 pool.ntp.org,0x9" /syncfromflags:manual /update 2>&1 | Out-Null
            [void](Run-Exe "$env:windir\System32\w32tm.exe" '/resync /force' 20)
            return @($true, ($msg + 'Automatic time sync enabled'))
        }
        '^reset-proxy$' {
            $p = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
            Set-ItemProperty $p -Name ProxyEnable -Value 0
            Remove-ItemProperty $p -Name AutoConfigURL
            Set-ItemProperty $p -Name AutoDetect -Value 1
            & "$env:windir\System32\netsh.exe" winhttp reset proxy 2>&1 | Out-Null
            try {
                Add-Type -Namespace CoreKit -Name WinInet -MemberDefinition '[DllImport("wininet.dll")] public static extern bool InternetSetOption(System.IntPtr h, int o, System.IntPtr b, int l);'
                [void][CoreKit.WinInet]::InternetSetOption([IntPtr]::Zero, 39, [IntPtr]::Zero, 0)
                [void][CoreKit.WinInet]::InternetSetOption([IntPtr]::Zero, 37, [IntPtr]::Zero, 0)
            } catch {}
            return @($true, 'Proxy settings removed (user + system)')
        }
        '^clear-cert-cache$' {
            & "$env:windir\System32\certutil.exe" -urlcache * delete 2>&1 | Out-Null
            & "$env:windir\System32\certutil.exe" -setreg chain\ChainCacheResyncFiletime @now 2>&1 | Out-Null
            return @($true, 'Certificate and revocation (CRL/OCSP) cache cleared')
        }
        '^update-roots$' {
            $sst = Join-Path $env:TEMP ('corekit_roots_' + [guid]::NewGuid().ToString('N') + '.sst')
            & "$env:windir\System32\certutil.exe" -generateSSTFromWU $sst 2>&1 | Out-Null
            if (-not (Test-Path $sst)) { return @($false, 'Could not download root certificates from Windows Update') }
            $before = @(Get-ChildItem Cert:\LocalMachine\Root).Count
            Import-Certificate -FilePath $sst -CertStoreLocation Cert:\LocalMachine\Root | Out-Null
            $after = @(Get-ChildItem Cert:\LocalMachine\Root).Count
            Remove-Item $sst -Force
            return @($true, ("Trusted root certificates updated ({0} added)" -f ($after - $before)))
        }
        '^clear-browser-cache$' {
            $closed = @()
            $mains = @(Get-CimInstance Win32_Process -Filter "Name='msedge.exe' OR Name='chrome.exe' OR Name='brave.exe' OR Name='firefox.exe' OR Name='opera.exe'")
            foreach ($p in $mains) {
                $cl = [string]$p.CommandLine
                if ($Keep -and $cl -like "*$Keep*") { continue }
                if ($cl -match '--type=' -or $cl -match '-contentproc') { continue }
                Stop-Process -Id $p.ProcessId -Force; $closed += ($p.Name -replace '\.exe$', '')
            }
            if ($closed.Count) { Start-Sleep -Seconds 2 }
            $roots = @("$env:LOCALAPPDATA\Microsoft\Edge\User Data", "$env:LOCALAPPDATA\Google\Chrome\User Data", "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data", "$env:APPDATA\Opera Software\Opera Stable")
            $freed = 0
            foreach ($r in $roots) {
                if (-not (Test-Path $r)) { continue }
                $profiles = @(Get-ChildItem $r -Directory | Where-Object { $_.Name -eq 'Default' -or $_.Name -like 'Profile *' }) + @(Get-Item $r)
                foreach ($pr in $profiles) {
                    foreach ($sub in @('Cache', 'Code Cache', 'GPUCache', 'Service Worker\CacheStorage', 'Service Worker\ScriptCache', 'ShaderCache', 'GrShaderCache', 'DawnCache')) {
                        $d = Join-Path $pr.FullName $sub
                        if (Test-Path $d) { $freed += (Get-ChildItem $d -Recurse -File | Measure-Object Length -Sum).Sum; Remove-Item "$d\*" -Recurse -Force }
                    }
                }
            }
            foreach ($fp in @(Get-ChildItem "$env:LOCALAPPDATA\Mozilla\Firefox\Profiles" -Directory)) {
                $d = Join-Path $fp.FullName 'cache2'
                if (Test-Path $d) { $freed += (Get-ChildItem $d -Recurse -File | Measure-Object Length -Sum).Sum; Remove-Item "$d\*" -Recurse -Force }
            }
            $msg = "Browser cache cleared ({0:N0} MB). Cookies and passwords kept." -f ($freed / 1MB)
            if ($closed.Count) { $msg += ' Closed: ' + (($closed | Select-Object -Unique) -join ', ') + '.' }
            return @($true, $msg)
        }
        '^reset-hosts$' {
            $hp = "$env:windir\System32\drivers\etc\hosts"
            Copy-Item $hp ("$hp.corekit-backup-" + (Get-Date -Format 'yyyyMMdd-HHmmss')) -Force
            $def = "# Copyright (c) 1993-2009 Microsoft Corp.`r`n#`r`n# This is a sample HOSTS file used by Microsoft TCP/IP for Windows.`r`n#`r`n# localhost name resolution is handled within DNS itself.`r`n#`t127.0.0.1       localhost`r`n#`t::1             localhost`r`n"
            [System.IO.File]::WriteAllText($hp, $def, [System.Text.Encoding]::ASCII)
            Clear-DnsClientCache
            return @($true, 'Hosts file reset to Windows default (backup saved next to it)')
        }
        '^reset-stack$' {
            & "$env:windir\System32\netsh.exe" winsock reset 2>&1 | Out-Null
            & "$env:windir\System32\netsh.exe" int ip reset 2>&1 | Out-Null
            & "$env:windir\System32\netsh.exe" int ipv6 reset 2>&1 | Out-Null
            Clear-DnsClientCache
            $script:Reboot = $true
            return @($true, 'Winsock and TCP/IP stack reset. Restart the PC to finish.')
        }
        '^reboot$' {
            & "$env:windir\System32\shutdown.exe" /r /t 15 /c "CoreKit: restarting to finish network repair" 2>&1 | Out-Null
            return @($true, 'PC will restart in 15 seconds')
        }
        default { return @($false, "Unknown action $id") }
    }
}

function Run-Fixes {
    $script:Reboot = $false
    $acts = @($Actions -split ',' | Where-Object { $_ })
    $res = @(); $i = 0
    foreach ($a in $acts) {
        $i++
        Prog ([int](100 * ($i - 1) / [math]::Max(1, $acts.Count))) $a
        Log '*' ("Running: " + $a)
        $r = $null
        try { $r = @(Run-Fix $a) } catch { $r = @($false, [string](Inner $_.Exception).Message) }
        if ($r.Count -lt 2) { $r = @($false, 'No result') }
        $ok = [bool]$r[-2]; $msg = [string]$r[-1]
        $res += [ordered]@{ id = $a; ok = $ok; msg = $msg }
        Log $(if ($ok) { '+' } else { '!' }) $msg
    }
    Prog 100 'Done'
    Out-Line ('R|' + ([ordered]@{ results = $res; reboot = [bool]$script:Reboot } | ConvertTo-Json -Depth 5 -Compress))
}

if ($Mode -eq 'fix') { Run-Fixes } else { Run-Scan }
