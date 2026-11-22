# CoreKit Storage & Performance: the installed-software list (from the registry and the Store) and
# the hibernation state. Drives, folder sizes, caches and the Recycle Bin are measured by CoreKit
# itself (fast, bounded) in Go. This only READS; nothing is changed here.
$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'

function U($d) { if ($d) { try { return [int64]([DateTimeOffset]$d).ToUnixTimeSeconds() } catch { return 0 } } return 0 }

# Where a classic program lives: its recorded folder, else the folder of its icon/uninstaller.
function LocFrom($e) {
    $l = ([string]$e.InstallLocation).Trim().Trim('"')
    if ($l) { return $l.TrimEnd('\') }
    foreach ($s in @([string]$e.DisplayIcon, [string]$e.UninstallString)) {
        if (-not $s) { continue }
        $t = $s.Trim()
        if ($t -match '^"([^"]+)"') { $t = $Matches[1] }
        elseif ($t -match '^([A-Za-z]:\\[^,]*?\.(exe|ico|dll))') { $t = $Matches[1] }
        $t = ($t -split ',')[0].Trim('"')
        if ($t -match '^[A-Za-z]:\\' -and $t -notmatch '(?i)\\Windows\\(Installer|System32)|msiexec') {
            try { return (Split-Path $t -Parent) } catch {}
        }
    }
    return ''
}

$apps = New-Object System.Collections.ArrayList
$seen = @{}

# --- classic desktop programs from the Uninstall registry keys ---
$keys = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
)
foreach ($k in $keys) {
    foreach ($e in Get-ItemProperty $k) {
        $name = [string]$e.DisplayName
        if (-not $name) { continue }
        $sysc = ([int]$e.SystemComponent -eq 1)                        # hidden system pieces: listed, never removable
        if ($e.ParentKeyName -or $e.ParentDisplayName) { continue }    # updates/sub-entries
        if ($e.ReleaseType -match 'Update|Hotfix|Security Update') { continue }
        if ($name -match '^(KB\d{6,}|Update for|Security Update|Hotfix)') { continue }
        $uninst = [string]$e.QuietUninstallString
        $quiet = $true
        if (-not $uninst) { $uninst = [string]$e.UninstallString; $quiet = $false }
        $msi = $false
        if ($e.WindowsInstaller -eq 1 -or $uninst -match 'msiexec') { $msi = $true }
        $key = ($name + '|' + [string]$e.DisplayVersion).ToLower()
        if ($seen[$key]) { continue }
        $seen[$key] = $true
        [void]$apps.Add([ordered]@{
                id        = ($e.PSChildName + '').Trim()
                name      = $name
                pub       = [string]$e.Publisher
                ver       = [string]$e.DisplayVersion
                size      = [int64]([int64]$e.EstimatedSize * 1024)   # EstimatedSize is in KB
                installed = $(if ($e.InstallDate -match '^\d{8}$') { U ([datetime]::ParseExact($e.InstallDate, 'yyyyMMdd', $null)) } else { 0 })
                loc       = (LocFrom $e)
                system    = $sysc
                uninstall = $uninst
                quiet     = $quiet
                source    = 'program'
                kind      = $(if ($msi) { 'msi' } else { 'exe' })
            })
    }
}

# --- Microsoft Store / UWP apps (so they can be listed and removed too) ---
foreach ($p in Get-AppxPackage) {
    $nm = [string]$p.Name
    if (-not $nm) { continue }
    $loc = [string]$p.InstallLocation
    $sz = 0
    [void]$apps.Add([ordered]@{
            id        = [string]$p.PackageFullName
            name      = $nm
            pub       = [string]$p.Publisher
            ver       = [string]$p.Version
            size      = $sz
            installed = 0
            loc       = $loc
            uninstall = ''
            quiet     = $true
            source    = 'store'
            kind      = 'appx'
            family    = [string]$p.PackageFamilyName
            nonremovable = [bool]$p.NonRemovable
            system    = ([bool]$p.IsFramework -or [string]$p.SignatureKind -eq 'System')
        })
}

# --- hibernation state ---
$hiberOn = $false
try { $hiberOn = ((powercfg /a) -join "`n") -notmatch 'Hibernation has not been enabled' -and (Test-Path "$env:SystemDrive\hiberfil.sys") } catch {}

"R|" + ([ordered]@{ apps = $apps; hiberOn = $hiberOn; osDrive = $env:SystemDrive } | ConvertTo-Json -Depth 6 -Compress)
