# CoreKit :: Activity Log - restore one deleted file from the Recycle Bin.
# Called by CoreKit.exe with:  -token "<drive>|<SID-folder>|$I<name>"
# Reads the Recycle Bin's own metadata ($I file) for the original path and moves
# the data ($R file) back. Only ever touches files inside $Recycle.Bin.

$ErrorActionPreference = 'SilentlyContinue'
try { [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false) } catch {}
function Out-Line([string]$s) { [Console]::Out.WriteLine($s); [Console]::Out.Flush() }
function Fail([string]$m) { Out-Line ('R|' + ([pscustomobject]@{ error = $m } | ConvertTo-Json -Compress)); exit 0 }

$token = ''
for ($i = 0; $i -lt $args.Count; $i++) { if ($args[$i] -eq '-token' -and $i + 1 -lt $args.Count) { $token = $args[$i + 1] } }
$parts = $token -split '\|'
if ($parts.Count -ne 3) { Fail 'Bad restore token.' }
$drive = $parts[0]; $sid = $parts[1]; $iname = $parts[2]

if ($drive -notmatch '^[A-Za-z]$') { Fail 'Bad drive.' }
if ($sid -notmatch '^S-[0-9\-]+$') { Fail 'Bad recycle folder.' }
if ($iname -notmatch '^\$I[A-Za-z0-9][A-Za-z0-9\.]*$') { Fail 'Bad item.' }

$rb   = $drive + ':\$Recycle.Bin\' + $sid
$meta = Join-Path $rb $iname
$rname = '$R' + $iname.Substring(2)
$data = Join-Path $rb $rname

# both must sit directly inside this recycle-bin folder
foreach ($p in @($meta, $data)) {
    $full = [IO.Path]::GetFullPath($p)
    if (-not $full.StartsWith(([IO.Path]::GetFullPath($rb) + '\'), [StringComparison]::OrdinalIgnoreCase)) { Fail 'Path check failed.' }
}
if (-not (Test-Path -LiteralPath $meta)) { Fail 'This item is no longer in the Recycle Bin.' }
if (-not (Test-Path -LiteralPath $data)) { Fail 'The deleted file''s data is gone (it may have been emptied).' }

try {
    $bytes = [IO.File]::ReadAllBytes($meta)
    if ($bytes.Length -lt 24) { Fail 'Unreadable item.' }
    $ver = [BitConverter]::ToInt64($bytes, 0)
    if ($ver -ge 2) {
        $len = [BitConverter]::ToInt32($bytes, 24)
        $orig = [Text.Encoding]::Unicode.GetString($bytes, 28, ($len - 1) * 2)
    } else {
        $orig = [Text.Encoding]::Unicode.GetString($bytes, 24, 520).Trim([char]0)
    }
} catch { Fail 'Could not read the item details.' }

if (-not $orig) { Fail 'Original location unknown.' }
$dir = Split-Path $orig -Parent
try { if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null } } catch { Fail 'The original folder could not be recreated.' }

$target = $orig
if (Test-Path -LiteralPath $target) {
    $base = [IO.Path]::GetFileNameWithoutExtension($orig)
    $ext  = [IO.Path]::GetExtension($orig)
    $target = Join-Path $dir ($base + ' (restored ' + (Get-Date -Format 'yyyy-MM-dd HHmmss') + ')' + $ext)
}

try {
    Move-Item -LiteralPath $data -Destination $target -Force -ErrorAction Stop
    Remove-Item -LiteralPath $meta -Force -ErrorAction SilentlyContinue
} catch { Fail ('Restore failed: ' + $_.Exception.Message) }

Out-Line ('R|' + ([pscustomobject]@{ ok = $true; path = $dir; file = $target } | ConvertTo-Json -Compress))
