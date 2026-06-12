
$leftovers = @()

# Build search terms from the program name + publisher.
$terms = @($name)
if ($publisher -and $publisher -ne $name) { $terms += $publisher }
$firstWord = ($name -split '\s')[0]
if ($firstWord.Length -ge 4 -and $firstWord -ne $name) { $terms += $firstWord }

# Match on WORD BOUNDARIES so a term like "Cove" matches "cove-nexus" but not
# unrelated words like "Auto-Discovery" (dis-COVE-ry) - matching that loosely
# would offer to delete core Windows services.
$patterns = @()
foreach ($t in $terms) { if ($t) { $patterns += ('\b' + [regex]::Escape($t) + '\b') } }
function Test-Term([string]$text) {
    if (-not $text) { return $false }
    foreach ($p in $patterns) { if ($text -match $p) { return $true } }
    return $false
}

function Get-FolderSize($path) {
    if (-not (Test-Path $path)) { return 0 }
    try {
        $sum = (Get-ChildItem $path -Recurse -Force -File -ErrorAction SilentlyContinue |
            Measure-Object -Property Length -Sum -ErrorAction SilentlyContinue).Sum
        if ($sum) { $sum } else { 0 }
    } catch { 0 }
}

# ── File system locations ──────────────────────────────────────────
$fsDirs = @(
    "$env:ProgramFiles",
    "${env:ProgramFiles(x86)}",
    "$env:ProgramData",
    "$env:LOCALAPPDATA",
    "$env:LOCALAPPDATA\Programs",   # per-user installs (Electron/Squirrel apps)
    "$env:APPDATA",
    "$env:LOCALAPPDATA\Low",
    "$env:TEMP",
    "$env:SystemRoot\Temp"
)

foreach ($baseDir in $fsDirs) {
    if (-not $baseDir -or -not (Test-Path $baseDir)) { continue }
    $hits = Get-ChildItem $baseDir -Directory -ErrorAction SilentlyContinue |
        Where-Object { Test-Term $_.Name }
    foreach ($m in $hits) {
        $size = Get-FolderSize $m.FullName
        $leftovers += @{ path = $m.FullName; category = 'Folder'; size_bytes = [long]$size }
    }
}

# Check the install location directly if it still exists.
if ($installLoc -and (Test-Path $installLoc)) {
    $already = $leftovers | Where-Object { $_.path -eq $installLoc }
    if (-not $already) {
        $size = Get-FolderSize $installLoc
        $leftovers += @{ path = $installLoc; category = 'Folder'; size_bytes = [long]$size }
    }
}

# ── Registry locations ─────────────────────────────────────────────
$regRoots = @('HKCU:\Software', 'HKLM:\SOFTWARE', 'HKLM:\SOFTWARE\WOW6432Node')
foreach ($root in $regRoots) {
    $hits = Get-ChildItem $root -ErrorAction SilentlyContinue |
        Where-Object { Test-Term $_.PSChildName }
    foreach ($m in $hits) {
        $regPath = $m.Name -replace '^HKEY_LOCAL_MACHINE','HKLM' -replace '^HKEY_CURRENT_USER','HKCU'
        $leftovers += @{ path = $regPath; category = 'Registry'; size_bytes = 0 }
    }
}

# Check if the original uninstall registry key still exists.
if ($regKey) {
    $testPath = $regKey -replace '^HKLM\\','HKLM:\' -replace '^HKCU\\','HKCU:\'
    if (Test-Path $testPath) {
        $leftovers += @{ path = $regKey; category = 'Registry'; size_bytes = 0 }
    }
}

# ── Services ───────────────────────────────────────────────────────
# Use Win32_Service for the binary path; NEVER flag a service that runs from
# %SystemRoot% (those are Windows/system services), and require a word-boundary
# name match.
$winRoot = [regex]::Escape($env:SystemRoot)
foreach ($s in (Get-CimInstance Win32_Service -ErrorAction SilentlyContinue)) {
    if ($s.PathName -and $s.PathName -match $winRoot) { continue }
    if ((Test-Term $s.Name) -or (Test-Term $s.DisplayName)) {
        $leftovers += @{ path = "Service: $($s.Name) ($($s.DisplayName))"; category = 'Service'; size_bytes = 0 }
    }
}

# ── Scheduled Tasks ────────────────────────────────────────────────
foreach ($t in (Get-ScheduledTask -ErrorAction SilentlyContinue)) {
    if ($t.TaskPath -like '\Microsoft\*') { continue }   # never touch Windows tasks
    if ((Test-Term $t.TaskName) -or (Test-Term $t.TaskPath)) {
        $leftovers += @{ path = "Task: $($t.TaskPath)$($t.TaskName)"; category = 'Scheduled Task'; size_bytes = 0 }
    }
}

# Deduplicate
$unique = @{}
$deduped = @()
foreach ($l in $leftovers) {
    if (-not $unique[$l.path]) {
        $unique[$l.path] = $true
        $deduped += $l
    }
}

# $deduped holds hashtables, whose keys Measure-Object can't sum; total manually.
$totalSize = [long]0
foreach ($l in $deduped) { $totalSize += [long]$l.size_bytes }

@{
    leftovers = $deduped
    total_size_bytes = [long]$totalSize
} | ConvertTo-Json -Depth 3 -Compress
