
$leftovers = @()

# Build search terms from program name (split into meaningful words)
$terms = @($name)
# Add publisher if different from name
if ($publisher -and $publisher -ne $name) { $terms += $publisher }
# Add first word if multi-word (e.g., "SignalRGB" from "SignalRGB Pro")
$firstWord = ($name -split '\s')[0]
if ($firstWord.Length -ge 4 -and $firstWord -ne $name) { $terms += $firstWord }

function Get-FolderSize($path) {
    if (-not (Test-Path $path)) { return 0 }
    try {
        (Get-ChildItem $path -Recurse -Force -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum
    } catch { 0 }
}

# ── File system locations ──────────────────────────────────────────
$fsDirs = @(
    "$env:ProgramFiles",
    "${env:ProgramFiles(x86)}",
    "$env:ProgramData",
    "$env:LOCALAPPDATA",
    "$env:APPDATA",
    "$env:LOCALAPPDATA\Low",
    "$env:TEMP",
    "$env:SystemRoot\Temp"
)

foreach ($baseDir in $fsDirs) {
    if (-not $baseDir -or -not (Test-Path $baseDir)) { continue }
    foreach ($term in $terms) {
        $matches = Get-ChildItem $baseDir -Directory -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match [regex]::Escape($term) }
        foreach ($m in $matches) {
            $size = Get-FolderSize $m.FullName
            $leftovers += @{
                path = $m.FullName
                category = 'Folder'
                size_bytes = [long]$size
            }
        }
    }
}

# Check install location directly if it still exists
if ($installLoc -and (Test-Path $installLoc)) {
    $already = $leftovers | Where-Object { $_.path -eq $installLoc }
    if (-not $already) {
        $size = Get-FolderSize $installLoc
        $leftovers += @{
            path = $installLoc
            category = 'Folder'
            size_bytes = [long]$size
        }
    }
}

# ── Registry locations ─────────────────────────────────────────────
$regRoots = @(
    'HKCU:\Software',
    'HKLM:\SOFTWARE',
    'HKLM:\SOFTWARE\WOW6432Node'
)

foreach ($root in $regRoots) {
    foreach ($term in $terms) {
        $matches = Get-ChildItem $root -ErrorAction SilentlyContinue |
            Where-Object { $_.PSChildName -match [regex]::Escape($term) }
        foreach ($m in $matches) {
            $regPath = $m.Name -replace '^HKEY_LOCAL_MACHINE','HKLM' -replace '^HKEY_CURRENT_USER','HKCU'
            $leftovers += @{
                path = $regPath
                category = 'Registry'
                size_bytes = 0
            }
        }
    }
}

# Check if original uninstall registry key still exists
if ($regKey) {
    $testPath = $regKey -replace '^HKLM\\','HKLM:\' -replace '^HKCU\\','HKCU:\'
    if (Test-Path $testPath) {
        $leftovers += @{
            path = $regKey
            category = 'Registry'
            size_bytes = 0
        }
    }
}

# ── Services ───────────────────────────────────────────────────────
foreach ($term in $terms) {
    $svcs = Get-Service -ErrorAction SilentlyContinue |
        Where-Object { $_.ServiceName -match [regex]::Escape($term) -or $_.DisplayName -match [regex]::Escape($term) }
    foreach ($s in $svcs) {
        $leftovers += @{
            path = "Service: $($s.ServiceName) ($($s.DisplayName))"
            category = 'Service'
            size_bytes = 0
        }
    }
}

# ── Scheduled Tasks ────────────────────────────────────────────────
foreach ($term in $terms) {
    $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue |
        Where-Object { $_.TaskName -match [regex]::Escape($term) -or $_.TaskPath -match [regex]::Escape($term) }
    foreach ($t in $tasks) {
        $leftovers += @{
            path = "Task: $($t.TaskPath)$($t.TaskName)"
            category = 'Scheduled Task'
            size_bytes = 0
        }
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
