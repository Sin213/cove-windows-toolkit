
$leftovers = @()

# Build search terms from the program name + publisher. Generic vendor/OS words
# (e.g. "Microsoft", "Windows", "Intel") must NOT become search terms - they would
# match core OS folders/keys/services and offer them for deletion.
$generic = @('microsoft','windows','intel','google','nvidia','amd','realtek','common','program','programs','corporation','corp','inc','llc','ltd','gmbh','system','systems','update','updater','app','apps','data','user','default','driver','drivers','software','technologies','technology','solutions','x64','x86','win32','win64','the')
$terms = @($name)
if ($publisher -and $publisher -ne $name -and ($generic -notcontains $publisher.ToLower())) { $terms += $publisher }
$firstWord = ($name -split '\s')[0]
if ($firstWord.Length -ge 4 -and $firstWord -ne $name -and ($generic -notcontains $firstWord.ToLower())) { $terms += $firstWord }

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

# --- Safety net: never offer to remove protected Windows components, even if a
# term happened to match one (e.g. Defender services run from ProgramData, so the
# %SystemRoot% guard alone misses them). ---
$protSvc = @('windefend','wdnissvc','mdcoresvc','sense','wscsvc','securityhealthservice','wdfilter','wdboot','webthreatdefsvc','mpssvc','wuauserv','bits','cryptsvc','trustedinstaller','msiserver','winmgmt','eventlog','schedule','dnscache','nsi','dcomlaunch','rpcss','lanmanserver','lanmanworkstation','wlansvc','dhcp','dot3svc','winhttpautoproxysvc','sysmain','spooler','samss','netlogon','gpsvc','profsvc')
$protDir = @("$env:ProgramData\Microsoft","$env:LOCALAPPDATA\Microsoft","$env:APPDATA\Microsoft","$env:ProgramFiles\Common Files","${env:ProgramFiles(x86)}\Common Files","$env:ProgramFiles\Windows Defender","$env:ProgramFiles\WindowsApps","$env:ProgramData\Package Cache","$env:SystemRoot","$env:ProgramData\Microsoft\Windows Defender","$env:ProgramData\Microsoft\Windows","$env:LOCALAPPDATA\Packages") | ForEach-Object { $_.TrimEnd('\').ToLower() }
$protReg = @('hklm\software\microsoft','hklm\software\wow6432node\microsoft','hkcu\software\microsoft','hklm\software\windows','hklm\software\wow6432node\windows','hklm\software\policies','hkcu\software\policies','hklm\software\classes','hkcu\software\classes')
function Test-Protected($l) {
    switch ($l.category) {
        'Service' {
            $svc = (($l.path -replace '^Service: ','') -replace ' \(.*$','').Trim().ToLower()
            return ($protSvc -contains $svc)
        }
        'Registry' { return ($protReg -contains $l.path.TrimEnd('\').ToLower()) }
        default {
            $pl = $l.path.TrimEnd('\').ToLower()
            return ($protDir -contains $pl)
        }
    }
}
$deduped = @($deduped | Where-Object { -not (Test-Protected $_) })

# $deduped holds hashtables, whose keys Measure-Object can't sum; total manually.
$totalSize = [long]0
foreach ($l in $deduped) { $totalSize += [long]$l.size_bytes }

@{
    leftovers = $deduped
    total_size_bytes = [long]$totalSize
} | ConvertTo-Json -Depth 3 -Compress
