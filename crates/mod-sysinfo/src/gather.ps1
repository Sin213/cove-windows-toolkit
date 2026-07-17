$ErrorActionPreference = 'Continue'
$errors = @()
function Get-CoveCim([string]$class, [string]$namespace = 'root\cimv2') {
    try { @(Get-CimInstance -ClassName $class -Namespace $namespace -ErrorAction Stop) }
    catch { $script:errors += "${class}: $($_.Exception.Message)"; @() }
}

$os = Get-CoveCim Win32_OperatingSystem | Select-Object -First 1
$cs = Get-CoveCim Win32_ComputerSystem | Select-Object -First 1
$cpus = @(Get-CoveCim Win32_Processor); $cpu = $cpus | Select-Object -First 1
$bb = Get-CoveCim Win32_BaseBoard | Select-Object -First 1
$bios = Get-CoveCim Win32_BIOS | Select-Object -First 1
$gpu = @(Get-CoveCim Win32_VideoController)
$mon = @(Get-CoveCim WmiMonitorID 'root\wmi')
$disk = @(Get-CoveCim Win32_DiskDrive)
$physical = @(try { Get-PhysicalDisk -ErrorAction Stop } catch { $errors += "PhysicalDisk: $($_.Exception.Message)" })
$vol = @(Get-CoveCim Win32_LogicalDisk | Where-Object { $_.DriveType -eq 3 })
$audio = @(Get-CoveCim Win32_SoundDevice)
$net = @(Get-CoveCim Win32_NetworkAdapter | Where-Object { $_.PhysicalAdapter -eq $true })
$netcfg = @(Get-CoveCim Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled -eq $true })
$mem = @(Get-CoveCim Win32_PhysicalMemory)
$memArr = @(Get-CoveCim Win32_PhysicalMemoryArray | Where-Object { $_.Use -eq 3 })

# ACPI thermal zones are not CPU-package sensors, so do not label one as CPU.
$cpuTemp = $null

# Map partition letters to disk indices
$partMap = @{}
Get-CimInstance Win32_DiskPartition | ForEach-Object {
    $part = $_
    Get-CimInstance -Query "ASSOCIATORS OF {Win32_DiskPartition.DeviceID='$($part.DeviceID)'} WHERE AssocClass=Win32_LogicalDiskToPartition" | ForEach-Object {
        $partMap[$_.DeviceID] = $part.DiskIndex
    }
}

# Build storage array
$storageArr = @()
foreach ($d in $disk) {
    $parts = @()
    foreach ($v in $vol) {
        if ($partMap[$v.DeviceID] -eq $d.Index) {
            $parts += @{
                letter = $v.DeviceID
                label = if ($v.VolumeName) { $v.VolumeName } else { '' }
                size_bytes = [long]$v.Size
                free_bytes = [long]$v.FreeSpace
                filesystem = if ($v.FileSystem) { $v.FileSystem } else { '' }
            }
        }
    }
    $pd = $physical | Where-Object { $_.FriendlyName -eq $d.Model -or ($_.SerialNumber -and $_.SerialNumber.Trim() -eq $d.SerialNumber.Trim()) } | Select-Object -First 1
    $mt = if ($pd -and $pd.MediaType) { [string]$pd.MediaType } else { 'Unknown' }
    $iface = if ($pd -and $pd.BusType) { [string]$pd.BusType } elseif ($d.InterfaceType) { [string]$d.InterfaceType } else { 'Unknown' }
    $storageArr += @{
        model = if ($d.Model) { $d.Model.Trim() } else { 'Unknown' }
        interface_type = $iface
        media_type = $mt
        size_bytes = [long]$d.Size
        partitions = $parts
        status = if ($d.Status) { $d.Status } else { 'Unknown' }
    }
}

# GPU array
# Win32_VideoController.AdapterRAM is a signed 32-bit field (caps at ~4GB).
# The real VRAM is the 64-bit HardwareInformation.qwMemorySize in the display
# class registry; build a name -> bytes lookup keyed by DriverDesc.
$gpuMem = @{}
Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}' -ErrorAction SilentlyContinue | ForEach-Object {
    $p = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
    if ($p.DriverDesc -and $p.'HardwareInformation.qwMemorySize') {
        $gpuMem[[string]$p.DriverDesc] = [long]$p.'HardwareInformation.qwMemorySize'
    }
}

$gpuArr = @()
foreach ($g in $gpu) {
    $vram = if ($g.Name -and $gpuMem.ContainsKey([string]$g.Name)) { $gpuMem[[string]$g.Name] } elseif ([uint64]$g.AdapterRAM -lt 4294967295) { [uint64]$g.AdapterRAM } else { 0 }
    $gpuArr += @{
        name = if ($g.Name) { $g.Name } else { 'Unknown' }
        driver_version = if ($g.DriverVersion) { $g.DriverVersion } else { '' }
        vram_bytes = [long]$vram
        status = if ($g.Status) { $g.Status } else { 'Unknown' }
    }
}

# Monitor array
$monArr = @()
foreach ($m in $mon) {
    $mfr = if ($m.ManufacturerName) { [string]::new([char[]]($m.ManufacturerName | Where-Object { $_ -ne 0 })) } else { '' }
    $mdl = if ($m.UserFriendlyName) { [string]::new([char[]]($m.UserFriendlyName | Where-Object { $_ -ne 0 })) } else { 'Monitor' }
    $name = if ($mfr) { "$mfr $mdl" } else { $mdl }
    $monArr += @{ name = $name; resolution = '' }
}
# Do not pair monitor identities to unrelated video-controller array indices.
if ($monArr.Count -eq 0 -and $gpu.Count -gt 0) {
    foreach ($g in $gpu) {
        if ($g.CurrentHorizontalResolution) {
            $hz = if ($g.CurrentRefreshRate) { "@$($g.CurrentRefreshRate)Hz" } else { '' }
            $monArr += @{ name = 'Display'; resolution = "$($g.CurrentHorizontalResolution)x$($g.CurrentVerticalResolution)$hz" }
        }
    }
}

# Audio
$audioArr = @()
foreach ($a in $audio) {
    $audioArr += @{
        name = if ($a.Name) { $a.Name } else { 'Unknown' }
        status = if ($a.Status) { $a.Status } else { 'Unknown' }
    }
}

# Network
$netArr = @()
foreach ($n in $net) {
    $cfg = $netcfg | Where-Object { $_.Index -eq $n.Index }
    $ipAddr = ''
    if ($cfg.IPAddress) { $ipAddr = ($cfg.IPAddress | Select-Object -First 1) }
    $spd = ''
    if ($n.Speed) {
        $s = [long]$n.Speed
        if ($s -ge 1000000000) { $spd = "$([math]::Round($s/1e9,1)) Gbps" }
        elseif ($s -ge 1000000) { $spd = "$([math]::Round($s/1e6,0)) Mbps" }
        else { $spd = "$s bps" }
    }
    $atype = if ($n.AdapterType) { $n.AdapterType } else { '' }
    if ($n.Name -match 'Wi-Fi|Wireless|WLAN|802\.11' -or $atype -match 'Wireless|802\.11') { $atype = 'Wi-Fi' }
    $st = if ($n.NetConnectionStatus -eq 2) { 'Connected' } else { 'Disconnected' }
    $netArr += @{
        name = if ($n.Name) { $n.Name } else { 'Unknown' }
        adapter_type = $atype
        mac = if ($n.MACAddress) { $n.MACAddress } else { '' }
        speed = $spd
        ip = $ipAddr
        status = $st
    }
}

# Effective module speed: ConfiguredClockSpeed is the ACTUAL running speed
# (reflects an active XMP/EXPO profile); Speed often reports only the JEDEC base
# rating (e.g. DDR5-6000 running at 6000 but Speed=4800). Prefer the former and
# fall back to Speed when ConfiguredClockSpeed is missing/zero.
function Get-ModuleSpeed($m) {
    if ($m.ConfiguredClockSpeed -and [int]$m.ConfiguredClockSpeed -gt 0) { [int]$m.ConfiguredClockSpeed }
    else { [int]$m.Speed }
}

# Installed RAM = sum of the physical module capacities. Win32_ComputerSystem's
# TotalPhysicalMemory reports OS-VISIBLE memory (installed minus hardware-reserved),
# so 32 GB installed shows as ~31.2 GB. Fall back to it only if SMBIOS lists nothing.
$ramTotalBytes = [long](($mem | Measure-Object -Property Capacity -Sum).Sum)
if (-not $ramTotalBytes -or $ramTotalBytes -le 0) { $ramTotalBytes = [long]$cs.TotalPhysicalMemory }

# RAM modules
$memModules = @()
foreach ($m in $mem) {
    $memModules += @{
        capacity_bytes = [long]$m.Capacity
        speed_mhz = Get-ModuleSpeed $m
        manufacturer = if ($m.Manufacturer) { $m.Manufacturer.Trim() } else { '' }
        part_number = if ($m.PartNumber) { $m.PartNumber.Trim() } else { '' }
        slot = if ($m.DeviceLocator) { $m.DeviceLocator } else { '' }
    }
}

# Determine RAM type
$memType = ''
if ($mem.Count -gt 0 -and $mem[0].SMBIOSMemoryType) {
    switch ($mem[0].SMBIOSMemoryType) {
        20 { $memType = 'DDR' }
        21 { $memType = 'DDR2' }
        24 { $memType = 'DDR3' }
        26 { $memType = 'DDR4' }
        34 { $memType = 'DDR5' }
        default { $memType = "Type $($mem[0].SMBIOSMemoryType)" }
    }
}

$slotsTotal = 0
foreach ($ma in $memArr) { $slotsTotal += $ma.MemoryDevices }
if ($slotsTotal -eq 0) { $slotsTotal = $mem.Count }

# Arch
$archStr = if ($os.OSArchitecture) { [string]$os.OSArchitecture } else { switch ([int]$cpu.Architecture) { 9 {'x64'} 12 {'ARM64'} 0 {'x86'} default {'Unknown'} } }

$result = @{
    complete = ($errors.Count -eq 0)
    errors = @($errors)
    os = @{
        name = $os.Caption -replace 'Microsoft ',''
        version = $(if ($dv = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name DisplayVersion -ErrorAction SilentlyContinue).DisplayVersion) { $dv } else { (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name ReleaseId -ErrorAction SilentlyContinue).ReleaseId })
        build = "$($os.BuildNumber).$((Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name UBR -ErrorAction SilentlyContinue).UBR)"
        arch = $archStr
        install_date = if ($os.InstallDate) { $os.InstallDate.ToString('yyyy-MM-dd') } else { '' }
        last_boot = if ($os.LastBootUpTime) { $os.LastBootUpTime.ToString('o') } else { '' }
    }
    cpu = @{
        name = if ($cpu.Name) { $cpu.Name.Trim() } else { '' }
        cores = [int](($cpus | Measure-Object NumberOfCores -Sum).Sum)
        threads = [int](($cpus | Measure-Object NumberOfLogicalProcessors -Sum).Sum)
        base_clock_mhz = $(if ($bm = (Get-ItemProperty 'HKLM:\HARDWARE\DESCRIPTION\System\CentralProcessor\0' -Name '~MHz' -ErrorAction SilentlyContinue).'~MHz') { [int]$bm } else { [int]$cpu.MaxClockSpeed })
        max_clock_mhz = [int]$cpu.MaxClockSpeed
        architecture = $archStr
        temperature_c = $cpuTemp
    }
    ram = @{
        total_bytes = $ramTotalBytes
        available_bytes = [long]($os.FreePhysicalMemory * 1024)
        speed_mhz = if ($mem.Count -gt 0) { Get-ModuleSpeed $mem[0] } else { 0 }
        slots_used = $mem.Count
        slots_total = $slotsTotal
        ram_type = $memType
        modules = $memModules
    }
    motherboard = @{
        manufacturer = if ($bb.Manufacturer) { $bb.Manufacturer } else { '' }
        product = if ($bb.Product) { $bb.Product } else { '' }
        serial = if ($bb.SerialNumber) { $bb.SerialNumber } else { '' }
        bios_vendor = if ($bios.Manufacturer) { $bios.Manufacturer } else { '' }
        bios_version = if ($bios.SMBIOSBIOSVersion) { $bios.SMBIOSBIOSVersion } else { '' }
        bios_date = if ($bios.ReleaseDate) { $bios.ReleaseDate.ToString('yyyy-MM-dd') } else { '' }
    }
    graphics = $gpuArr
    monitors = $monArr
    storage = $storageArr
    audio = $audioArr
    network = $netArr
}

$result | ConvertTo-Json -Depth 5 -Compress
