$ErrorActionPreference = 'SilentlyContinue'

$os = Get-CimInstance Win32_OperatingSystem
$cs = Get-CimInstance Win32_ComputerSystem
$cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
$bb = Get-CimInstance Win32_BaseBoard
$bios = Get-CimInstance Win32_BIOS
$gpu = @(Get-CimInstance Win32_VideoController)
$mon = @(Get-CimInstance WmiMonitorID -Namespace root\wmi 2>$null)
$disk = @(Get-CimInstance Win32_DiskDrive)
$vol = @(Get-CimInstance Win32_LogicalDisk | Where-Object { $_.DriveType -eq 3 })
$audio = @(Get-CimInstance Win32_SoundDevice)
$net = @(Get-CimInstance Win32_NetworkAdapter | Where-Object { $_.PhysicalAdapter -eq $true })
$netcfg = @(Get-CimInstance Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled -eq $true })
$mem = @(Get-CimInstance Win32_PhysicalMemory)
$memArr = @(Get-CimInstance Win32_PhysicalMemoryArray)

# CPU temperature via MSAcpi_ThermalZoneTemperature (requires admin)
$cpuTemp = $null
try {
    $tz = Get-CimInstance MSAcpi_ThermalZoneTemperature -Namespace root\wmi -ErrorAction Stop | Select-Object -First 1
    if ($tz.CurrentTemperature) {
        $cpuTemp = [math]::Round(($tz.CurrentTemperature - 2732) / 10.0, 1)
    }
} catch {}

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
    $mt = 'HDD'
    if ($d.MediaType -match 'SSD|Solid') { $mt = 'SSD' }
    elseif ($d.Model -match 'NVMe|SSD') { $mt = 'SSD' }
    $iface = ''
    if ($d.InterfaceType) { $iface = $d.InterfaceType }
    if ($d.Model -match 'NVMe') { $iface = 'NVMe' }
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
    $vram = if ($g.Name -and $gpuMem.ContainsKey([string]$g.Name)) { $gpuMem[[string]$g.Name] } else { [long]$g.AdapterRAM }
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
# Fill resolution from VideoController if available
for ($i = 0; $i -lt $gpu.Count -and $i -lt $monArr.Count; $i++) {
    $g = $gpu[$i]
    if ($g.CurrentHorizontalResolution -and $g.CurrentVerticalResolution) {
        $hz = if ($g.CurrentRefreshRate) { "@$($g.CurrentRefreshRate)Hz" } else { '' }
        $monArr[$i].resolution = "$($g.CurrentHorizontalResolution)x$($g.CurrentVerticalResolution)$hz"
    }
}
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
    if ($n.Name -match 'Wi-Fi|Wireless') { $atype = 'Wi-Fi' }
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
$archStr = switch ($cpu.AddressWidth) { 64 { '64-bit' }; 32 { '32-bit' }; default { "$($cpu.AddressWidth)-bit" } }

$result = @{
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
        cores = [int]$cpu.NumberOfCores
        threads = [int]$cpu.NumberOfLogicalProcessors
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
