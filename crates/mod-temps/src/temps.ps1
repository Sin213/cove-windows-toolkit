$ErrorActionPreference = 'SilentlyContinue'

$readings = @()
$warnings = @()

# ── CPU Temperature via ACPI Thermal Zone (requires admin) ──────────
try {
    $zones = Get-CimInstance MSAcpi_ThermalZoneTemperature -Namespace root\wmi -ErrorAction Stop
    foreach ($z in $zones) {
        if ($z.CurrentTemperature -and $z.CurrentTemperature -gt 0) {
            $tempC = [math]::Round(($z.CurrentTemperature - 2732) / 10.0, 1)
            if ($tempC -gt 0 -and $tempC -lt 150) {
                $name = if ($z.InstanceName -match 'CPUZ') { 'CPU Package' }
                        elseif ($z.InstanceName) { $z.InstanceName -replace '\\\\.*$','' -replace '_',' ' }
                        else { 'Thermal Zone' }
                $readings += @{
                    sensor = $name
                    category = 'CPU'
                    temperature_c = $tempC
                    max_c = 100.0
                    critical_c = 105.0
                }
            }
        }
    }
} catch {
    $warnings += 'ACPI thermal zone not accessible (requires admin privileges).'
}

# ── CPU via Open Hardware Monitor / Libre Hardware Monitor WMI ──────
$ohmSensors = @()
try {
    $ohmSensors = @(Get-CimInstance -Namespace root\OpenHardwareMonitor -ClassName Sensor -ErrorAction Stop |
        Where-Object { $_.SensorType -eq 'Temperature' })
} catch {
    try {
        $ohmSensors = @(Get-CimInstance -Namespace root\LibreHardwareMonitor -ClassName Sensor -ErrorAction Stop |
            Where-Object { $_.SensorType -eq 'Temperature' })
    } catch {}
}

if ($ohmSensors.Count -gt 0) {
    # If OHM/LHM is available, it's more accurate -replace ACPI readings
    $readings = @()
    foreach ($s in $ohmSensors) {
        $cat = 'Other'
        if ($s.Parent -match 'cpu|processor' -or $s.Name -match 'CPU|Core') { $cat = 'CPU' }
        elseif ($s.Parent -match 'gpu|video|nvidia|amd|radeon' -or $s.Name -match 'GPU') { $cat = 'GPU' }
        elseif ($s.Parent -match 'hdd|ssd|nvme|disk|storage') { $cat = 'Disk' }

        $maxC = $null
        $critC = $null
        switch ($cat) {
            'CPU'  { $maxC = 100.0; $critC = 105.0 }
            'GPU'  { $maxC = 93.0;  $critC = 100.0 }
            'Disk' { $maxC = 70.0;  $critC = 75.0  }
        }

        $readings += @{
            sensor = $s.Name
            category = $cat
            temperature_c = [math]::Round([double]$s.Value, 1)
            max_c = $maxC
            critical_c = $critC
        }
    }
} else {
    if ($readings.Count -eq 0) {
        $warnings += 'No hardware monitor service detected. Install Libre Hardware Monitor for detailed per-core temps.'
    }
}

# ── GPU Temperature via WMI (NVIDIA) ───────────────────────────────
# Only if we don't already have GPU temps from OHM/LHM
$hasGpu = ($readings | Where-Object { $_.category -eq 'GPU' }).Count -gt 0
if (-not $hasGpu) {
    try {
        $nv = Get-CimInstance -Namespace root\cimv2 -ClassName Win32_VideoController -ErrorAction Stop |
            Select-Object -First 1
        # Try nvidia-smi for NVIDIA GPUs
        $nvSmi = & "nvidia-smi" --query-gpu=temperature.gpu --format=csv,noheader,nounits 2>$null
        if ($LASTEXITCODE -eq 0 -and $nvSmi) {
            $gpuTemp = [double]$nvSmi.Trim()
            $readings += @{
                sensor = if ($nv.Name) { $nv.Name } else { 'GPU' }
                category = 'GPU'
                temperature_c = $gpuTemp
                max_c = 93.0
                critical_c = 100.0
            }
        }
    } catch {}
}

# ── Disk Temperature via SMART (S.M.A.R.T. attribute 194 or MSFT) ──
$hasDisk = ($readings | Where-Object { $_.category -eq 'Disk' }).Count -gt 0
if (-not $hasDisk) {
    try {
        $msftDisks = Get-CimInstance -Namespace root\Microsoft\Windows\Storage -ClassName MSFT_PhysicalDisk -ErrorAction Stop
        foreach ($d in $msftDisks) {
            $tempK = $null
            try {
                $rel = Get-CimInstance -Namespace root\Microsoft\Windows\Storage -ClassName MSFT_StorageReliabilityCounter -ErrorAction Stop |
                    Where-Object { $_.DeviceId -eq $d.DeviceId } | Select-Object -First 1
                if ($rel.Temperature) { $tempK = $rel.Temperature }
            } catch {}

            if ($tempK -and $tempK -gt 0 -and $tempK -lt 150) {
                $readings += @{
                    sensor = if ($d.FriendlyName) { $d.FriendlyName } else { "Disk $($d.DeviceId)" }
                    category = 'Disk'
                    temperature_c = [math]::Round([double]$tempK, 1)
                    max_c = 70.0
                    critical_c = 75.0
                }
            }
        }
    } catch {}
}

$result = @{
    readings = $readings
    warnings = $warnings
}

$result | ConvertTo-Json -Depth 3 -Compress
