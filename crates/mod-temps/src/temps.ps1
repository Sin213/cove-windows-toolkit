$ErrorActionPreference = 'SilentlyContinue'

$readings = @()
$warnings = @()

# ── Try Libre Hardware Monitor / Open Hardware Monitor WMI first ───
$ohmSensors = @()
try {
    $ohmSensors = @(Get-CimInstance -Namespace root\LibreHardwareMonitor -ClassName Sensor -ErrorAction Stop |
        Where-Object { $_.SensorType -eq 'Temperature' })
} catch {
    try {
        $ohmSensors = @(Get-CimInstance -Namespace root\OpenHardwareMonitor -ClassName Sensor -ErrorAction Stop |
            Where-Object { $_.SensorType -eq 'Temperature' })
    } catch {}
}

if ($ohmSensors.Count -gt 0) {
    foreach ($s in $ohmSensors) {
        $cat = 'Other'
        if ($s.Parent -match 'cpu|processor|amd|intel' -or $s.Name -match 'CPU|Core|CCD|Tctl|Tdie|Package') { $cat = 'CPU' }
        elseif ($s.Parent -match 'gpu|video|nvidia|amd|radeon' -or $s.Name -match 'GPU|Hot Spot|Junction') { $cat = 'GPU' }
        elseif ($s.Parent -match 'hdd|ssd|nvme|disk|storage' -or $s.Name -match 'Drive|Assembly') { $cat = 'Disk' }

        $maxC = $null; $critC = $null
        switch ($cat) {
            'CPU'  { $maxC = 95.0; $critC = 105.0 }
            'GPU'  { $maxC = 93.0; $critC = 100.0 }
            'Disk' { $maxC = 70.0; $critC = 75.0  }
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
    # ── CPU: Try thermal zone performance counters (works without LHM) ─
    try {
        $zones = Get-CimInstance Win32_PerfFormattedData_Counters_ThermalZoneInformation -ErrorAction Stop
        foreach ($z in $zones) {
            if ($z.Temperature -and $z.Temperature -gt 0 -and $z.Temperature -lt 150) {
                $tempC = [math]::Round($z.Temperature - 273.15, 1)
                if ($tempC -gt 0 -and $tempC -lt 120) {
                    $readings += @{
                        sensor = if ($z.Name) { $z.Name -replace '\\\\.*$','' -replace '_',' ' } else { 'Thermal Zone' }
                        category = 'CPU'
                        temperature_c = $tempC
                        max_c = 95.0
                        critical_c = 105.0
                    }
                }
            }
        }
    } catch {}

    # ── CPU: ACPI fallback (admin required) ─────────────────────────────
    if (($readings | Where-Object { $_.category -eq 'CPU' }).Count -eq 0) {
        try {
            $zones = Get-CimInstance MSAcpi_ThermalZoneTemperature -Namespace root\wmi -ErrorAction Stop
            foreach ($z in $zones) {
                if ($z.CurrentTemperature -and $z.CurrentTemperature -gt 0) {
                    $tempC = [math]::Round(($z.CurrentTemperature - 2732) / 10.0, 1)
                    if ($tempC -gt 0 -and $tempC -lt 150) {
                        $readings += @{
                            sensor = 'CPU Package'
                            category = 'CPU'
                            temperature_c = $tempC
                            max_c = 95.0
                            critical_c = 105.0
                        }
                    }
                }
            }
        } catch {}
    }

    # ── GPU: nvidia-smi for NVIDIA ──────────────────────────────────────
    try {
        $nvSmi = & "nvidia-smi" --query-gpu=temperature.gpu,name --format=csv,noheader,nounits 2>$null
        if ($LASTEXITCODE -eq 0 -and $nvSmi) {
            foreach ($line in $nvSmi -split "`n") {
                $parts = $line.Trim() -split ',\s*'
                if ($parts.Count -ge 2) {
                    $readings += @{
                        sensor = $parts[1].Trim()
                        category = 'GPU'
                        temperature_c = [math]::Round([double]$parts[0].Trim(), 1)
                        max_c = 93.0
                        critical_c = 100.0
                    }
                }
            }
        }
    } catch {}

    # ── GPU: AMD via Win32_VideoController + registry ───────────────────
    $hasGpu = ($readings | Where-Object { $_.category -eq 'GPU' }).Count -gt 0
    if (-not $hasGpu) {
        try {
            $gpu = Get-CimInstance Win32_VideoController -ErrorAction Stop | Where-Object { $_.Status -eq 'OK' -and $_.CurrentHorizontalResolution -gt 0 } | Select-Object -First 1
            if ($gpu.Name -match 'AMD|Radeon') {
                # Try rocm-smi
                $rocm = & "C:\Windows\System32\AMD\rocm-smi.exe" --showtemp --json 2>$null
                if ($LASTEXITCODE -eq 0 -and $rocm) {
                    $json = $rocm | ConvertFrom-Json
                    $temp = $json.card0.'Temperature (Sensor edge) (C)'
                    if ($temp) {
                        $readings += @{
                            sensor = $gpu.Name
                            category = 'GPU'
                            temperature_c = [math]::Round([double]$temp, 1)
                            max_c = 93.0
                            critical_c = 100.0
                        }
                    }
                }
            }
        } catch {}
    }

    # ── Disk: via StorageReliabilityCounter ──────────────────────────────
    try {
        Get-PhysicalDisk -ErrorAction Stop | ForEach-Object {
            $disk = $_
            try {
                $rel = $disk | Get-StorageReliabilityCounter -ErrorAction Stop
                if ($rel.Temperature -and $rel.Temperature -gt 0 -and $rel.Temperature -lt 100) {
                    $readings += @{
                        sensor = if ($disk.FriendlyName) { $disk.FriendlyName } else { "Disk $($disk.DeviceId)" }
                        category = 'Disk'
                        temperature_c = [math]::Round([double]$rel.Temperature, 1)
                        max_c = 70.0
                        critical_c = 75.0
                    }
                }
            } catch {}
        }
    } catch {}

    if ($readings.Count -eq 0) {
        $warnings += 'No temperature sensors detected. Install Libre Hardware Monitor for full sensor access.'
    }
}

$result = @{
    readings = $readings
    warnings = $warnings
}

$result | ConvertTo-Json -Depth 3 -Compress
