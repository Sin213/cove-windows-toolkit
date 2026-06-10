$ErrorActionPreference = 'SilentlyContinue'

$paths = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
)

$programs = @()
$seen = @{}

foreach ($path in $paths) {
    $items = Get-ItemProperty $path -ErrorAction SilentlyContinue
    foreach ($item in $items) {
        $name = $item.DisplayName
        if (-not $name -or $name.Length -lt 2) { continue }
        if ($seen[$name]) { continue }
        $seen[$name] = $true

        $sizeBytes = 0
        if ($item.EstimatedSize) { $sizeBytes = [long]$item.EstimatedSize * 1024 }

        $installDate = ''
        if ($item.InstallDate) {
            $d = $item.InstallDate
            if ($d.Length -eq 8) {
                $installDate = "$($d.Substring(0,4))-$($d.Substring(4,2))-$($d.Substring(6,2))"
            } else {
                $installDate = $d
            }
        }

        $isSystem = $false
        $sysPublishers = @('Microsoft Corporation', 'Microsoft', 'NVIDIA', 'Intel', 'Intel(R)')
        if ($item.SystemComponent -eq 1) { $isSystem = $true }
        elseif ($item.Publisher -and $sysPublishers -contains $item.Publisher -and $name -match 'Visual C\+\+|\.NET|MSVC|Driver|Runtime') { $isSystem = $true }
        elseif (-not $item.UninstallString) { $isSystem = $true }

        $regKey = if ($item.PSPath) {
            $item.PSPath -replace '^Microsoft\.PowerShell\.Core\\Registry::', '' -replace '^HKEY_LOCAL_MACHINE', 'HKLM' -replace '^HKEY_CURRENT_USER', 'HKCU'
        } else { '' }

        $programs += @{
            name = $name
            publisher = if ($item.Publisher) { $item.Publisher } else { '' }
            version = if ($item.DisplayVersion) { $item.DisplayVersion } else { '' }
            install_date = $installDate
            size_bytes = $sizeBytes
            uninstall_string = if ($item.UninstallString) { $item.UninstallString } else { '' }
            quiet_uninstall_string = if ($item.QuietUninstallString) { $item.QuietUninstallString } else { '' }
            install_location = if ($item.InstallLocation) { $item.InstallLocation.TrimEnd('\') } else { '' }
            registry_key = $regKey
            is_system = $isSystem
        }
    }
}

$programs | Sort-Object { $_.name } | ConvertTo-Json -Depth 3 -Compress
