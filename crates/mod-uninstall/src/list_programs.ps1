$ErrorActionPreference = 'Stop'

$roots = @(
    @{ path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'; required = $true },
    # This view is absent on some architectures, but if present it must be read
    # completely or the caller could mistake a partial inventory for removals.
    @{ path = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'; required = $false },
    # Per-user registrations are optional and are never executable by Cove's
    # elevated uninstaller policy, but remain visible when the hive is present.
    @{ path = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'; required = $false }
)

$programs = @()

foreach ($root in $roots) {
    $exists = Test-Path -LiteralPath $root.path -ErrorAction Stop
    if (-not $exists) {
        if ($root.required) { throw "Required uninstall registry root is missing: $($root.path)" }
        continue
    }
    # `-ErrorAction Stop` is deliberate: returning a successful partial list
    # makes snapshot/diff report installed applications as removed.
    $items = Get-ChildItem -LiteralPath $root.path -ErrorAction Stop |
        ForEach-Object { Get-ItemProperty -LiteralPath $_.PSPath -ErrorAction Stop }
    foreach ($item in $items) {
        $name = $item.DisplayName
        if (-not $name -or $name.Length -lt 2) { continue }
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

        # Registry identity, not display name, distinguishes per-user/machine,
        # x86/x64, and side-by-side installations with the same friendly name.
        if (-not $regKey) { continue }

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
            can_uninstall = $false
            uninstall_reason = ''
        }
    }
}

ConvertTo-Json -InputObject @($programs | Sort-Object { $_.name }) -Depth 3 -Compress
