# Fails when `cargo audit` reports a maintenance warning that is not on the
# reviewed approved list. Plain `cargo audit` only exits nonzero for published
# vulnerabilities, so a newly introduced unmaintained/unsound advisory would
# otherwise pass CI silently.
#
# Vulnerabilities are still gated by the separate plain `cargo audit` step.

$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
$approvedFile = Join-Path $PSScriptRoot 'audit-approved-warnings.txt'

$approved = Get-Content -LiteralPath $approvedFile |
    ForEach-Object { ($_ -split '#')[0].Trim() } |
    Where-Object { $_ -ne '' }

Push-Location $root
try {
    $raw = & cargo audit --json
}
finally {
    Pop-Location
}

if (-not $raw) {
    Write-Error 'cargo audit produced no JSON output.'
    exit 1
}

$report = ($raw -join "`n") | ConvertFrom-Json

$found = @()
foreach ($kind in $report.warnings.PSObject.Properties) {
    foreach ($warning in $kind.Value) {
        $found += [pscustomobject]@{
            Id      = $warning.advisory.id
            Kind    = $kind.Name
            Package = $warning.package.name
        }
    }
}

$unexpected = $found | Where-Object { $approved -notcontains $_.Id }
$stale = $approved | Where-Object { $found.Id -notcontains $_ }

Write-Output "cargo audit warnings: $($found.Count) (approved list: $($approved.Count))"

if ($stale) {
    Write-Output "Approved warnings no longer present (remove from the list): $($stale -join ', ')"
}

if ($unexpected) {
    foreach ($warning in $unexpected) {
        Write-Output "UNAPPROVED $($warning.Kind) warning: $($warning.Id) ($($warning.Package))"
    }
    Write-Error 'New undocumented cargo audit warnings block release. Review them and update scripts/audit-approved-warnings.txt and the internal audit/SECURITY.md policy.'
    exit 1
}

Write-Output 'All cargo audit warnings are on the reviewed approved list.'
