# Cross-Machine Smoke Test

Use this to validate a build on a machine **other than the developer's** - the class
of failures behind "works for me but not for others." Prioritize machines that differ
from the dev box:

- **Non-English Windows** (German/French/Spanish/Chinese/Japanese display language) - the highest-value test, since this is where encoding + locale bugs surface.
- **A VM** (no thermal sensor, no dedicated GPU, no SMBIOS serial).
- **A laptop** (battery, Wi-Fi instead of Ethernet).
- **Windows 10** (if you develop on 11) and a **Home N / LTSC** edition if available.
- An account whose **username contains a non-ASCII character** (e.g. `José`, `Müller`).

Run the **Setup** or **Portable** exe elevated (accept the UAC prompt). Walk every panel
and confirm real data appears - not blanks, not garbage, not obviously-fake values.

## What to check per panel

| Panel | Pass criteria | Was a known cross-machine risk |
|---|---|---|
| **System Info** | Manufacturer/model/BIOS/serial render correctly - **no mojibake** (`MÃ¼ller`, `æ–‡å­—`). RAM size & speed populated. | Encoding (UTF-8) |
| **Temperatures** | CPU temp shows after the PawnIO driver installs (first run, elevated). On a VM with no sensor, shows an honest "n/a" - not a crash or a fake number. | Driver dep, WMI null |
| **Disk Health** | SMART rows show real model/serial, "Healthy" status, integer wear/temp. | (mostly invariant) |
| **Network Diagnostics** | Primary adapter detected (Ethernet **or** Wi-Fi). On Wi-Fi, **signal % and dBm are real**, not `-100 dBm`. | Locale (`ifOperStatus`, signal `%`) |
| **Power** | Display-off / sleep / disk-sleep timeouts show the **real minute values**, not all `0`. | Locale (powercfg hex) |
| **Windows Update** | Component store shows Healthy/Needs Repair/**Unknown** - a healthy non-English machine must NOT show a false "Needs Repair". | Locale (DISM text) |
| **Bloatware** | Installed AppX apps are correctly detected as installed (case-insensitive). | Locale/casing |
| **Privacy** | DiagTrack / telemetry rows show a real start-mode, or **"NotAvailable"** on Home N / LTSC - not blank. | Edition (LTSC/N) |
| **Runtimes** | .NET / VC++ / Java / DirectX list populates. On a GPU-less VM the scan **completes within ~15s** (dxdiag no longer hangs). | Hang risk |
| **Drivers / Event Log / BSOD / Security** | Lists populate; device/file/process names with accents render cleanly. | Encoding |
| **SFC / DISM repair** | Output text is readable (not NUL-interleaved); success/failure reported correctly via exit code. | Encoding/locale |
| **Set DNS** | After applying, DNS is actually set (re-open the panel / `ipconfig /all`) - "success" must mean it really applied, not a no-op. | Locale (`ifOperStatus`) |

## Quick automated probe (run in PowerShell on the test machine)

```powershell
# Confirm UTF-8 round-trips (the core Phase-1 fix). Should print accented text cleanly.
powershell -NoProfile -NonInteractive -Command "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8;Write-Output 'cafe Muller 90% test'"

# Confirm an 'Up' adapter is found by the locale-safe field used by the app.
Get-NetAdapter | Where-Object { $_.ifOperStatus -eq 'Up' } | Select-Object Name, ifOperStatus
```

## Red flags that mean a regression

- Any `MÃ¼ller` / `æ–‡` style mojibake in any field.
- Power timeouts all reading `0`, or Wi-Fi signal reading `-100 dBm`.
- A healthy machine reporting component store "Needs Repair".
- The Runtimes scan hanging for more than ~20 seconds.
- "Set DNS" reporting success but `ipconfig /all` shows DNS unchanged.
