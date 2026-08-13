# Third-party notices

Cove Windows Toolkit embeds the following third-party components. They are used
only by the optional CPU temperature feature and are never installed or executed
unless you explicitly ask for them from the Temperatures screen.

## LibreHardwareMonitor

- Bundle: `crates/mod-temps/resources/LibreHardwareMonitor.zip`
- Upstream: https://github.com/LibreHardwareMonitor/LibreHardwareMonitor
- Licence: Mozilla Public License 2.0 (https://www.mozilla.org/MPL/2.0/)

Cove loads `LibreHardwareMonitorLib.dll` to read temperature sensors. The library
is redistributed unmodified. Source for the library is available from the
upstream project above, as required by the MPL.

The bundle also carries the library's own dependencies, redistributed unmodified
under their respective licences:

| Component | Licence |
|-----------|---------|
| HidSharp | Apache-2.0 |
| Aga.Controls (TreeViewAdv) | BSD-3-Clause |
| OxyPlot, OxyPlot.WindowsForms | MIT |
| Microsoft.Win32.TaskScheduler | MIT |
| `Microsoft.Bcl.*`, `System.*` (.NET runtime packages) | MIT |
| BlackSharp.Core, DiskInfoToolkit, RAMSPDToolkit-NDD | See upstream LibreHardwareMonitor release |

## PawnIO

- Bundle: `crates/mod-temps/resources/PawnIO_setup.exe`
- Upstream: https://github.com/namazso/PawnIO.Setup and https://pawnio.eu/

PawnIO is a signed kernel-mode driver that LibreHardwareMonitor uses to read CPU
registers. Cove redistributes the vendor's signed installer unmodified and runs
it only when you click "Enable CPU sensors" and confirm the prompt. No
diagnostic, scan, or cleanup path installs it. Once installed it is a normal
Windows driver and can be removed through Apps & Features. The same installer is
what the vendor publishes for unattended installs, and it is invoked with the
vendor's documented `-install -silent` switches.
