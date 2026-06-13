pub mod types;

pub fn silent_cmd(program: &str) -> std::process::Command {
    let mut cmd = std::process::Command::new(program);
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x08000000); // CREATE_NO_WINDOW
    }
    cmd
}

/// Prelude prepended to every PowerShell `-Command` script so its stdout is
/// emitted as UTF-8 regardless of the machine's active code page. Without this,
/// non-English Windows (CP-1252, GBK, Shift-JIS, ...) and accented usernames
/// produce mojibake that breaks JSON/text parsing. PowerShell 5.1 safe.
pub const PS_PRELUDE: &str =
    "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8;$OutputEncoding=[System.Text.Encoding]::UTF8;";

/// Build a `powershell` command pre-seeded with `-NoProfile -NonInteractive
/// -Command`, with [`PS_PRELUDE`] prepended to `script` so output is UTF-8 on
/// any locale. Callers add `.output()`/`.spawn()` as before.
///
/// For the rare call site that needs extra flags before `-Command` (e.g.
/// `-ExecutionPolicy Bypass`), build the command manually and prepend
/// [`PS_PRELUDE`] to the script string instead.
pub fn powershell(script: &str) -> std::process::Command {
    let mut cmd = silent_cmd("powershell");
    let full = format!("{PS_PRELUDE}{script}");
    cmd.args(["-NoProfile", "-NonInteractive", "-Command", &full]);
    cmd
}
