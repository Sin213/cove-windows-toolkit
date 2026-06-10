pub fn generate_html_report(title: &str, sections: &[(&str, &str)]) -> String {
    let mut html = format!(r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>{title}</title>
<style>
body {{ font-family: 'Segoe UI', sans-serif; max-width: 860px; margin: 0 auto; padding: 24px; background: #0f1117; color: #d4d4d8; }}
h1 {{ color: #60a5fa; border-bottom: 2px solid #60a5fa; padding-bottom: 12px; font-size: 22px; }}
h2 {{ color: #a78bfa; font-size: 16px; margin: 0 0 8px 0; }}
.section {{ background: #1c1e26; border-radius: 8px; padding: 16px; margin: 14px 0; border: 1px solid #2a2d38; }}
.section pre {{ white-space: pre-wrap; word-break: break-word; font-size: 12px; color: #a1a1aa; margin: 0; line-height: 1.6; }}
.badge {{ display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; margin-left: 8px; }}
.badge-ok {{ background: #052e16; color: #4ade80; }}
.badge-warn {{ background: #422006; color: #fbbf24; }}
.badge-crit {{ background: #450a0a; color: #f87171; }}
.meta {{ font-size: 12px; color: #71717a; margin-bottom: 16px; }}
.footer {{ text-align: center; color: #52525b; margin-top: 32px; font-size: 12px; padding-top: 16px; border-top: 1px solid #2a2d38; }}
table {{ width: 100%; border-collapse: collapse; font-size: 12px; }}
th {{ text-align: left; color: #71717a; padding: 6px 8px; border-bottom: 1px solid #2a2d38; font-weight: 500; }}
td {{ padding: 6px 8px; border-bottom: 1px solid #1c1e26; }}
</style>
</head>
<body>
<h1>{title}</h1>
<div class="meta">Generated on {{TIMESTAMP}} by Cove Windows Toolkit</div>
"#);

    let timestamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
    html = html.replace("{TIMESTAMP}", &timestamp);

    for (heading, content) in sections {
        let content_html = content
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('\n', "<br>");
        html.push_str(&format!(
            "<div class=\"section\"><h2>{}</h2><pre>{}</pre></div>\n",
            heading, content_html
        ));
    }

    html.push_str("<div class=\"footer\">Cove Windows Toolkit &mdash; Confidential</div>\n</body></html>");
    html
}

pub fn generate_full_report(data: &FullReportData) -> String {
    let mut sections = Vec::new();

    // Health
    sections.push(("System Health".to_string(), format!(
        "Score: {}/100\n{}",
        data.health_score,
        data.health_findings.join("\n")
    )));

    // Drivers
    sections.push(("Drivers".to_string(), format!(
        "Total: {}  |  Unsigned: {}  |  Outdated: {}\n{}",
        data.driver_total, data.driver_unsigned, data.driver_outdated,
        if data.driver_issues.is_empty() { "No issues found.".to_string() } else { data.driver_issues.join("\n") }
    )));

    // Events
    sections.push(("Event Logs (System)".to_string(), format!(
        "Critical: {}  |  Error: {}  |  Warning: {}\n{}",
        data.event_critical, data.event_error, data.event_warning,
        if data.recent_events.is_empty() { "No recent critical/error events.".to_string() } else { data.recent_events.join("\n") }
    )));

    // Updates
    sections.push(("Windows Update".to_string(), format!(
        "Service: {}  |  Pending: {}\n{}",
        data.update_service, data.pending_updates.len(),
        if data.pending_updates.is_empty() { "System is up to date.".to_string() } else { data.pending_updates.join("\n") }
    )));

    // Temperatures
    if !data.temperatures.is_empty() {
        sections.push(("Temperatures".to_string(), data.temperatures.join("\n")));
    }

    // Disk Health
    if !data.disk_health.is_empty() {
        sections.push(("Disk Health".to_string(), data.disk_health.join("\n")));
    }

    // Runtimes
    if !data.runtimes.is_empty() {
        sections.push(("Installed Runtimes".to_string(), data.runtimes.join("\n")));
    }

    // Security
    sections.push(("Security".to_string(), data.security_summary.clone()));

    // Activation
    sections.push(("Windows Activation".to_string(), data.activation.clone()));

    let refs: Vec<(&str, &str)> = sections.iter().map(|(h, c)| (h.as_str(), c.as_str())).collect();
    generate_html_report("System Diagnostic Report", &refs)
}

pub struct FullReportData {
    pub health_score: u64,
    pub health_findings: Vec<String>,
    pub driver_total: u64,
    pub driver_unsigned: u64,
    pub driver_outdated: u64,
    pub driver_issues: Vec<String>,
    pub event_critical: u64,
    pub event_error: u64,
    pub event_warning: u64,
    pub recent_events: Vec<String>,
    pub update_service: String,
    pub pending_updates: Vec<String>,
    pub temperatures: Vec<String>,
    pub disk_health: Vec<String>,
    pub runtimes: Vec<String>,
    pub security_summary: String,
    pub activation: String,
}
