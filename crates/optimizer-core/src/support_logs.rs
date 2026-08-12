//! Bounded, sanitized support-log excerpts shared by the desktop app.

use serde::Serialize;
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

const MAX_SUPPORT_LOG_FILES: usize = 7;

#[derive(Debug, Serialize)]
pub struct LogExcerpt {
    pub text: String,
    pub file_count: usize,
    pub bytes_read: u64,
    pub truncated: bool,
}

/// Read the newest matching regular log files without ever loading more than
/// `max_bytes`. Rolling log names end in an ISO date, so filename order is
/// chronological and deterministic even when filesystem mtimes are coarse.
pub fn read_recent_logs(
    log_dir: &Path,
    filename_prefix: &str,
    max_bytes: u64,
) -> Result<LogExcerpt, String> {
    if max_bytes == 0 {
        return Err("The support-log byte limit must be greater than zero.".into());
    }

    let entries = fs::read_dir(log_dir)
        .map_err(|error| format!("Could not read the log directory: {error}"))?;
    let mut files = Vec::with_capacity(MAX_SUPPORT_LOG_FILES);
    let mut matching_files = 0usize;
    for entry in entries.flatten() {
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if !file_type.is_file() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        if !is_rolling_log_name(&name, filename_prefix) {
            continue;
        }
        matching_files = matching_files.saturating_add(1);
        files.push((name, entry.path()));
        files.sort_by(|left, right| right.0.cmp(&left.0));
        files.truncate(MAX_SUPPORT_LOG_FILES);
    }

    let mut remaining = max_bytes;
    let mut truncated = matching_files > files.len();
    let mut selected = Vec::new();
    for (name, path) in files {
        let header = format!("--- {name} ---\n");
        let required_overhead = header.len() as u64 + 1;
        if remaining < required_overhead {
            truncated = true;
            break;
        }

        let mut file = match File::open(&path) {
            Ok(file) => file,
            Err(_) => {
                truncated = true;
                continue;
            }
        };
        let length = match file.metadata() {
            Ok(metadata) => metadata.len(),
            Err(_) => {
                truncated = true;
                continue;
            }
        };
        let content_limit = remaining - required_overhead;
        let to_read = length.min(content_limit).min(i64::MAX as u64);
        if length > to_read {
            truncated = true;
            if file.seek(SeekFrom::End(-(to_read as i64))).is_err() {
                continue;
            }
        }

        let mut bytes = Vec::new();
        if file.take(to_read).read_to_end(&mut bytes).is_err() {
            truncated = true;
            continue;
        }
        let mut contents = String::from_utf8_lossy(&bytes).into_owned();
        let decoded_limit = usize::try_from(content_limit).unwrap_or(usize::MAX);
        if contents.len() > decoded_limit {
            truncate_utf8_bytes(&mut contents, decoded_limit);
            truncated = true;
        }
        let mut section = header;
        section.push_str(&contents);
        if !section.ends_with('\n') {
            section.push('\n');
        }
        remaining = remaining.saturating_sub(section.len() as u64);
        selected.push(section);
    }

    selected.reverse();
    let file_count = selected.len();
    let text = selected.concat();
    let bytes_read = text.len() as u64;

    Ok(LogExcerpt {
        text,
        file_count,
        bytes_read,
        truncated,
    })
}

fn is_rolling_log_name(name: &str, filename_prefix: &str) -> bool {
    let Some(date) = name
        .strip_prefix(filename_prefix)
        .and_then(|suffix| suffix.strip_prefix('.'))
    else {
        return false;
    };
    let bytes = date.as_bytes();
    bytes.len() == 10
        && bytes[4] == b'-'
        && bytes[7] == b'-'
        && bytes
            .iter()
            .enumerate()
            .all(|(index, byte)| matches!(index, 4 | 7) || byte.is_ascii_digit())
}

fn truncate_utf8_bytes(value: &mut String, limit: usize) {
    if value.len() <= limit {
        return;
    }
    let mut boundary = limit;
    while boundary > 0 && !value.is_char_boundary(boundary) {
        boundary -= 1;
    }
    value.truncate(boundary);
}

/// Remove personal paths and common credential/URL shapes before logs are
/// displayed, copied, or saved. This is deliberately a final boundary even
/// though UI-originated messages are also sanitized before they are written.
pub fn sanitize_support_text(input: &str, user_profile: Option<&Path>) -> String {
    let mut output = input.to_string();
    if let Some(profile) = user_profile {
        let profile = profile.to_string_lossy();
        if !profile.is_empty() {
            output = replace_ascii_case_insensitive(&output, &profile, "%USERPROFILE%");
        }
    }
    output = redact_windows_profiles(&output);
    output = redact_urls(&output);
    output = redact_bearer_tokens(&output);
    for key in [
        "token",
        "access_token",
        "refresh_token",
        "password",
        "passwd",
        "passkey",
        "secret",
        "api_key",
        "api-key",
        "apikey",
        "x-api-key",
        "authorization",
        "auth",
        "cookie",
        "set-cookie",
        "session_id",
        "sessionid",
    ] {
        output = redact_assignment(&output, key);
    }
    output
}

fn replace_ascii_case_insensitive(input: &str, needle: &str, replacement: &str) -> String {
    if needle.is_empty() {
        return input.to_string();
    }
    let lower_input = input.to_ascii_lowercase();
    let lower_needle = needle.to_ascii_lowercase();
    let mut output = String::with_capacity(input.len());
    let mut offset = 0;
    while let Some(relative) = lower_input[offset..].find(&lower_needle) {
        let start = offset + relative;
        let end = start + needle.len();
        output.push_str(&input[offset..start]);
        output.push_str(replacement);
        offset = end;
    }
    output.push_str(&input[offset..]);
    output
}

fn redact_windows_profiles(input: &str) -> String {
    let mut output = String::with_capacity(input.len());
    let lower = input.to_ascii_lowercase();
    let marker = ":\\users\\";
    let mut offset = 0;

    while let Some(relative) = lower[offset..].find(marker) {
        let colon = offset + relative;
        if colon == 0 || !input.as_bytes()[colon - 1].is_ascii_alphabetic() {
            let end = colon + marker.len();
            output.push_str(&input[offset..end]);
            offset = end;
            continue;
        }
        let start = colon - 1;
        let username_start = colon + marker.len();
        let username_end = input.as_bytes()[username_start..]
            .iter()
            .position(|byte| {
                matches!(
                    *byte,
                    b'\\' | b'/' | b'\r' | b'\n' | b'\t' | b' ' | b'"' | b'\''
                )
            })
            .map(|relative_end| username_start + relative_end)
            .unwrap_or(input.len());
        output.push_str(&input[offset..start]);
        output.push_str("%USERPROFILE%");
        offset = username_end;
    }
    output.push_str(&input[offset..]);
    output
}

fn redact_urls(input: &str) -> String {
    let lower = input.to_ascii_lowercase();
    let mut output = String::with_capacity(input.len());
    let mut offset = 0;

    while offset < input.len() {
        let Some((relative, replacement)) = [
            ("https://", "https://<redacted>"),
            ("http://", "http://<redacted>"),
            ("ftp://", "ftp://<redacted>"),
            ("file://", "file://<redacted>"),
            ("magnet:?", "magnet:?<redacted>"),
        ]
        .into_iter()
        .filter_map(|(marker, replacement)| {
            lower[offset..]
                .find(marker)
                .map(|relative| (relative, replacement))
        })
        .min_by_key(|item| item.0) else {
            break;
        };
        let start = offset + relative;
        let end = input.as_bytes()[start..]
            .iter()
            .position(|byte| {
                matches!(
                    *byte,
                    b' ' | b'\r' | b'\n' | b'\t' | b'"' | b'\'' | b'<' | b'>'
                )
            })
            .map(|relative_end| start + relative_end)
            .unwrap_or(input.len());
        output.push_str(&input[offset..start]);
        output.push_str(replacement);
        offset = end;
    }
    output.push_str(&input[offset..]);
    output
}

fn redact_bearer_tokens(input: &str) -> String {
    redact_value_after_marker(input, "bearer ", "Bearer <redacted>")
}

fn redact_assignment(input: &str, key: &str) -> String {
    let lower = input.to_ascii_lowercase();
    let lower_key = key.to_ascii_lowercase();
    let bytes = input.as_bytes();
    let mut output = String::with_capacity(input.len());
    let mut copied_through = 0;
    let mut search_from = 0;

    while let Some(relative) = lower[search_from..].find(&lower_key) {
        let key_start = search_from + relative;
        let key_end = key_start + key.len();
        search_from = key_end;

        if key_start > 0
            && matches!(bytes[key_start - 1], b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'_')
        {
            continue;
        }

        let mut cursor = key_end;
        if bytes
            .get(cursor)
            .is_some_and(|byte| matches!(*byte, b'\'' | b'"'))
        {
            cursor += 1;
        }
        while bytes
            .get(cursor)
            .is_some_and(|byte| matches!(*byte, b' ' | b'\t'))
        {
            cursor += 1;
        }
        if !bytes
            .get(cursor)
            .is_some_and(|byte| matches!(*byte, b'=' | b':'))
        {
            continue;
        }
        cursor += 1;
        while bytes
            .get(cursor)
            .is_some_and(|byte| matches!(*byte, b' ' | b'\t'))
        {
            cursor += 1;
        }
        let quote = bytes
            .get(cursor)
            .copied()
            .filter(|byte| matches!(byte, b'\'' | b'"'));
        if quote.is_some() {
            cursor += 1;
        }
        let value_start = cursor;
        let value_end = bytes[value_start..]
            .iter()
            .position(|byte| {
                quote.map_or_else(
                    || {
                        matches!(
                            *byte,
                            b' ' | b'\r' | b'\n' | b'\t' | b',' | b';' | b'}' | b']'
                        )
                    },
                    |quote| *byte == quote,
                )
            })
            .map(|relative_end| value_start + relative_end)
            .unwrap_or(input.len());
        if value_start == value_end {
            continue;
        }

        output.push_str(&input[copied_through..value_start]);
        output.push_str("<redacted>");
        copied_through = value_end;
        search_from = value_end;
    }
    output.push_str(&input[copied_through..]);
    output
}

fn redact_value_after_marker(input: &str, marker: &str, replacement: &str) -> String {
    let lower = input.to_ascii_lowercase();
    let lower_marker = marker.to_ascii_lowercase();
    let mut output = String::with_capacity(input.len());
    let mut offset = 0;

    while let Some(relative) = lower[offset..].find(&lower_marker) {
        let start = offset + relative;
        let value_start = start + marker.len();
        let value_end = input.as_bytes()[value_start..]
            .iter()
            .position(|byte| {
                matches!(
                    *byte,
                    b' ' | b'\r' | b'\n' | b'\t' | b',' | b';' | b'"' | b'\''
                )
            })
            .map(|relative_end| value_start + relative_end)
            .unwrap_or(input.len());
        output.push_str(&input[offset..start]);
        output.push_str(replacement);
        offset = value_end;
    }
    output.push_str(&input[offset..]);
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let path =
                std::env::temp_dir().join(format!("cove-support-logs-{}", uuid::Uuid::new_v4()));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn support_text_redacts_paths_urls_and_credentials() {
        let input = concat!(
            "C:\\Users\\Alice\\AppData\\Local https://example.com/a?token=abc ",
            "Authorization:Bearer SECRET cookie=sessionid token=hunter2 ",
            "\"access_token\" : \"json-secret\" password = spaced-secret ",
            "x-api-key:'header-secret' session_id=session-secret ",
            "ftp://example.test/private file:///C:/Users/Alice/private magnet:?xt=private"
        );
        let clean = sanitize_support_text(input, Some(Path::new(r"C:\Users\Alice")));

        assert!(!clean.contains("Alice"));
        assert!(!clean.contains("example.com"));
        assert!(!clean.contains("SECRET"));
        assert!(!clean.contains("sessionid"));
        assert!(!clean.contains("hunter2"));
        assert!(!clean.contains("json-secret"));
        assert!(!clean.contains("spaced-secret"));
        assert!(!clean.contains("header-secret"));
        assert!(!clean.contains("session-secret"));
        assert!(!clean.contains("example.test"));
        assert!(!clean.contains("xt=private"));
        assert!(clean.contains("%USERPROFILE%"));
        assert!(clean.contains("https://<redacted>"));
        assert!(clean.contains("file://<redacted>"));
    }

    #[test]
    fn recent_logs_are_newest_first_and_bounded() {
        let directory = TestDirectory::new();
        fs::write(directory.0.join("cove.log.2026-08-10"), "old\n").unwrap();
        fs::write(directory.0.join("cove.log.2026-08-11"), "newest-entry\n").unwrap();
        fs::write(
            directory.0.join("cove.log-private.2026-08-12"),
            "not really a log\n",
        )
        .unwrap();
        fs::write(directory.0.join("not-a-log.txt"), "ignore me\n").unwrap();

        let excerpt = read_recent_logs(&directory.0, "cove.log", 45).unwrap();

        assert_eq!(excerpt.file_count, 1);
        assert_eq!(excerpt.bytes_read, excerpt.text.len() as u64);
        assert!(excerpt.bytes_read <= 45);
        assert!(excerpt.truncated);
        assert!(excerpt.text.contains("newest-entry"));
        assert!(!excerpt.text.contains("old"));
        assert!(!excerpt.text.contains("ignore"));
        assert!(!excerpt.text.contains("not really"));
    }

    #[test]
    fn recent_logs_cap_the_number_of_files() {
        let directory = TestDirectory::new();
        for day in 1..=10 {
            fs::write(
                directory.0.join(format!("cove.log.2026-07-{day:02}")),
                format!("day-{day}\n"),
            )
            .unwrap();
        }

        let excerpt = read_recent_logs(&directory.0, "cove.log", 16 * 1024).unwrap();

        assert_eq!(excerpt.file_count, MAX_SUPPORT_LOG_FILES);
        assert!(excerpt.truncated);
        assert!(excerpt.text.contains("day-10"));
        assert!(excerpt.text.contains("day-4"));
        assert!(!excerpt.text.contains("day-3\n"));
    }
}
