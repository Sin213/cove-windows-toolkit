# Leftover discovery is implemented in Rust and is deliberately limited to the
# exact registered HKLM InstallLocation. This file remains as a tombstone so an
# older include/caller cannot silently reintroduce display-name heuristics.
@{ leftovers = @(); total_size_bytes = [long]0 } | ConvertTo-Json -Depth 3 -Compress
