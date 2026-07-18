//! Maps SMBIOS motherboard (manufacturer, product) strings to verified
//! product-page URLs. v1 is exact-override only: SMBIOS text is never
//! interpolated into a URL, so every returned link is a hand-verified
//! HTTPS address on a trusted manufacturer domain. Per-manufacturer URL
//! builders (MSI/Gigabyte/ASRock) can be added later behind the same
//! entry point without touching callers.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Manufacturer {
    Asus,
    // future: Msi, Gigabyte, AsRock
}

/// Placeholder strings BIOS vendors ship instead of real values.
/// Compared case-insensitively against the normalized string.
const PLACEHOLDERS: &[&str] = &[
    "",
    "to be filled by o.e.m.",
    "to be filled by oem",
    "default string",
    "none",
    "n/a",
    "na",
    "unknown",
    "not applicable",
    "not specified",
    "system product name",
    "system manufacturer",
    "base board product",
    "oem",
    "invalid",
    "x.x",
];

/// (manufacturer, normalized-UPPERCASE model key, verified https URL)
const PRODUCT_URL_OVERRIDES: &[(Manufacturer, &str, &str)] = &[(
    Manufacturer::Asus,
    "PRIME B650M-A AX6 II",
    "https://www.asus.com/motherboards-components/motherboards/prime/prime-b650m-a-ax6-ii/",
)];

/// Resolve a verified product-page URL for a motherboard.
/// `None` means "no verified link" and the UI renders plain text.
pub(crate) fn motherboard_product_url(manufacturer: &str, product: &str) -> Option<String> {
    let manufacturer = normalize(manufacturer);
    let product = normalize(product);
    if is_placeholder(&manufacturer) || is_placeholder(&product) {
        return None;
    }
    let mfr = canonical_manufacturer(&manufacturer)?;
    let key = product.to_ascii_uppercase();
    PRODUCT_URL_OVERRIDES
        .iter()
        .find(|(m, k, _)| *m == mfr && *k == key)
        .map(|(_, _, url)| (*url).to_string())
    // Future hook: on a lookup miss, dispatch to a per-manufacturer URL
    // builder here (overrides always take precedence).
}

/// Trim and collapse all internal whitespace runs to a single space.
fn normalize(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn is_placeholder(normalized: &str) -> bool {
    PLACEHOLDERS
        .iter()
        .any(|p| normalized.eq_ignore_ascii_case(p))
}

fn canonical_manufacturer(raw: &str) -> Option<Manufacturer> {
    let upper = raw.to_ascii_uppercase();
    let upper = upper.trim_end_matches(['.', ',']).trim();
    match upper {
        "ASUS"
        | "ASUSTEK"
        | "ASUSTEK COMPUTER"
        | "ASUSTEK COMPUTER INC"
        | "ASUSTEK COMPUTER INCORPORATED" => Some(Manufacturer::Asus),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PRIME_URL: &str =
        "https://www.asus.com/motherboards-components/motherboards/prime/prime-b650m-a-ax6-ii/";

    #[test]
    fn resolves_required_asus_prime_board() {
        assert_eq!(
            motherboard_product_url("ASUS", "PRIME B650M-A AX6 II").as_deref(),
            Some(PRIME_URL)
        );
    }

    #[test]
    fn resolves_asustek_full_alias_with_period() {
        assert_eq!(
            motherboard_product_url("ASUSTeK COMPUTER INC.", "PRIME B650M-A AX6 II").as_deref(),
            Some(PRIME_URL)
        );
    }

    #[test]
    fn resolves_asustek_alias_without_period() {
        assert_eq!(
            motherboard_product_url("ASUSTeK COMPUTER INC", "PRIME B650M-A AX6 II").as_deref(),
            Some(PRIME_URL)
        );
    }

    #[test]
    fn resolves_lowercase_and_mixed_case() {
        assert_eq!(
            motherboard_product_url("asus", "prime b650m-a ax6 ii").as_deref(),
            Some(PRIME_URL)
        );
    }

    #[test]
    fn normalizes_repeated_and_edge_whitespace() {
        assert_eq!(
            motherboard_product_url("  ASUS ", "PRIME  B650M-A \t AX6  II ").as_deref(),
            Some(PRIME_URL)
        );
    }

    #[test]
    fn rejects_placeholder_products() {
        for product in [
            "",
            "To be filled by O.E.M.",
            "Default string",
            "N/A",
            "System Product Name",
            "Unknown",
        ] {
            assert_eq!(
                motherboard_product_url("ASUS", product),
                None,
                "{product:?}"
            );
        }
    }

    #[test]
    fn rejects_placeholder_manufacturer() {
        assert_eq!(
            motherboard_product_url("To Be Filled By O.E.M.", "PRIME B650M-A AX6 II"),
            None
        );
    }

    #[test]
    fn unknown_manufacturer_returns_none() {
        assert_eq!(
            motherboard_product_url(
                "Micro-Star International Co., Ltd.",
                "MAG B650 TOMAHAWK WIFI"
            ),
            None
        );
    }

    #[test]
    fn known_manufacturer_unknown_model_returns_none() {
        assert_eq!(motherboard_product_url("ASUS", "ROG STRIX Z690-A"), None);
    }

    #[test]
    fn override_table_urls_pass_open_url_rules() {
        // Mirrors the validation gate in the open_url command so the table
        // can never ship a link the app refuses to open.
        for (_, _, url) in PRODUCT_URL_OVERRIDES {
            assert!(url.starts_with("https://"), "{url}");
            assert!(!url.chars().any(|c| c.is_control()), "{url}");
            assert!(
                !url.chars()
                    .any(|c| matches!(c, '&' | '|' | '<' | '>' | '^' | '`')),
                "{url}"
            );
        }
    }
}
