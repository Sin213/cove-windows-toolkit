//! Maps SMBIOS motherboard (manufacturer, product) strings to verified
//! product-page URLs. v1 is exact-override only: SMBIOS text is never
//! interpolated into a URL, so every returned link is a hand-verified
//! HTTPS address on a trusted manufacturer domain. Per-manufacturer URL
//! builders can be added later behind the same entry point without
//! touching callers.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Manufacturer {
    Asus,
    Msi,
    Gigabyte,
    AsRock,
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
const PRODUCT_URL_OVERRIDES: &[(Manufacturer, &str, &str)] = &[
    (
        Manufacturer::Asus,
        "PRIME B650M-A AX6 II",
        "https://www.asus.com/motherboards-components/motherboards/prime/prime-b650m-a-ax6-ii/",
    ),
    (
        Manufacturer::Asus,
        "ROG CROSSHAIR VIII DARK HERO",
        "https://rog.asus.com/us/motherboards/rog-crosshair/rog-crosshair-viii-dark-hero-model/",
    ),
    (
        Manufacturer::Asus,
        "ROG STRIX X670E-E GAMING WIFI",
        "https://rog.asus.com/us/motherboards/rog-strix/rog-strix-x670e-e-gaming-wifi-model/",
    ),
    (
        Manufacturer::Asus,
        "ROG CROSSHAIR X670E EXTREME",
        "https://rog.asus.com/motherboards/rog-crosshair/rog-crosshair-x670e-extreme-model/",
    ),
    (
        Manufacturer::Asus,
        "ROG STRIX Z790-E GAMING WIFI II",
        "https://rog.asus.com/motherboards/rog-strix/rog-strix-z790-e-gaming-wifi-ii/",
    ),
    (
        Manufacturer::Asus,
        "ROG MAXIMUS Z790 HERO",
        "https://rog.asus.com/motherboards/rog-maximus/rog-maximus-z790-hero-model/",
    ),
    (
        Manufacturer::Asus,
        "PRIME Z790-P",
        "https://www.asus.com/motherboards-components/motherboards/prime/prime-z790-p/",
    ),
    (
        Manufacturer::Asus,
        "PRIME X670-P",
        "https://www.asus.com/us/motherboards-components/motherboards/prime/prime-x670-p/",
    ),
    (
        Manufacturer::Asus,
        "PRIME X570-P",
        "https://www.asus.com/us/motherboards-components/motherboards/prime/prime-x570-p/",
    ),
    (
        Manufacturer::Asus,
        "TUF GAMING X670E-PLUS WIFI",
        "https://www.asus.com/us/motherboards-components/motherboards/tuf-gaming/tuf-gaming-x670e-plus-wifi/",
    ),
    (
        Manufacturer::Asus,
        "TUF GAMING B550-PLUS",
        "https://www.asus.com/us/motherboards-components/motherboards/tuf-gaming/tuf-gaming-b550-plus/",
    ),
    (
        Manufacturer::Asus,
        "ROG STRIX B850-A GAMING WIFI7 NEO",
        "https://rog.asus.com/us/motherboards/rog-strix/rog-strix-b850-a-gaming-wifi7-neo/",
    ),
    (
        Manufacturer::Asus,
        "ROG STRIX B850-F GAMING WIFI7 NEO",
        "https://rog.asus.com/us/motherboards/rog-strix/rog-strix-b850-f-gaming-wifi7-neo/",
    ),
    (
        Manufacturer::Asus,
        "ROG STRIX B850-G GAMING WIFI",
        "https://rog.asus.com/us/motherboards/rog-strix/rog-strix-b850-g-gaming-wifi/",
    ),
    (
        Manufacturer::Asus,
        "ROG STRIX B850-E GAMING WIFI",
        "https://rog.asus.com/us/motherboards/rog-strix/rog-strix-b850-e-gaming-wifi/",
    ),
    (
        Manufacturer::Asus,
        "ROG STRIX B850-I GAMING WIFI",
        "https://rog.asus.com/us/motherboards/rog-strix/rog-strix-b850-i-gaming-wifi/",
    ),
    (
        Manufacturer::Asus,
        "ROG STRIX B850-A GAMING WIFI",
        "https://rog.asus.com/us/motherboards/rog-strix/rog-strix-b850-a-gaming-wifi/",
    ),
    (
        Manufacturer::Asus,
        "ROG STRIX B850-F GAMING WIFI",
        "https://rog.asus.com/us/motherboards/rog-strix/rog-strix-b850-f-gaming-wifi/",
    ),
    (
        Manufacturer::Asus,
        "ROG STRIX X870-F GAMING WIFI",
        "https://rog.asus.com/us/motherboards/rog-strix/rog-strix-x870-f-gaming-wifi/",
    ),
    (
        Manufacturer::Asus,
        "ROG STRIX X870-I GAMING WIFI",
        "https://rog.asus.com/us/motherboards/rog-strix/rog-strix-x870-i-gaming-wifi/",
    ),
    (
        Manufacturer::Asus,
        "ROG STRIX X870-A GAMING WIFI",
        "https://rog.asus.com/us/motherboards/rog-strix/rog-strix-x870-a-gaming-wifi/",
    ),
    (
        Manufacturer::Asus,
        "ROG STRIX X870E-E GAMING WIFI",
        "https://rog.asus.com/us/motherboards/rog-strix/rog-strix-x870e-e-gaming-wifi/",
    ),
    (
        Manufacturer::Asus,
        "ROG STRIX Z790-A GAMING WIFI II",
        "https://rog.asus.com/us/motherboards/rog-strix/rog-strix-z790-a-gaming-wifi-ii/",
    ),
    (
        Manufacturer::Asus,
        "ROG STRIX Z790-F GAMING WIFI II",
        "https://rog.asus.com/us/motherboards/rog-strix/rog-strix-z790-f-gaming-wifi-ii/",
    ),
    (
        Manufacturer::Asus,
        "ROG STRIX Z790-H GAMING WIFI",
        "https://rog.asus.com/us/motherboards/rog-strix/rog-strix-z790-h-gaming-wifi-model/",
    ),
    (
        Manufacturer::Asus,
        "ROG STRIX Z790-E GAMING WIFI",
        "https://rog.asus.com/us/motherboards/rog-strix/rog-strix-z790-e-gaming-wifi-model/",
    ),
    (
        Manufacturer::Asus,
        "ROG STRIX B760-A GAMING WIFI",
        "https://rog.asus.com/us/motherboards/rog-strix/rog-strix-b760-a-gaming-wifi/",
    ),
    (
        Manufacturer::Asus,
        "ROG STRIX B760-I GAMING WIFI",
        "https://rog.asus.com/us/motherboards/rog-strix/rog-strix-b760-i-gaming-wifi-model/",
    ),
    (
        Manufacturer::Asus,
        "ROG STRIX B650E-I GAMING WIFI",
        "https://rog.asus.com/us/motherboards/rog-strix/rog-strix-b650e-i-gaming-wifi-model/",
    ),
    (
        Manufacturer::Asus,
        "ROG STRIX B650E-F GAMING WIFI",
        "https://rog.asus.com/us/motherboards/rog-strix/rog-strix-b650e-f-gaming-wifi-model/",
    ),
    (
        Manufacturer::Asus,
        "ROG STRIX B650E-E GAMING WIFI",
        "https://rog.asus.com/us/motherboards/rog-strix/rog-strix-b650e-e-gaming-wifi-model/",
    ),
    (
        Manufacturer::Asus,
        "ROG STRIX B650-A GAMING WIFI",
        "https://rog.asus.com/us/motherboards/rog-strix/rog-strix-b650-a-gaming-wifi-model/",
    ),
    (
        Manufacturer::Asus,
        "TUF GAMING B650-PLUS WIFI",
        "https://www.asus.com/us/motherboards-components/motherboards/tuf-gaming/tuf-gaming-b650-plus-wifi/",
    ),
    (
        Manufacturer::Asus,
        "TUF GAMING B650M-PLUS WIFI",
        "https://www.asus.com/us/motherboards-components/motherboards/tuf-gaming/tuf-gaming-b650m-plus-wifi/",
    ),
    (
        Manufacturer::Asus,
        "TUF GAMING B650-E WIFI",
        "https://www.asus.com/us/motherboards-components/motherboards/tuf-gaming/tuf-gaming-b650-e-wifi/",
    ),
    (
        Manufacturer::Asus,
        "TUF GAMING X870-PLUS WIFI",
        "https://www.asus.com/us/motherboards-components/motherboards/tuf-gaming/tuf-gaming-x870-plus-wifi/",
    ),
    (
        Manufacturer::Asus,
        "TUF GAMING B850M-PLUS WIFI",
        "https://www.asus.com/us/motherboards-components/motherboards/tuf-gaming/tuf-gaming-b850m-plus-wifi/",
    ),
    (
        Manufacturer::Asus,
        "TUF GAMING B850-PLUS WIFI",
        "https://www.asus.com/us/motherboards-components/motherboards/tuf-gaming/tuf-gaming-b850-plus-wifi/",
    ),
    (
        Manufacturer::Asus,
        "TUF GAMING Z790-PLUS WIFI",
        "https://www.asus.com/us/motherboards-components/motherboards/tuf-gaming/tuf-gaming-z790-plus-wifi/",
    ),
    (
        Manufacturer::Asus,
        "TUF GAMING Z790-PRO WIFI",
        "https://www.asus.com/us/motherboards-components/motherboards/tuf-gaming/tuf-gaming-z790-pro-wifi/",
    ),
    (
        Manufacturer::Asus,
        "PRIME X870-P WIFI",
        "https://www.asus.com/us/motherboards-components/motherboards/prime/prime-x870-p-wifi/",
    ),
    (
        Manufacturer::Asus,
        "PRIME B650-PLUS",
        "https://www.asus.com/us/motherboards-components/motherboards/prime/prime-b650-plus/",
    ),
    (
        Manufacturer::Asus,
        "PRIME B650M-A WIFI II",
        "https://www.asus.com/motherboards-components/motherboards/prime/prime-b650m-a-wifi-ii/",
    ),
    (
        Manufacturer::Asus,
        "PRIME B650M-K",
        "https://www.asus.com/motherboards-components/motherboards/prime/prime-b650m-k/",
    ),
    (
        Manufacturer::Asus,
        "PRIME B850-PLUS WIFI",
        "https://www.asus.com/us/motherboards-components/motherboards/prime/prime-b850-plus-wifi/",
    ),
    (
        Manufacturer::Asus,
        "PRIME B850M-A WIFI",
        "https://www.asus.com/motherboards-components/motherboards/prime/prime-b850m-a-wifi/",
    ),
    (
        Manufacturer::Asus,
        "PRIME B850M-K",
        "https://www.asus.com/motherboards-components/motherboards/prime/prime-b850m-k/",
    ),
    (
        Manufacturer::Asus,
        "PRIME Z790-A WIFI",
        "https://www.asus.com/motherboards-components/motherboards/prime/prime-z790-a-wifi/",
    ),
    (
        Manufacturer::Asus,
        "PRIME Z790-P WIFI",
        "https://www.asus.com/us/motherboards-components/motherboards/prime/prime-z790-p-wifi/",
    ),
    (
        Manufacturer::Asus,
        "PRIME B760-PLUS",
        "https://www.asus.com/us/motherboards-components/motherboards/prime/prime-b760-plus/",
    ),
    (
        Manufacturer::Asus,
        "PRIME B760M-A WIFI",
        "https://www.asus.com/motherboards-components/motherboards/prime/prime-b760m-a-wifi/",
    ),
    (
        Manufacturer::Asus,
        "PROART Z890-CREATOR WIFI",
        "https://www.asus.com/us/motherboards-components/motherboards/proart/proart-z890-creator-wifi/",
    ),
    (
        Manufacturer::Asus,
        "PROART Z790-CREATOR WIFI",
        "https://www.asus.com/us/motherboards-components/motherboards/proart/proart-z790-creator-wifi/",
    ),
    (
        Manufacturer::Asus,
        "PROART X870E-CREATOR WIFI",
        "https://www.asus.com/us/motherboards-components/motherboards/proart/proart-x870e-creator-wifi/",
    ),
    (
        Manufacturer::Asus,
        "PROART X670E-CREATOR WIFI",
        "https://www.asus.com/us/motherboards-components/motherboards/proart/proart-x670e-creator-wifi/",
    ),
    (
        Manufacturer::Asus,
        "ROG CROSSHAIR X870E HERO",
        "https://rog.asus.com/us/motherboards/rog-crosshair/rog-crosshair-x870e-hero/",
    ),
    (
        Manufacturer::Asus,
        "ROG CROSSHAIR X670E HERO",
        "https://rog.asus.com/us/motherboards/rog-crosshair/rog-crosshair-x670e-hero-model/",
    ),
    (
        Manufacturer::Asus,
        "ROG MAXIMUS Z790 DARK HERO",
        "https://rog.asus.com/us/motherboards/rog-maximus/rog-maximus-z790-dark-hero/",
    ),
    (
        Manufacturer::Asus,
        "ROG MAXIMUS Z790 APEX ENCORE",
        "https://rog.asus.com/us/motherboards/rog-maximus/rog-maximus-z790-apex-encore/",
    ),
    (
        Manufacturer::Asus,
        "ROG MAXIMUS Z890 HERO",
        "https://rog.asus.com/us/motherboards/rog-maximus/rog-maximus-z890-hero/",
    ),
    (
        Manufacturer::Asus,
        "ROG MAXIMUS Z790 FORMULA",
        "https://rog.asus.com/us/motherboards/rog-maximus/rog-maximus-z790-formula/",
    ),
    (
        Manufacturer::Msi,
        "MAG B650 TOMAHAWK WIFI",
        "https://www.msi.com/Motherboard/MAG-B650-TOMAHAWK-WIFI",
    ),
    (
        Manufacturer::Msi,
        "MAG X670E TOMAHAWK WIFI",
        "https://www.msi.com/Motherboard/MAG-X670E-TOMAHAWK-WIFI",
    ),
    (
        Manufacturer::Msi,
        "MPG Z790 CARBON WIFI",
        "https://www.msi.com/Motherboard/MPG-Z790-CARBON-WIFI",
    ),
    (
        Manufacturer::Msi,
        "MPG X670E CARBON WIFI",
        "https://www.msi.com/Motherboard/MPG-X670E-CARBON-WIFI",
    ),
    (
        Manufacturer::Msi,
        "MEG X670E ACE",
        "https://www.msi.com/Motherboard/MEG-X670E-ACE",
    ),
    (
        Manufacturer::Msi,
        "PRO B650M-A WIFI",
        "https://www.msi.com/Motherboard/PRO-B650M-A-WIFI",
    ),
    (
        Manufacturer::Msi,
        "PRO Z790-P WIFI",
        "https://www.msi.com/Motherboard/PRO-Z790-P-WIFI",
    ),
    (
        Manufacturer::Msi,
        "MPG B550 GAMING PLUS",
        "https://www.msi.com/Motherboard/MPG-B550-GAMING-PLUS",
    ),
    (
        Manufacturer::Msi,
        "MEG X870E GODLIKE",
        "https://www.msi.com/Motherboard/MEG-X870E-GODLIKE",
    ),
    (
        Manufacturer::Msi,
        "MPG X870E CARBON WIFI",
        "https://www.msi.com/Motherboard/MPG-X870E-CARBON-WIFI",
    ),
    (
        Manufacturer::Msi,
        "MPG X870E EDGE TI WIFI",
        "https://www.msi.com/Motherboard/MPG-X870E-EDGE-TI-WIFI",
    ),
    (
        Manufacturer::Msi,
        "MAG X870 TOMAHAWK WIFI",
        "https://www.msi.com/Motherboard/MAG-X870-TOMAHAWK-WIFI",
    ),
    (
        Manufacturer::Msi,
        "PRO X870-P WIFI",
        "https://www.msi.com/Motherboard/PRO-X870-P-WIFI",
    ),
    (
        Manufacturer::Msi,
        "X870E GAMING PLUS WIFI",
        "https://www.msi.com/Motherboard/X870E-GAMING-PLUS-WIFI",
    ),
    (
        Manufacturer::Msi,
        "MPG B850 EDGE TI WIFI",
        "https://www.msi.com/Motherboard/MPG-B850-EDGE-TI-WIFI",
    ),
    (
        Manufacturer::Msi,
        "MAG B850 TOMAHAWK MAX WIFI",
        "https://www.msi.com/Motherboard/MAG-B850-TOMAHAWK-MAX-WIFI",
    ),
    (
        Manufacturer::Msi,
        "MAG B850 TOMAHAWK WIFI",
        "https://www.msi.com/Motherboard/MAG-B850-TOMAHAWK-WIFI",
    ),
    (
        Manufacturer::Msi,
        "MAG B850M MORTAR WIFI",
        "https://www.msi.com/Motherboard/MAG-B850M-MORTAR-WIFI",
    ),
    (
        Manufacturer::Msi,
        "B850 GAMING PLUS WIFI",
        "https://www.msi.com/Motherboard/B850-GAMING-PLUS-WIFI",
    ),
    (
        Manufacturer::Msi,
        "B850M GAMING PLUS WIFI",
        "https://www.msi.com/Motherboard/B850M-GAMING-PLUS-WIFI",
    ),
    (
        Manufacturer::Msi,
        "B850MPOWER",
        "https://www.msi.com/Motherboard/B850MPOWER",
    ),
    (
        Manufacturer::Msi,
        "PRO B850-P WIFI",
        "https://www.msi.com/Motherboard/PRO-B850-P-WIFI",
    ),
    (
        Manufacturer::Msi,
        "PRO B850-S WIFI6E",
        "https://www.msi.com/Motherboard/PRO-B850-S-WIFI6E",
    ),
    (
        Manufacturer::Msi,
        "PRO B850M-A WIFI",
        "https://www.msi.com/Motherboard/PRO-B850M-A-WIFI",
    ),
    (
        Manufacturer::Msi,
        "PRO B850M-P",
        "https://www.msi.com/Motherboard/PRO-B850M-P",
    ),
    (
        Manufacturer::Msi,
        "MEG Z890 GODLIKE",
        "https://www.msi.com/Motherboard/MEG-Z890-GODLIKE",
    ),
    (
        Manufacturer::Msi,
        "MEG Z890 ACE",
        "https://www.msi.com/Motherboard/MEG-Z890-ACE",
    ),
    (
        Manufacturer::Msi,
        "MPG Z890 CARBON WIFI",
        "https://www.msi.com/Motherboard/MPG-Z890-CARBON-WIFI",
    ),
    (
        Manufacturer::Msi,
        "MPG Z890 EDGE TI WIFI",
        "https://www.msi.com/Motherboard/MPG-Z890-EDGE-TI-WIFI",
    ),
    (
        Manufacturer::Msi,
        "MAG Z890 TOMAHAWK WIFI",
        "https://www.msi.com/Motherboard/MAG-Z890-TOMAHAWK-WIFI",
    ),
    (
        Manufacturer::Msi,
        "Z890 GAMING PLUS WIFI",
        "https://www.msi.com/Motherboard/Z890-GAMING-PLUS-WIFI",
    ),
    (
        Manufacturer::Msi,
        "Z890 GAMING WIFI",
        "https://www.msi.com/Motherboard/Z890-GAMING-WIFI",
    ),
    (
        Manufacturer::Msi,
        "Z890 GAMING WIFI6E",
        "https://www.msi.com/Motherboard/Z890-GAMING-WIFI6E",
    ),
    (
        Manufacturer::Msi,
        "PRO Z890-A WIFI",
        "https://www.msi.com/Motherboard/PRO-Z890-A-WIFI",
    ),
    (
        Manufacturer::Msi,
        "PRO Z890-P WIFI",
        "https://www.msi.com/Motherboard/PRO-Z890-P-WIFI",
    ),
    (
        Manufacturer::Msi,
        "PRO Z890-S WIFI",
        "https://www.msi.com/Motherboard/PRO-Z890-S-WIFI",
    ),
    (
        Manufacturer::Msi,
        "MPG B860I EDGE TI WIFI",
        "https://www.msi.com/Motherboard/MPG-B860I-EDGE-TI-WIFI",
    ),
    (
        Manufacturer::Msi,
        "MAG B860 TOMAHAWK WIFI",
        "https://www.msi.com/Motherboard/MAG-B860-TOMAHAWK-WIFI",
    ),
    (
        Manufacturer::Msi,
        "MAG B860M MORTAR WIFI",
        "https://www.msi.com/Motherboard/MAG-B860M-MORTAR-WIFI",
    ),
    (
        Manufacturer::Msi,
        "B860 GAMING PLUS WIFI",
        "https://www.msi.com/Motherboard/B860-GAMING-PLUS-WIFI",
    ),
    (
        Manufacturer::Msi,
        "B860M GAMING PLUS WIFI",
        "https://www.msi.com/Motherboard/B860M-GAMING-PLUS-WIFI",
    ),
    (
        Manufacturer::Msi,
        "PRO B860-P WIFI",
        "https://www.msi.com/Motherboard/PRO-B860-P-WIFI",
    ),
    (
        Manufacturer::Msi,
        "PRO B860M-A WIFI",
        "https://www.msi.com/Motherboard/PRO-B860M-A-WIFI",
    ),
    (
        Manufacturer::Msi,
        "PRO B860M-A WIFI6E",
        "https://www.msi.com/Motherboard/PRO-B860M-A-WIFI6E",
    ),
    (
        Manufacturer::Msi,
        "PRO B860M-B",
        "https://www.msi.com/Motherboard/PRO-B860M-B",
    ),
    (
        Manufacturer::Msi,
        "B860M GAMING WIFI",
        "https://www.msi.com/Motherboard/B860M-GAMING-WIFI",
    ),
    (
        Manufacturer::Msi,
        "MEG X670E GODLIKE",
        "https://www.msi.com/Motherboard/MEG-X670E-GODLIKE",
    ),
    (
        Manufacturer::Msi,
        "MPG B650 CARBON WIFI",
        "https://www.msi.com/Motherboard/MPG-B650-CARBON-WIFI",
    ),
    (
        Manufacturer::Msi,
        "MPG B650 EDGE WIFI",
        "https://www.msi.com/Motherboard/MPG-B650-EDGE-WIFI",
    ),
    (
        Manufacturer::Msi,
        "MPG B650I EDGE WIFI",
        "https://www.msi.com/Motherboard/MPG-B650I-EDGE-WIFI",
    ),
    (
        Manufacturer::Msi,
        "MAG B650M MORTAR WIFI",
        "https://www.msi.com/Motherboard/MAG-B650M-MORTAR-WIFI",
    ),
    (
        Manufacturer::Msi,
        "MAG B650M MORTAR",
        "https://www.msi.com/Motherboard/MAG-B650M-MORTAR",
    ),
    (
        Manufacturer::Msi,
        "B650 GAMING PLUS WIFI",
        "https://www.msi.com/Motherboard/B650-GAMING-PLUS-WIFI",
    ),
    (
        Manufacturer::Msi,
        "B650 GAMING PLUS",
        "https://www.msi.com/Motherboard/B650-GAMING-PLUS",
    ),
    (
        Manufacturer::Msi,
        "B650M GAMING PLUS WIFI",
        "https://www.msi.com/Motherboard/B650M-GAMING-PLUS-WIFI",
    ),
    (
        Manufacturer::Msi,
        "B650M PROJECT ZERO",
        "https://www.msi.com/Motherboard/B650M-PROJECT-ZERO",
    ),
    (
        Manufacturer::Msi,
        "PRO X670-P WIFI",
        "https://www.msi.com/Motherboard/PRO-X670-P-WIFI",
    ),
    (
        Manufacturer::Msi,
        "PRO B650-P WIFI",
        "https://www.msi.com/Motherboard/PRO-B650-P-WIFI",
    ),
    (
        Manufacturer::Msi,
        "PRO B650-S WIFI",
        "https://www.msi.com/Motherboard/PRO-B650-S-WIFI",
    ),
    (
        Manufacturer::Msi,
        "PRO B650-VC WIFI",
        "https://www.msi.com/Motherboard/PRO-B650-VC-WIFI",
    ),
    (
        Manufacturer::Msi,
        "PRO B650M-A",
        "https://www.msi.com/Motherboard/PRO-B650M-A",
    ),
    (
        Manufacturer::Msi,
        "PRO B650M-P",
        "https://www.msi.com/Motherboard/PRO-B650M-P",
    ),
    (
        Manufacturer::Msi,
        "PRO B650M-B",
        "https://www.msi.com/Motherboard/PRO-B650M-B",
    ),
    (
        Manufacturer::Gigabyte,
        "B650 AORUS ELITE AX",
        "https://www.gigabyte.com/Motherboard/B650-AORUS-ELITE-AX-rev-10-11",
    ),
    (
        Manufacturer::Gigabyte,
        "B650 AORUS PRO AX",
        "https://www.gigabyte.com/Motherboard/B650-AORUS-PRO-AX-rev-1x",
    ),
    (
        Manufacturer::Gigabyte,
        "X670E AORUS MASTER",
        "https://www.gigabyte.com/Motherboard/X670E-AORUS-MASTER-rev-1x",
    ),
    (
        Manufacturer::Gigabyte,
        "Z790 AORUS ELITE AX",
        "https://www.gigabyte.com/Motherboard/Z790-AORUS-ELITE-AX-rev-10",
    ),
    (
        Manufacturer::Gigabyte,
        "Z790 AORUS MASTER",
        "https://www.gigabyte.com/Motherboard/Z790-AORUS-MASTER-rev-10",
    ),
    (
        Manufacturer::Gigabyte,
        "B550 AORUS ELITE",
        "https://www.gigabyte.com/Motherboard/B550-AORUS-ELITE-rev-10",
    ),
    (
        Manufacturer::Gigabyte,
        "X570 AORUS ELITE",
        "https://www.gigabyte.com/Motherboard/X570-AORUS-ELITE-rev-10",
    ),
    (
        Manufacturer::Gigabyte,
        "X870 AORUS INFINITY",
        "https://www.gigabyte.com/Motherboard/X870-AORUS-INFINITY",
    ),
    (
        Manufacturer::Gigabyte,
        "X870 AORUS STEALTH ICE",
        "https://www.gigabyte.com/Motherboard/X870-AORUS-STEALTH-ICE-rev-11",
    ),
    (
        Manufacturer::Gigabyte,
        "X870 AORUS ELITE WIFI7 ICE",
        "https://www.gigabyte.com/Motherboard/X870-AORUS-ELITE-WIFI7-ICE-rev-12",
    ),
    (
        Manufacturer::Gigabyte,
        "X870 AORUS ELITE WIFI7",
        "https://www.gigabyte.com/Motherboard/X870-AORUS-ELITE-WIFI7-rev-12",
    ),
    (
        Manufacturer::Gigabyte,
        "X870 AORUS ELITE X3D",
        "https://www.gigabyte.com/Motherboard/X870-AORUS-ELITE-X3D",
    ),
    (
        Manufacturer::Gigabyte,
        "X870 AORUS ELITE X3D ICE",
        "https://www.gigabyte.com/Motherboard/X870-AORUS-ELITE-X3D-ICE",
    ),
    (
        Manufacturer::Gigabyte,
        "X870 AORUS STEALTH",
        "https://www.gigabyte.com/Motherboard/X870-AORUS-STEALTH",
    ),
    (
        Manufacturer::Gigabyte,
        "X870I AORUS PRO ICE",
        "https://www.gigabyte.com/Motherboard/X870I-AORUS-PRO-ICE-rev-11",
    ),
    (
        Manufacturer::Gigabyte,
        "X870M AORUS ELITE WIFI7",
        "https://www.gigabyte.com/Motherboard/X870M-AORUS-ELITE-WIFI7",
    ),
    (
        Manufacturer::Gigabyte,
        "X870M AORUS ELITE WIFI7 ICE",
        "https://www.gigabyte.com/Motherboard/X870M-AORUS-ELITE-WIFI7-ICE",
    ),
    (
        Manufacturer::Gigabyte,
        "B850 AORUS ELITE-P ICE",
        "https://www.gigabyte.com/Motherboard/B850-AORUS-ELITE-P-ICE",
    ),
    (
        Manufacturer::Gigabyte,
        "B850 AORUS ELITE X3D",
        "https://www.gigabyte.com/Motherboard/B850-AORUS-ELITE-X3D",
    ),
    (
        Manufacturer::Gigabyte,
        "B850M AORUS STEALTH ICE",
        "https://www.gigabyte.com/Motherboard/B850M-AORUS-STEALTH-ICE",
    ),
    (
        Manufacturer::Gigabyte,
        "B850M AORUS STEALTH",
        "https://www.gigabyte.com/Motherboard/B850M-AORUS-STEALTH",
    ),
    (
        Manufacturer::Gigabyte,
        "B850 AORUS STEALTH ICE",
        "https://www.gigabyte.com/Motherboard/B850-AORUS-STEALTH-ICE-rev-11",
    ),
    (
        Manufacturer::Gigabyte,
        "B850M EAGLE WIFI7",
        "https://www.gigabyte.com/Motherboard/B850M-EAGLE-WIFI7",
    ),
    (
        Manufacturer::Gigabyte,
        "B850M DS3H",
        "https://www.gigabyte.com/Motherboard/B850M-DS3H-rev-12",
    ),
    (
        Manufacturer::Gigabyte,
        "B850M EAGLE WIFI6E ICE",
        "https://www.gigabyte.com/Motherboard/B850M-EAGLE-WIFI6E-ICE-rev-11",
    ),
    (
        Manufacturer::Gigabyte,
        "B850M EAGLE WIFI6E",
        "https://www.gigabyte.com/Motherboard/B850M-EAGLE-WIFI6E-rev-11",
    ),
    (
        Manufacturer::Gigabyte,
        "B850M DS3H ICE",
        "https://www.gigabyte.com/Motherboard/B850M-DS3H-ICE-rev-12",
    ),
    (
        Manufacturer::Gigabyte,
        "B850 AORUS STEALTH",
        "https://www.gigabyte.com/Motherboard/B850-AORUS-STEALTH",
    ),
    (
        Manufacturer::Gigabyte,
        "Z890 AORUS ELITE WIFI7 PLUS",
        "https://www.gigabyte.com/Motherboard/Z890-AORUS-ELITE-WIFI7-PLUS",
    ),
    (
        Manufacturer::Gigabyte,
        "Z890 AORUS ELITE DUO X",
        "https://www.gigabyte.com/Motherboard/Z890-AORUS-ELITE-DUO-X",
    ),
    (
        Manufacturer::Gigabyte,
        "Z890M FORCE DUO X WIFI7",
        "https://www.gigabyte.com/Motherboard/Z890M-FORCE-DUO-X-WIFI7",
    ),
    (
        Manufacturer::Gigabyte,
        "Z890 AORUS TACHYON DUO X ICE",
        "https://www.gigabyte.com/Motherboard/Z890-AORUS-TACHYON-DUO-X-ICE",
    ),
    (
        Manufacturer::Gigabyte,
        "Z890 EAGLE PLUS",
        "https://www.gigabyte.com/Motherboard/Z890-EAGLE-PLUS",
    ),
    (
        Manufacturer::Gigabyte,
        "Z890 D PLUS",
        "https://www.gigabyte.com/Motherboard/Z890-D-PLUS",
    ),
    (
        Manufacturer::Gigabyte,
        "Z890 EAGLE WIFI7 PLUS",
        "https://www.gigabyte.com/Motherboard/Z890-EAGLE-WIFI7-PLUS",
    ),
    (
        Manufacturer::Gigabyte,
        "Z890 AORUS XTREME AI TOP",
        "https://www.gigabyte.com/Motherboard/Z890-AORUS-XTREME-AI-TOP",
    ),
    (
        Manufacturer::Gigabyte,
        "Z890 AORUS MASTER AI TOP",
        "https://www.gigabyte.com/Motherboard/Z890-AORUS-MASTER-AI-TOP",
    ),
    (
        Manufacturer::Gigabyte,
        "Z890 AORUS ELITE X ICE",
        "https://www.gigabyte.com/Motherboard/Z890-AORUS-ELITE-X-ICE",
    ),
    (
        Manufacturer::Gigabyte,
        "Z890 AORUS PRO ICE",
        "https://www.gigabyte.com/Motherboard/Z890-AORUS-PRO-ICE",
    ),
    (
        Manufacturer::Gigabyte,
        "Z890 AORUS ELITE WIFI7 ICE",
        "https://www.gigabyte.com/Motherboard/Z890-AORUS-ELITE-WIFI7-ICE",
    ),
    (
        Manufacturer::Gigabyte,
        "B860 DS3H",
        "https://www.gigabyte.com/Motherboard/B860-DS3H-rev-11",
    ),
    (
        Manufacturer::Gigabyte,
        "B860 DS3H WIFI6E",
        "https://www.gigabyte.com/Motherboard/B860-DS3H-WIFI6E-rev-13",
    ),
    (
        Manufacturer::Gigabyte,
        "B860M D3HP",
        "https://www.gigabyte.com/Motherboard/B860M-D3HP-rev-11",
    ),
    (
        Manufacturer::Gigabyte,
        "B860M E GEN5",
        "https://www.gigabyte.com/Motherboard/B860M-E-GEN5",
    ),
    (
        Manufacturer::Gigabyte,
        "B860M C",
        "https://www.gigabyte.com/Motherboard/B860M-C",
    ),
    (
        Manufacturer::Gigabyte,
        "B860M D3W",
        "https://www.gigabyte.com/Motherboard/B860M-D3W",
    ),
    (
        Manufacturer::Gigabyte,
        "B860M K GEN5",
        "https://www.gigabyte.com/Motherboard/B860M-K-GEN5",
    ),
    (
        Manufacturer::Gigabyte,
        "B860M DS3H WIFI6E",
        "https://www.gigabyte.com/Motherboard/B860M-DS3H-WIFI6E-rev-22",
    ),
    (
        Manufacturer::Gigabyte,
        "B860M DS3H",
        "https://www.gigabyte.com/Motherboard/B860M-DS3H-rev-22",
    ),
    (
        Manufacturer::Gigabyte,
        "B860M EAGLE PLUS WIFI6E",
        "https://www.gigabyte.com/Motherboard/B860M-EAGLE-PLUS-WIFI6E-rev-20",
    ),
    (
        Manufacturer::Gigabyte,
        "B860M AORUS PRO WIFI7",
        "https://www.gigabyte.com/Motherboard/B860M-AORUS-PRO-WIFI7",
    ),
    (
        Manufacturer::Gigabyte,
        "B860M AORUS ELITE WIFI6E ICE",
        "https://www.gigabyte.com/Motherboard/B860M-AORUS-ELITE-WIFI6E-ICE",
    ),
    (
        Manufacturer::Gigabyte,
        "B650E EAGLE",
        "https://www.gigabyte.com/Motherboard/B650E-EAGLE",
    ),
    (
        Manufacturer::Gigabyte,
        "B650EM C",
        "https://www.gigabyte.com/Motherboard/B650EM-C",
    ),
    (
        Manufacturer::Gigabyte,
        "B650M GAMING WIFI",
        "https://www.gigabyte.com/Motherboard/B650M-GAMING-WIFI-rev-15",
    ),
    (
        Manufacturer::Gigabyte,
        "B650EM FORCE WIFI6E",
        "https://www.gigabyte.com/Motherboard/B650EM-FORCE-WIFI6E",
    ),
    (
        Manufacturer::Gigabyte,
        "B650EM DS3H WIFI6E",
        "https://www.gigabyte.com/Motherboard/B650EM-DS3H-WIFI6E",
    ),
    (
        Manufacturer::Gigabyte,
        "B650 GAMING X AX V2",
        "https://www.gigabyte.com/Motherboard/B650-GAMING-X-AX-V2-rev-13",
    ),
    (
        Manufacturer::Gigabyte,
        "B650E EAGLE WIFI6E",
        "https://www.gigabyte.com/Motherboard/B650E-EAGLE-WIFI6E",
    ),
    (
        Manufacturer::Gigabyte,
        "B650M S2H",
        "https://www.gigabyte.com/Motherboard/B650M-S2H-rev-14",
    ),
    (
        Manufacturer::Gigabyte,
        "B650M AORUS ELITE AX",
        "https://www.gigabyte.com/Motherboard/B650M-AORUS-ELITE-AX-rev-14",
    ),
    (
        Manufacturer::Gigabyte,
        "B650I AORUS ULTRA",
        "https://www.gigabyte.com/Motherboard/B650I-AORUS-ULTRA-rev-14",
    ),
    (
        Manufacturer::Gigabyte,
        "B650I AX",
        "https://www.gigabyte.com/Motherboard/B650I-AX-rev-11",
    ),
    (
        Manufacturer::Gigabyte,
        "B650M H",
        "https://www.gigabyte.com/Motherboard/B650M-H-rev-14",
    ),
    (
        Manufacturer::Gigabyte,
        "B760M H V2",
        "https://www.gigabyte.com/Motherboard/B760M-H-V2",
    ),
    (
        Manufacturer::Gigabyte,
        "B760 DS3H WIFI6E GEN5",
        "https://www.gigabyte.com/Motherboard/B760-DS3H-WIFI6E-GEN5",
    ),
    (
        Manufacturer::Gigabyte,
        "B760 GAMING X GEN5",
        "https://www.gigabyte.com/Motherboard/B760-GAMING-X-GEN5",
    ),
    (
        Manufacturer::AsRock,
        "B650M PRO RS",
        "https://www.asrock.com/mb/AMD/B650M%20Pro%20RS/index.asp",
    ),
    (
        Manufacturer::AsRock,
        "X670E TAICHI",
        "https://www.asrock.com/mb/AMD/X670E%20Taichi/index.asp",
    ),
    (
        Manufacturer::AsRock,
        "X670E PG LIGHTNING",
        "https://pg.asrock.com/mb/AMD/X670E%20PG%20Lightning/index.asp",
    ),
    (
        Manufacturer::AsRock,
        "B550M PRO4",
        "https://www.asrock.com/mb/AMD/B550M%20Pro4/index.asp",
    ),
    (
        Manufacturer::AsRock,
        "Z790 TAICHI",
        "https://www.asrock.com/mb/Intel/Z790%20Taichi/index.asp",
    ),
    (
        Manufacturer::AsRock,
        "Z790 PG LIGHTNING",
        "https://pg.asrock.com/mb/Intel/Z790%20PG%20Lightning/index.asp",
    ),
    (
        Manufacturer::AsRock,
        "B850 RIPTIDE WIFI",
        "https://pg.asrock.com/mb/AMD/B850%20Riptide%20WiFi/index.asp",
    ),
    (
        Manufacturer::AsRock,
        "B850 STEEL LEGEND WIFI",
        "https://www.asrock.com/mb/AMD/B850%20Steel%20Legend%20WiFi/index.asp",
    ),
    (
        Manufacturer::AsRock,
        "B850 LIVEMIXER WIFI",
        "https://www.asrock.com/mb/AMD/B850%20LiveMixer%20WiFi/index.asp",
    ),
    (
        Manufacturer::AsRock,
        "B850 PRO RS WIFI",
        "https://www.asrock.com/mb/AMD/B850%20Pro%20RS%20WiFi/index.asp",
    ),
    (
        Manufacturer::AsRock,
        "B850 PRO RS",
        "https://www.asrock.com/mb/AMD/B850%20Pro%20RS/index.asp",
    ),
    (
        Manufacturer::AsRock,
        "B850 PRO-A WIFI",
        "https://www.asrock.com/mb/AMD/B850%20Pro-A%20WiFi/index.asp",
    ),
    (
        Manufacturer::AsRock,
        "B850 PRO-A",
        "https://www.asrock.com/mb/AMD/B850%20Pro-A/index.asp",
    ),
    (
        Manufacturer::AsRock,
        "B850M RIPTIDE WIFI",
        "https://pg.asrock.com/mb/AMD/B850M%20Riptide%20WiFi/index.asp",
    ),
    (
        Manufacturer::AsRock,
        "B850M STEEL LEGEND WIFI",
        "https://www.asrock.com/mb/AMD/B850M%20Steel%20Legend%20WiFi/index.asp",
    ),
    (
        Manufacturer::AsRock,
        "B850M PRO RS WIFI",
        "https://www.asrock.com/mb/AMD/B850M%20Pro%20RS%20WiFi/index.asp",
    ),
    (
        Manufacturer::AsRock,
        "B850M PRO RS",
        "https://www.asrock.com/mb/AMD/B850M%20Pro%20RS/index.asp",
    ),
    (
        Manufacturer::AsRock,
        "B850M PRO-A WIFI",
        "https://www.asrock.com/mb/AMD/B850M%20Pro-A%20WiFi/index.asp",
    ),
    (
        Manufacturer::AsRock,
        "B850M PRO-A",
        "https://www.asrock.com/mb/AMD/B850M%20Pro-A/index.asp",
    ),
    (
        Manufacturer::AsRock,
        "B850M-X WIFI",
        "https://www.asrock.com/mb/AMD/B850M-X%20WiFi/index.asp",
    ),
    (
        Manufacturer::AsRock,
        "B850M-X",
        "https://www.asrock.com/mb/AMD/B850M-X/index.asp",
    ),
    (
        Manufacturer::AsRock,
        "B850I LIGHTNING WIFI",
        "https://pg.asrock.com/mb/AMD/B850I%20Lightning%20WiFi/index.asp",
    ),
    (
        Manufacturer::AsRock,
        "X870E TAICHI",
        "https://www.asrock.com/mb/AMD/X870E%20Taichi/index.asp",
    ),
    (
        Manufacturer::AsRock,
        "X870E NOVA WIFI",
        "https://pg.asrock.com/mb/AMD/X870E%20Nova%20WiFi/index.asp",
    ),
    (
        Manufacturer::AsRock,
        "X870 STEEL LEGEND WIFI",
        "https://www.asrock.com/mb/AMD/X870%20Steel%20Legend%20WiFi/index.asp",
    ),
    (
        Manufacturer::AsRock,
        "X870E TAICHI LITE",
        "https://www.asrock.com/mb/AMD/X870E%20Taichi%20Lite/index.asp",
    ),
    (
        Manufacturer::AsRock,
        "X870 RIPTIDE WIFI",
        "https://pg.asrock.com/mb/AMD/X870%20Riptide%20WiFi/index.asp",
    ),
    (
        Manufacturer::AsRock,
        "X870 PRO RS WIFI",
        "https://www.asrock.com/mb/AMD/X870%20Pro%20RS%20WiFi/index.asp",
    ),
    (
        Manufacturer::AsRock,
        "X870 PRO RS",
        "https://www.asrock.com/mb/AMD/X870%20Pro%20RS/index.asp",
    ),
    (
        Manufacturer::AsRock,
        "Z890 TAICHI AQUA",
        "https://www.asrock.com/mb/Intel/Z890%20Taichi%20AQUA/index.asp",
    ),
    (
        Manufacturer::AsRock,
        "Z890 TAICHI OCF",
        "https://www.asrock.com/mb/Intel/Z890%20Taichi%20OCF/index.asp",
    ),
    (
        Manufacturer::AsRock,
        "Z890 TAICHI",
        "https://www.asrock.com/mb/Intel/Z890%20Taichi/index.asp",
    ),
    (
        Manufacturer::AsRock,
        "Z890 TAICHI LITE",
        "https://www.asrock.com/mb/Intel/Z890%20Taichi%20Lite/index.asp",
    ),
    (
        Manufacturer::AsRock,
        "Z890 NOVA WIFI",
        "https://pg.asrock.com/mb/Intel/Z890%20Nova%20WiFi/index.asp",
    ),
    (
        Manufacturer::AsRock,
        "Z890 RIPTIDE WIFI",
        "https://pg.asrock.com/mb/Intel/Z890%20Riptide%20WiFi/index.asp",
    ),
    (
        Manufacturer::AsRock,
        "Z890 LIGHTNING WIFI",
        "https://pg.asrock.com/mb/Intel/Z890%20Lightning%20WiFi/index.asp",
    ),
    (
        Manufacturer::AsRock,
        "Z890M RIPTIDE WIFI",
        "https://pg.asrock.com/mb/Intel/Z890M%20Riptide%20WiFi/index.asp",
    ),
    (
        Manufacturer::AsRock,
        "Z890I NOVA WIFI",
        "https://pg.asrock.com/mb/Intel/Z890I%20Nova%20WiFi/index.asp",
    ),
    (
        Manufacturer::AsRock,
        "Z890 STEEL LEGEND WIFI",
        "https://www.asrock.com/mb/Intel/Z890%20Steel%20Legend%20WiFi/index.asp",
    ),
    (
        Manufacturer::AsRock,
        "Z890 LIVEMIXER WIFI",
        "https://www.asrock.com/mb/Intel/Z890%20LiveMixer%20WiFi/index.asp",
    ),
    (
        Manufacturer::AsRock,
        "Z890 PRO RS WIFI WHITE",
        "https://www.asrock.com/mb/Intel/Z890%20Pro%20RS%20WiFi%20White/index.asp",
    ),
    (
        Manufacturer::AsRock,
        "Z890 PRO RS WIFI",
        "https://www.asrock.com/mb/Intel/Z890%20Pro%20RS%20WiFi/index.asp",
    ),
    (
        Manufacturer::AsRock,
        "Z890 PRO RS",
        "https://www.asrock.com/mb/Intel/Z890%20Pro%20RS/index.asp",
    ),
    (
        Manufacturer::AsRock,
        "Z890 PRO-A WIFI",
        "https://www.asrock.com/mb/Intel/Z890%20Pro-A%20WiFi/index.asp",
    ),
    (
        Manufacturer::AsRock,
        "Z890 PRO-A",
        "https://www.asrock.com/mb/Intel/Z890%20Pro-A/index.asp",
    ),
    (
        Manufacturer::AsRock,
        "B860 LIGHTNING WIFI",
        "https://pg.asrock.com/mb/Intel/B860%20Lightning%20WiFi/index.asp",
    ),
    (
        Manufacturer::AsRock,
        "B860 STEEL LEGEND WIFI",
        "https://www.asrock.com/mb/Intel/B860%20Steel%20Legend%20WiFi/index.asp",
    ),
    (
        Manufacturer::AsRock,
        "B860 LIVEMIXER WIFI",
        "https://www.asrock.com/mb/Intel/B860%20LiveMixer%20WiFi/index.asp",
    ),
    (
        Manufacturer::AsRock,
        "B860 PRO RS WIFI",
        "https://www.asrock.com/mb/Intel/B860%20Pro%20RS%20WiFi/index.asp",
    ),
    (
        Manufacturer::AsRock,
        "B860 PRO RS",
        "https://www.asrock.com/mb/Intel/B860%20Pro%20RS/index.asp",
    ),
    (
        Manufacturer::AsRock,
        "B860 PRO-A WIFI",
        "https://www.asrock.com/mb/Intel/B860%20Pro-A%20WiFi/index.asp",
    ),
    (
        Manufacturer::AsRock,
        "B860 PRO-A",
        "https://www.asrock.com/mb/Intel/B860%20Pro-A/index.asp",
    ),
    (
        Manufacturer::AsRock,
        "B860M LIGHTNING WIFI",
        "https://pg.asrock.com/mb/Intel/B860M%20Lightning%20WiFi/index.asp",
    ),
    (
        Manufacturer::AsRock,
        "B860M STEEL LEGEND WIFI",
        "https://www.asrock.com/mb/Intel/B860M%20Steel%20Legend%20WiFi/index.asp",
    ),
    (
        Manufacturer::AsRock,
        "B860M LIVEMIXER WIFI",
        "https://www.asrock.com/mb/Intel/B860M%20LiveMixer%20WiFi/index.asp",
    ),
    (
        Manufacturer::AsRock,
        "B860M PRO RS WIFI",
        "https://www.asrock.com/mb/Intel/B860M%20Pro%20RS%20WiFi/index.asp",
    ),
    (
        Manufacturer::AsRock,
        "B860M PRO RS",
        "https://www.asrock.com/mb/Intel/B860M%20Pro%20RS/index.asp",
    ),
    (
        Manufacturer::AsRock,
        "B860M PRO-A WIFI",
        "https://www.asrock.com/mb/Intel/B860M%20Pro-A%20WiFi/index.asp",
    ),
    (
        Manufacturer::AsRock,
        "B860M PRO-A",
        "https://www.asrock.com/mb/Intel/B860M%20Pro-A/index.asp",
    ),
    (
        Manufacturer::AsRock,
        "B860M-X WIFI",
        "https://www.asrock.com/mb/Intel/B860M-X%20WiFi/index.asp",
    ),
    (
        Manufacturer::AsRock,
        "B860M-X",
        "https://www.asrock.com/mb/Intel/B860M-X/index.asp",
    ),
    (
        Manufacturer::AsRock,
        "B860I LIGHTNING WIFI",
        "https://pg.asrock.com/mb/Intel/B860I%20Lightning%20WiFi/index.asp",
    ),
    (
        Manufacturer::AsRock,
        "B650 STEEL LEGEND WIFI",
        "https://www.asrock.com/mb/AMD/B650%20Steel%20Legend%20WiFi/index.asp",
    ),
    (
        Manufacturer::AsRock,
        "X670E STEEL LEGEND",
        "https://www.asrock.com/mb/AMD/X670E%20Steel%20Legend/index.asp",
    ),
    (
        Manufacturer::AsRock,
        "Z790 STEEL LEGEND WIFI",
        "https://www.asrock.com/mb/Intel/Z790%20Steel%20Legend%20WiFi/index.asp",
    ),
    (
        Manufacturer::AsRock,
        "B760M STEEL LEGEND WIFI",
        "https://www.asrock.com/mb/Intel/B760M%20Steel%20Legend%20WiFi/index.asp",
    ),
    // DDR4-era boards (AM4 / LGA1200)
    (
        Manufacturer::Asus,
        "ROG CROSSHAIR VIII HERO",
        "https://rog.asus.com/motherboards/rog-crosshair/rog-crosshair-viii-hero-model/",
    ),
    (
        Manufacturer::Asus,
        "TUF B450-PLUS GAMING",
        "https://www.asus.com/us/motherboards-components/motherboards/tuf-gaming/tuf-b450-plus-gaming/",
    ),
    (
        Manufacturer::Asus,
        "PRIME Z490-P",
        "https://www.asus.com/motherboards-components/motherboards/prime/prime-z490-p/",
    ),
    (
        Manufacturer::Asus,
        "TUF GAMING B460M-PLUS",
        "https://www.asus.com/motherboards-components/motherboards/tuf-gaming/tuf-gaming-b460m-plus/",
    ),
    (
        Manufacturer::Msi,
        "MPG X570 GAMING PLUS",
        "https://www.msi.com/Motherboard/MPG-X570-GAMING-PLUS",
    ),
    (
        Manufacturer::Msi,
        "B450 TOMAHAWK MAX",
        "https://www.msi.com/Motherboard/b450-tomahawk-max",
    ),
    (
        Manufacturer::Msi,
        "MAG Z490 TOMAHAWK",
        "https://www.msi.com/Motherboard/MAG-Z490-TOMAHAWK",
    ),
    (
        Manufacturer::Msi,
        "B460M PRO-VDH WIFI",
        "https://www.msi.com/Motherboard/B460M-PRO-VDH-WIFI",
    ),
    (
        Manufacturer::Gigabyte,
        "X570 AORUS MASTER",
        "https://www.gigabyte.com/Motherboard/X570-AORUS-MASTER-rev-10",
    ),
    (
        Manufacturer::Gigabyte,
        "B450M DS3H",
        "https://www.gigabyte.com/Motherboard/B450M-DS3H-rev-1x",
    ),
    (
        Manufacturer::Gigabyte,
        "Z490 AORUS ELITE AC",
        "https://www.gigabyte.com/Motherboard/Z490-AORUS-ELITE-AC-rev-10",
    ),
    (
        Manufacturer::Gigabyte,
        "B460M DS3H",
        "https://www.gigabyte.com/Motherboard/B460M-DS3H-rev-10",
    ),
    (
        Manufacturer::AsRock,
        "X570 PHANTOM GAMING 4",
        "https://www.asrock.com/mb/AMD/X570%20phantom%20Gaming%204/index.asp",
    ),
    (
        Manufacturer::AsRock,
        "B450M PRO4",
        "https://www.asrock.com/mb/AMD/B450m%20Pro4/",
    ),
    (
        Manufacturer::AsRock,
        "Z490 PHANTOM GAMING 4",
        "https://www.asrock.com/mb/Intel/Z490%20Phantom%20Gaming%204/",
    ),
    (
        Manufacturer::AsRock,
        "B460M PRO4",
        "https://www.asrock.com/mb/Intel/B460M%20Pro4/",
    ),
    (
        Manufacturer::Gigabyte,
        "B760M D2H DDR4",
        "https://www.gigabyte.com/us/Motherboard/B760M-D2H-DDR4-rev-10",
    ),
];

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
        "MSI"
        | "MICRO-STAR INTERNATIONAL"
        | "MICRO-STAR INTERNATIONAL CO"
        | "MICRO-STAR INTERNATIONAL CO., LTD"
        | "MICRO-STAR INTL CO" => Some(Manufacturer::Msi),
        "GIGABYTE"
        | "GIGABYTE TECHNOLOGY"
        | "GIGABYTE TECHNOLOGY CO"
        | "GIGABYTE TECHNOLOGY CO., LTD"
        | "GIGA-BYTE TECHNOLOGY"
        | "GIGA-BYTE TECHNOLOGY CO"
        | "GIGA-BYTE TECHNOLOGY CO., LTD" => Some(Manufacturer::Gigabyte),
        "ASROCK" | "ASROCK INC" | "ASROCK INCORPORATION" => Some(Manufacturer::AsRock),
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
    fn resolves_rog_crosshair_viii_dark_hero() {
        assert_eq!(
            motherboard_product_url("ASUS", "ROG CROSSHAIR VIII DARK HERO").as_deref(),
            Some(
                "https://rog.asus.com/us/motherboards/rog-crosshair/rog-crosshair-viii-dark-hero-model/"
            )
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
            motherboard_product_url("Some Random OEM Inc.", "MAG B650 TOMAHAWK WIFI"),
            None
        );
    }

    #[test]
    fn known_manufacturer_unknown_model_returns_none() {
        assert_eq!(motherboard_product_url("ASUS", "ROG STRIX Z690-A"), None);
    }

    #[test]
    fn resolves_msi_board_via_smbios_manufacturer_string() {
        assert_eq!(
            motherboard_product_url(
                "Micro-Star International Co., Ltd.",
                "MAG B650 TOMAHAWK WIFI"
            )
            .as_deref(),
            Some("https://www.msi.com/Motherboard/MAG-B650-TOMAHAWK-WIFI")
        );
    }

    #[test]
    fn resolves_gigabyte_board_via_smbios_manufacturer_string() {
        assert_eq!(
            motherboard_product_url("Gigabyte Technology Co., Ltd.", "B650 AORUS ELITE AX")
                .as_deref(),
            Some("https://www.gigabyte.com/Motherboard/B650-AORUS-ELITE-AX-rev-10-11")
        );
    }

    #[test]
    fn resolves_asrock_board_via_smbios_manufacturer_string() {
        assert_eq!(
            motherboard_product_url("ASRock", "X670E Taichi").as_deref(),
            Some("https://www.asrock.com/mb/AMD/X670E%20Taichi/index.asp")
        );
    }

    #[test]
    fn override_table_urls_pass_open_url_rules() {
        // Mirrors the validation gate in the open_url command so the table
        // can never ship a link the app refuses to open.
        for (manufacturer, _, url) in PRODUCT_URL_OVERRIDES {
            assert!(url.starts_with("https://"), "{url}");
            assert!(!url.chars().any(|c| c.is_control()), "{url}");
            assert!(
                !url.chars()
                    .any(|c| matches!(c, '&' | '|' | '<' | '>' | '^' | '`')),
                "{url}"
            );

            let trusted_prefixes: &[&str] = match manufacturer {
                Manufacturer::Asus => &["https://www.asus.com/", "https://rog.asus.com/"],
                Manufacturer::Msi => &["https://www.msi.com/"],
                Manufacturer::Gigabyte => &["https://www.gigabyte.com/"],
                Manufacturer::AsRock => &["https://www.asrock.com/", "https://pg.asrock.com/"],
            };
            assert!(
                trusted_prefixes
                    .iter()
                    .any(|prefix| url.starts_with(prefix)),
                "URL does not use a trusted domain for {manufacturer:?}: {url}"
            );
        }
    }

    #[test]
    fn resolves_ddr4_era_boards_per_vendor() {
        assert_eq!(
            motherboard_product_url("ASUS", "ROG CROSSHAIR VIII HERO").as_deref(),
            Some("https://rog.asus.com/motherboards/rog-crosshair/rog-crosshair-viii-hero-model/")
        );
        assert_eq!(
            motherboard_product_url("Micro-Star International Co., Ltd.", "B450 TOMAHAWK MAX")
                .as_deref(),
            Some("https://www.msi.com/Motherboard/b450-tomahawk-max")
        );
        assert_eq!(
            motherboard_product_url("Gigabyte Technology Co., Ltd.", "B450M DS3H").as_deref(),
            Some("https://www.gigabyte.com/Motherboard/B450M-DS3H-rev-1x")
        );
        assert_eq!(
            motherboard_product_url("ASRock", "B460M Pro4").as_deref(),
            Some("https://www.asrock.com/mb/Intel/B460M%20Pro4/")
        );
        assert_eq!(
            motherboard_product_url("Gigabyte Technology Co., Ltd.", "B760M D2H DDR4")
                .as_deref(),
            Some("https://www.gigabyte.com/us/Motherboard/B760M-D2H-DDR4-rev-10")
        );
    }

    #[test]
    fn override_table_has_unique_manufacturer_model_keys() {
        for (index, (manufacturer, key, _)) in PRODUCT_URL_OVERRIDES.iter().enumerate() {
            assert!(
                !PRODUCT_URL_OVERRIDES[index + 1..].iter().any(
                    |(other_manufacturer, other_key, _)| {
                        manufacturer == other_manufacturer && key == other_key
                    }
                ),
                "duplicate override for {manufacturer:?} {key}"
            );
        }
    }
}
