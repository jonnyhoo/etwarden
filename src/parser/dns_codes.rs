//! # `parser::dns_codes`
//!
//! **Purpose**: DNS record type and RCODE status code lookup tables.
//! **Public API**: `fn dns_type_name(code) -> &'static str`, `fn dns_status_name(code) -> &'static str`
//! **Dependencies**: (none)
//! **Platform**: `cross-platform`
//! **Privilege**: `none`
//! **Line budget**: 160 / 200

/// Returns the human-readable DNS record type name for a given numeric code.
///
/// Covers all IANA-assigned types through 65 (HTTPS), plus common
/// extended types. Returns `"UNKNOWN"` for unrecognized codes.
#[must_use]
pub const fn dns_type_name(code: u16) -> &'static str {
    match code {
        1 => "A",
        2 => "NS",
        3 => "MD",
        4 => "MF",
        5 => "CNAME",
        6 => "SOA",
        7 => "MB",
        8 => "MG",
        9 => "MR",
        10 => "NULL",
        11 => "WKS",
        12 => "PTR",
        13 => "HINFO",
        14 => "MINFO",
        15 => "MX",
        16 => "TXT",
        17 => "RP",
        18 => "AFSDB",
        19 => "X25",
        20 => "ISDN",
        21 => "RT",
        22 => "NSAP",
        23 => "NSAP-PTR",
        24 => "SIG",
        25 => "KEY",
        26 => "PX",
        27 => "GPOS",
        28 => "AAAA",
        29 => "LOC",
        30 => "NXT",
        31 => "EID",
        32 => "NIMLOC",
        33 => "SRV",
        34 => "ATMA",
        35 => "NAPTR",
        36 => "KX",
        37 => "CERT",
        38 => "A6",
        39 => "DNAME",
        40 => "SINK",
        41 => "OPT",
        42 => "APL",
        43 => "DS",
        44 => "SSHFP",
        45 => "IPSECKEY",
        46 => "RRSIG",
        47 => "NSEC",
        48 => "DNSKEY",
        49 => "DHCID",
        50 => "NSEC3",
        51 => "NSEC3PARAM",
        52 => "TLSA",
        53 => "SMIMEA",
        55 => "HIP",
        56 => "NINFO",
        57 => "RKEY",
        58 => "TALINK",
        59 => "CDS",
        60 => "CDNSKEY",
        61 => "OPENPGPKEY",
        62 => "CSYNC",
        63 => "ZONEMD",
        64 => "SVCB",
        65 => "HTTPS",
        99 => "SPF",
        249 => "TKEY",
        250 => "TSIG",
        251 => "IXFR",
        252 => "AXFR",
        255 => "ANY",
        256 => "URI",
        257 => "CAA",
        258 => "AVC",
        260 => "AMTRELAY",
        32768 => "TA",
        32769 => "DLV",
        _ => "UNKNOWN",
    }
}

/// Returns the human-readable DNS status (RCODE) name for a given numeric code.
///
/// Covers standard RCODEs (0-23) and Windows extended DNS status codes
/// (9001-9505). Returns `"UNKNOWN"` for unrecognized codes.
#[must_use]
pub const fn dns_status_name(code: u32) -> &'static str {
    match code {
        // Standard RCODEs
        0 => "NOERROR",
        1 => "FORMERR",
        2 => "SERVFAIL",
        3 => "NXDOMAIN",
        4 => "NOTIMP",
        5 => "REFUSED",
        6 => "YXDOMAIN",
        7 => "YXRRSET",
        8 => "NXRRSET",
        9 => "NOTAUTH",
        10 => "NOTZONE",
        16 => "BADVERS",
        17 => "BADKEY",
        18 => "BADTIME",
        19 => "BADMODE",
        20 => "BADNAME",
        21 => "BADALG",
        22 => "BADTRUNC",
        23 => "BADCOOKIE",
        // Windows extended codes
        87 => "INVALID_PARAMETER",
        9001 => "DNS_SERVER_UNABLE_TO_INTERPRET_FORMAT",
        9002 => "DNS_SERVER_FAILURE",
        9003 => "DNS_NAME_DOES_NOT_EXIST",
        9004 => "DNS_REQUEST_NOT_SUPPORTED",
        9005 => "DNS_OPERATION_REFUSED",
        9006 => "DNS_NAME_THAT_OUGHT_NOT_EXIST_DOES_EXIST",
        9007 => "DNS_RRSET_THAT_OUGHT_NOT_EXIST_DOES_EXIST",
        9008 => "DNS_RRSET_THAT_OUGHT_TO_EXIST_DOES_NOT_EXIST",
        9009 => "DNS_SERVER_NOT_AUTHORITATIVE_FOR_ZONE",
        9010 => "DNS_NAME_NOT_IN_ZONE",
        9016 => "DNS_SIGNATURE_FAILED_TO_VERIFY",
        9017 => "DNS_BAD_KEY",
        9018 => "DNS_SIGNATURE_VALIDITY_EXPIRED",
        9501 => "NO_RECORDS_FOUND",
        9502 => "BAD_DNS_PACKET",
        9503 => "NO_DNS_PACKET",
        9505 => "UNSECURED_DNS_PACKET",
        _ => "UNKNOWN",
    }
}

/// Parses the Windows DNS Client ETW `QueryResults` string into a list of IPs.
///
/// The format is: `"1.2.3.4;5.6.7.8;type: 1 example.com;"` where
/// semicolon-separated entries are either IP addresses or metadata.
/// We extract only the IP-like entries.
pub fn parse_query_results(results: &str) -> Vec<String> {
    if results.trim().is_empty() {
        return Vec::new();
    }

    results
        .split(';')
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .filter(|part| looks_like_ip(part))
        .map(String::from)
        .collect()
}

/// Checks if a string looks like an IP address (v4 or v6).
fn looks_like_ip(s: &str) -> bool {
    s.parse::<std::net::IpAddr>().is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn common_dns_types() {
        assert_eq!(dns_type_name(1), "A");
        assert_eq!(dns_type_name(28), "AAAA");
        assert_eq!(dns_type_name(5), "CNAME");
        assert_eq!(dns_type_name(15), "MX");
        assert_eq!(dns_type_name(16), "TXT");
        assert_eq!(dns_type_name(33), "SRV");
        assert_eq!(dns_type_name(65), "HTTPS");
        assert_eq!(dns_type_name(257), "CAA");
    }

    #[test]
    fn unknown_type_returns_unknown() {
        assert_eq!(dns_type_name(9999), "UNKNOWN");
    }

    #[test]
    fn common_dns_statuses() {
        assert_eq!(dns_status_name(0), "NOERROR");
        assert_eq!(dns_status_name(2), "SERVFAIL");
        assert_eq!(dns_status_name(3), "NXDOMAIN");
        assert_eq!(dns_status_name(5), "REFUSED");
        assert_eq!(dns_status_name(9003), "DNS_NAME_DOES_NOT_EXIST");
    }

    #[test]
    fn unknown_status_returns_unknown() {
        assert_eq!(dns_status_name(99999), "UNKNOWN");
    }

    #[test]
    fn parse_query_results_extracts_ips() {
        let results = "93.184.216.34;type: 1 example.com;";
        let ips = parse_query_results(results);
        assert_eq!(ips, vec!["93.184.216.34"]);
    }

    #[test]
    fn parse_query_results_multiple_ips() {
        let results = "1.1.1.1;8.8.8.8;type: 1 example.com;9.9.9.9";
        let ips = parse_query_results(results);
        assert_eq!(ips, vec!["1.1.1.1", "8.8.8.8", "9.9.9.9"]);
    }

    #[test]
    fn parse_query_results_empty() {
        assert!(parse_query_results("").is_empty());
        assert!(parse_query_results("type: 5 example.com;").is_empty());
    }

    #[test]
    fn parse_query_results_rejects_invalid_ip_like_tokens() {
        let results = "bad;::::;1.2.3.999;93.184.216.34";
        let ips = parse_query_results(results);
        assert_eq!(ips, vec!["93.184.216.34"]);
    }

    #[test]
    fn parse_query_results_ipv6() {
        let results = "2606:4700:4700::1111;2606:4700:4700::1001;";
        let ips = parse_query_results(results);
        assert_eq!(ips.len(), 2);
    }
}
