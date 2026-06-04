//! # `parser::dpi::tls::extensions`
//!
//! **Purpose**: Parses TLS `ClientHello` extension metadata for passive fingerprints.
//! **Public API**: module-private extension parser
//! **Dependencies**: (none)
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 140 / 180

#[derive(Default)]
pub(super) struct ParsedExtensions {
    pub(super) sni: Option<String>,
    pub(super) alpn: Vec<String>,
    pub(super) extension_ids: Vec<u16>,
    pub(super) supported_groups: Vec<u16>,
    pub(super) ec_point_formats: Vec<u8>,
    pub(super) signature_algorithms: Vec<u16>,
    pub(super) supported_versions: Vec<u16>,
    pub(super) count: usize,
}

pub(super) fn parse_extensions(data: &[u8]) -> Option<ParsedExtensions> {
    let mut parsed = ParsedExtensions::default();
    let mut offset = 0;

    while offset + 4 <= data.len() {
        let ext_type = u16::from_be_bytes([data[offset], data[offset + 1]]);
        let ext_len = usize::from(u16::from_be_bytes([data[offset + 2], data[offset + 3]]));
        let ext_data_start = offset + 4;
        let ext_data_end = checked_end(ext_data_start, ext_len, data.len())?;
        let ext_data = &data[ext_data_start..ext_data_end];
        parsed.count += 1;
        parsed.extension_ids.push(ext_type);

        match ext_type {
            0x0000 => parsed.sni = extract_sni(ext_data),
            0x000a => parsed.supported_groups = extract_u16_list(ext_data).unwrap_or_default(),
            0x000b => parsed.ec_point_formats = extract_u8_list(ext_data).unwrap_or_default(),
            0x000d => {
                parsed.signature_algorithms = extract_u16_list(ext_data).unwrap_or_default();
            }
            0x0010 => parsed.alpn = extract_alpn(ext_data).unwrap_or_default(),
            0x002b => {
                parsed.supported_versions =
                    extract_supported_versions(ext_data).unwrap_or_default();
            }
            _ => {}
        }

        offset = ext_data_end;
    }

    (offset == data.len()).then_some(parsed)
}

const fn checked_end(start: usize, len: usize, limit: usize) -> Option<usize> {
    let Some(end) = start.checked_add(len) else {
        return None;
    };
    if end <= limit {
        Some(end)
    } else {
        None
    }
}

fn extract_u16_list(data: &[u8]) -> Option<Vec<u16>> {
    let list_len_end = checked_end(0, 2, data.len())?;
    let list_len = usize::from(u16::from_be_bytes([data[0], data[1]]));
    let list_end = checked_end(list_len_end, list_len, data.len())?;
    if list_end != data.len() || list_len % 2 != 0 {
        return None;
    }

    let mut values = Vec::with_capacity(list_len / 2);
    let mut offset = list_len_end;
    while offset < list_end {
        values.push(u16::from_be_bytes([data[offset], data[offset + 1]]));
        offset += 2;
    }
    Some(values)
}

fn extract_u8_list(data: &[u8]) -> Option<Vec<u8>> {
    let list_len = usize::from(*data.first()?);
    let list_end = checked_end(1, list_len, data.len())?;
    (list_end == data.len()).then(|| data[1..list_end].to_vec())
}

fn extract_sni(data: &[u8]) -> Option<String> {
    let list_len_end = checked_end(0, 2, data.len())?;
    let list_len = usize::from(u16::from_be_bytes([data[0], data[1]]));
    let list_end = checked_end(list_len_end, list_len, data.len())?;
    if list_end != data.len() {
        return None;
    }

    let entry_start = list_len_end;
    checked_end(entry_start, 3, list_end)?;
    if data[entry_start] != 0 {
        return None;
    }

    let entry_len = usize::from(u16::from_be_bytes([
        data[entry_start + 1],
        data[entry_start + 2],
    ]));
    let hostname_start = entry_start + 3;
    let hostname_end = checked_end(hostname_start, entry_len, list_end)?;
    let hostname = data.get(hostname_start..hostname_end)?;
    if hostname.is_empty() {
        return None;
    }

    visible_utf8(hostname)
}

fn extract_alpn(data: &[u8]) -> Option<Vec<String>> {
    let list_len_end = checked_end(0, 2, data.len())?;
    let list_len = usize::from(u16::from_be_bytes([data[0], data[1]]));
    let list_end = checked_end(list_len_end, list_len, data.len())?;
    if list_end != data.len() {
        return None;
    }

    let mut protocols = Vec::new();
    let mut offset = list_len_end;
    while offset < list_end {
        let len = usize::from(*data.get(offset)?);
        offset += 1;
        let protocol_end = checked_end(offset, len, list_end)?;
        let protocol = data.get(offset..protocol_end)?;
        if protocol.is_empty() {
            return None;
        }
        protocols.push(visible_utf8(protocol)?);
        offset = protocol_end;
    }
    Some(protocols)
}

fn extract_supported_versions(data: &[u8]) -> Option<Vec<u16>> {
    let list_len = usize::from(*data.first()?);
    let list_end = checked_end(1, list_len, data.len())?;
    if list_end != data.len() || list_len % 2 != 0 {
        return None;
    }

    let mut versions = Vec::with_capacity(list_len / 2);
    let mut offset = 1;
    while offset < list_end {
        versions.push(u16::from_be_bytes([data[offset], data[offset + 1]]));
        offset += 2;
    }
    Some(versions)
}

fn visible_utf8(value: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(value).ok()?;
    (!text.bytes().any(|byte| byte.is_ascii_control())).then(|| text.to_string())
}
