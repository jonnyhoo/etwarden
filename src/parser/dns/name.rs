//! # `parser::dns::name`
//!
//! **Purpose**: Parses DNS names, including bounded compression-pointer walking.
//! **Public API**: module-private `parse_dns_name`
//! **Dependencies**: (none)
//! **Platform**: `cross-platform`
//! **Privilege**: `none`
//! **Line budget**: 75 / 110

/// Maximum DNS name length per RFC 1035 §2.3.4.
const MAX_DNS_NAME_LEN: usize = 253;
/// Cap on pointer indirection hops while parsing a compressed name.
const MAX_NAME_POINTER_HOPS: usize = 16;

/// Parse a DNS name, returning (name, offset after encoded name).
/// Handles compression pointers when `allow_compression` is true.
pub(super) fn parse_dns_name(
    payload: &[u8],
    start: usize,
    allow_compression: bool,
) -> Option<(Option<String>, usize)> {
    let mut offset = start;
    let mut end = None;
    let mut hops = 0;
    let mut name_len = 0usize;
    let mut name = String::new();

    loop {
        let label_len = usize::from(*payload.get(offset)?);
        if label_len == 0 {
            let next = end.or_else(|| offset.checked_add(1))?;
            return Some(((!name.is_empty()).then_some(name), next));
        }
        if label_len & 0xC0 == 0xC0 {
            if !allow_compression {
                return None;
            }
            let pointer_end = offset.checked_add(2)?;
            let pointer_next = usize::from(*payload.get(offset + 1)?);
            let pointer = ((label_len & 0x3F) << 8) | pointer_next;
            if pointer >= offset || pointer >= payload.len() {
                return None;
            }
            end.get_or_insert(pointer_end);
            hops += 1;
            if hops > MAX_NAME_POINTER_HOPS {
                return None;
            }
            offset = pointer;
            continue;
        }
        if label_len & 0xC0 != 0 {
            return None;
        }
        let next = offset.checked_add(1)?.checked_add(label_len)?;
        if next > payload.len() {
            return None;
        }
        if !name.is_empty() {
            name.push('.');
        }
        let dot_len = usize::from(name_len > 0);
        name_len = name_len.checked_add(dot_len)?.checked_add(label_len)?;
        if name_len > MAX_DNS_NAME_LEN {
            return None;
        }
        let label = std::str::from_utf8(&payload[offset + 1..next]).ok()?;
        if label.bytes().any(|byte| byte.is_ascii_control()) {
            return None;
        }
        name.push_str(label);
        offset = next;
    }
}
