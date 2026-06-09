use super::*;

#[test]
fn etw_session_variant_displays_message() {
    let err = EtwardenError::EtwSession("start failed".into());
    let msg = err.to_string();
    assert!(msg.contains("ETW session error"), "actual: {msg}");
    assert!(msg.contains("start failed"), "actual: {msg}");
}

#[test]
fn privilege_variant_is_privilege() {
    let err = EtwardenError::Privilege("not admin".into());
    assert!(err.is_privilege());
}

#[test]
fn non_privilege_is_not_privilege() {
    let err = EtwardenError::OutputWrite("disk full".into());
    assert!(!err.is_privilege());
}

#[test]
fn process_spawn_variant_displays_message() {
    let err = EtwardenError::ProcessSpawn("not found".into());
    let msg = err.to_string();
    assert!(msg.contains("process spawn error"), "actual: {msg}");
}

#[test]
fn process_control_variant_displays_message() {
    let err = EtwardenError::ProcessControl("kill denied".into());
    let msg = err.to_string();
    assert!(msg.contains("process control error"), "actual: {msg}");
}

#[test]
fn network_inventory_variant_displays_message() {
    let err = EtwardenError::NetworkInventory("socket table unavailable".into());
    let msg = err.to_string();
    assert!(msg.contains("network inventory error"), "actual: {msg}");
}

#[test]
fn pcap_write_variant_displays_message() {
    let err = EtwardenError::PcapWrite("io error".into());
    let msg = err.to_string();
    assert!(msg.contains("pcap write error"), "actual: {msg}");
}

#[test]
fn output_write_variant_displays_message() {
    let err = EtwardenError::OutputWrite("pipe closed".into());
    let msg = err.to_string();
    assert!(msg.contains("output write error"), "actual: {msg}");
}

#[test]
fn mitm_proxy_variant_displays_message() {
    let err = EtwardenError::MitmProxy("bind failed".into());
    let msg = err.to_string();
    assert!(msg.contains("MITM proxy error"), "actual: {msg}");
}

#[test]
fn result_alias_works() {
    fn returns_result() -> Result<()> {
        Err(EtwardenError::EtwSession("test".into()))
    }
    let res = returns_result();
    assert!(res.is_err());
}
