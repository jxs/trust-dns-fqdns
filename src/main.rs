use trust_dns_proto::op::Message;

/// `SERVICE_NAME` as a Fully Qualified Domain Name.
const SERVICE_NAME_FQDN: &str = "_p2p._udp.local.";

/// An encoded MDNS packet.
pub type MdnsPacket = Vec<u8>;

/// Appends a `QNAME` (as defined by RFC1035) to the `Vec`.
///
/// # Panic
///
/// Panics if `name` has a zero-length component or a component that is too long.
/// This is fine considering that this function is not public and is only called in a controlled
/// environment.
///
fn append_qname(out: &mut Vec<u8>, name: &[u8]) {
    debug_assert!(name.is_ascii());

    for element in name.split(|&c| c == b'.') {
        assert!(element.len() < 64, "Service name has a label too long");
        // assert_ne!(element.len(), 0, "Service name contains zero length label");
        out.push(element.len() as u8);
        for chr in element.iter() {
            out.push(*chr);
        }
    }

    out.push(0);
}

/// Appends a big-endian u16 to `out`.
fn append_u16(out: &mut Vec<u8>, value: u16) {
    out.push(((value >> 8) & 0xff) as u8);
    out.push((value & 0xff) as u8);
}

/// Builds the binary representation of a DNS query to send on the network.
pub fn build_query() -> MdnsPacket {
    let mut out = Vec::with_capacity(33);

    // Program-generated transaction ID; unused by our implementation.
    append_u16(&mut out, rand::random());

    // 0x0 flag for a regular query.
    append_u16(&mut out, 0x0);

    // Number of questions.
    append_u16(&mut out, 0x1);

    // Number of answers, authorities, and additionals.
    append_u16(&mut out, 0x0);
    append_u16(&mut out, 0x0);
    append_u16(&mut out, 0x0);

    // Our single question.
    // The name.
    append_qname(&mut out, SERVICE_NAME_FQDN.as_bytes());

    // Flags.
    append_u16(&mut out, 0x0c);
    append_u16(&mut out, 0x01);

    // Since the output is constant, we reserve the right amount ahead of time.
    // If this assert fails, adjust the capacity of `out` in the source code.
    // debug_assert_eq!(out.capacity(), out.len());
    out
}

fn main() {
    let packet = build_query();
    Message::from_vec(&packet).unwrap();
}
