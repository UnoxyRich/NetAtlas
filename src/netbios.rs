use std::{
    net::{Ipv4Addr, UdpSocket},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

// NetBIOS node status uses an unauthenticated, unicast UDP query. Names are claims.
pub fn lookup(ip: Ipv4Addr) -> Option<String> {
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).ok()?;
    socket.connect((ip, 137)).ok()?;
    socket
        .set_read_timeout(Some(Duration::from_millis(600)))
        .ok()?;
    let id = (SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()?
        .subsec_nanos() as u16)
        ^ u16::from(ip.octets()[3]);
    let mut query = vec![
        (id >> 8) as u8,
        id as u8,
        0,
        0,
        0,
        1,
        0,
        0,
        0,
        0,
        0,
        0,
        32,
        b'C',
        b'K',
    ];
    query.extend_from_slice(&[b'A'; 30]);
    query.extend_from_slice(&[0, 0, 0x21, 0, 1]);
    socket.send(&query).ok()?;
    let mut packet = [0u8; 2048];
    let len = socket.recv(&mut packet).ok()?;
    parse_response(&packet[..len], id)
}

fn skip_name(packet: &[u8], mut pos: usize) -> Option<usize> {
    loop {
        let len = *packet.get(pos)?;
        pos += 1;
        if len == 0 {
            return Some(pos);
        }
        if len & 0xc0 == 0xc0 {
            return (pos < packet.len()).then_some(pos + 1);
        }
        if len & 0xc0 != 0 || len > 63 {
            return None;
        }
        pos = pos.checked_add(usize::from(len))?;
        if pos > packet.len() {
            return None;
        }
    }
}
fn word(data: &[u8], pos: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*data.get(pos)?, *data.get(pos + 1)?]))
}
fn parse_response(packet: &[u8], id: u16) -> Option<String> {
    if packet.len() < 12 || word(packet, 0)? != id || word(packet, 2)? & 0x800f != 0x8000 {
        return None;
    }
    let questions = usize::from(word(packet, 4)?);
    let answers = usize::from(word(packet, 6)?);
    let mut pos = 12;
    for _ in 0..questions {
        pos = skip_name(packet, pos)?.checked_add(4)?;
        if pos > packet.len() {
            return None;
        }
    }
    let mut fallback = None;
    for _ in 0..answers {
        pos = skip_name(packet, pos)?;
        let typ = word(packet, pos)?;
        let class = word(packet, pos + 2)?;
        let len = usize::from(word(packet, pos + 8)?);
        pos = pos.checked_add(10)?;
        let end = pos.checked_add(len)?;
        let data = packet.get(pos..end)?;
        pos = end;
        if typ != 0x21 || class != 1 {
            continue;
        }
        let count = usize::from(*data.first()?);
        for i in 0..count {
            let start = 1 + i * 18;
            let entry = data.get(start..start + 18)?;
            let flags = u16::from_be_bytes([entry[16], entry[17]]);
            if flags & 0x8000 != 0 || ![0x00, 0x20].contains(&entry[15]) {
                continue;
            }
            let name = std::str::from_utf8(&entry[..15]).ok()?.trim();
            if name.is_empty()
                || name == "*"
                || !name.bytes().all(|b| b.is_ascii_graphic() || b == b' ')
            {
                continue;
            }
            if entry[15] == 0x20 {
                return Some(name.to_owned());
            }
            fallback = Some(name.to_owned());
        }
    }
    fallback
}

#[cfg(test)]
mod tests {
    use super::*;
    fn response(id: u16, suffix: u8, flags: u16) -> Vec<u8> {
        let mut p = vec![
            (id >> 8) as u8,
            id as u8,
            0x80,
            0,
            0,
            0,
            0,
            1,
            0,
            0,
            0,
            0,
            0,
            0,
            0x21,
            0,
            1,
            0,
            0,
            0,
            0,
            0,
            19,
            1,
        ];
        p.extend_from_slice(b"DESKTOP        ");
        p.push(suffix);
        p.extend_from_slice(&flags.to_be_bytes());
        p
    }
    #[test]
    fn chooses_unique_computer_name_and_checks_packet() {
        let p = response(123, 0x20, 0);
        assert_eq!(parse_response(&p, 123).as_deref(), Some("DESKTOP"));
        assert_eq!(parse_response(&p, 124), None);
        assert_eq!(parse_response(&p[..p.len() - 1], 123), None);
        assert_eq!(parse_response(&response(123, 0x20, 0x8000), 123), None);
    }
}
