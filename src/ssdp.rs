use crate::{
    discovery::{networks, Message, Network},
    model::Observation,
};
use crossbeam_channel::Sender;
use std::{
    collections::HashSet,
    io::{Read, Write},
    net::{Ipv4Addr, SocketAddrV4, TcpStream, UdpSocket},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::{Duration, Instant},
};

pub fn monitor(tx: Sender<Message>, stop: Arc<AtomicBool>) {
    while !stop.load(Ordering::Relaxed) {
        for network in networks() {
            if stop.load(Ordering::Relaxed) {
                return;
            }
            probe(&network, &tx, &stop);
        }
        let start = Instant::now();
        while start.elapsed() < Duration::from_secs(30) && !stop.load(Ordering::Relaxed) {
            thread::sleep(Duration::from_millis(100));
        }
    }
}
fn probe(net: &Network, tx: &Sender<Message>, stop: &AtomicBool) {
    let Ok(socket) = UdpSocket::bind((net.address, 0)) else {
        return;
    };
    let _ = socket.set_read_timeout(Some(Duration::from_millis(100)));
    let request = b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n";
    if socket
        .send_to(request, (Ipv4Addr::new(239, 255, 255, 250), 1900))
        .is_err()
    {
        return;
    }
    let mut seen = HashSet::new();
    let start = Instant::now();
    let mut buf = [0; 8192];
    while start.elapsed() < Duration::from_secs(2) && !stop.load(Ordering::Relaxed) {
        let Ok((count, source)) = socket.recv_from(&mut buf) else {
            continue;
        };
        let std::net::IpAddr::V4(ip) = source.ip() else {
            continue;
        };
        if !net.contains(ip) {
            continue;
        }
        let response = String::from_utf8_lossy(&buf[..count]);
        let Some(location) = header(&response, "location") else {
            continue;
        };
        if !seen.insert((ip, location.to_owned())) {
            continue;
        }
        let Some((port, path)) = local_http_location(location, ip) else {
            continue;
        };
        if let Some(body) = fetch_description(ip, port, &path) {
            if let Some(mut observation) = parse_description(&body, ip, &net.interface) {
                observation.gateway = net.gateway == Some(ip);
                observation.local = net.address == ip;
                if let Some(server) = header(&response, "server") {
                    observation.findings.push(format!(
                        "UPnP server: {}",
                        server.chars().take(180).collect::<String>()
                    ));
                }
                let _ = tx.send(Message::Found(observation));
            }
        }
    }
}
fn header<'a>(text: &'a str, key: &str) -> Option<&'a str> {
    text.lines()
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.trim().eq_ignore_ascii_case(key))
        .map(|(_, value)| value.trim())
}
// Fetch only plain HTTP URLs hosted by the responding device itself.
fn local_http_location(location: &str, ip: Ipv4Addr) -> Option<(u16, String)> {
    let rest = location.strip_prefix("http://")?;
    let (authority, path) = rest.split_once('/').map_or((rest, ""), |(a, p)| (a, p));
    if authority.contains('@') || path.chars().any(char::is_control) {
        return None;
    }
    let (host, port) = authority
        .split_once(':')
        .map_or((authority, "80"), |(h, p)| (h, p));
    if host.parse::<Ipv4Addr>().ok()? != ip {
        return None;
    }
    Some((port.parse().ok()?, format!("/{path}")))
}
fn fetch_description(ip: Ipv4Addr, port: u16, path: &str) -> Option<String> {
    let mut stream = TcpStream::connect_timeout(
        &SocketAddrV4::new(ip, port).into(),
        Duration::from_millis(500),
    )
    .ok()?;
    stream
        .set_read_timeout(Some(Duration::from_millis(600)))
        .ok()?;
    stream
        .set_write_timeout(Some(Duration::from_millis(500)))
        .ok()?;
    write!(
        stream,
        "GET {path} HTTP/1.0\r\nHost: {ip}:{port}\r\nConnection: close\r\n\r\n"
    )
    .ok()?;
    let mut data = Vec::new();
    let _ = stream.take(65536).read_to_end(&mut data);
    let response = String::from_utf8_lossy(&data);
    if !response.lines().next()?.contains(" 200 ") {
        return None;
    }
    Some(response.split_once("\r\n\r\n")?.1.to_owned())
}
fn parse_description(xml: &str, ip: Ipv4Addr, iface: &str) -> Option<Observation> {
    let doc = roxmltree::Document::parse(xml).ok()?;
    let device = doc
        .descendants()
        .find(|n| n.tag_name().name() == "device")?;
    let field = |key| {
        device
            .children()
            .find(|n| n.tag_name().name() == key)
            .and_then(|n| n.text())
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(|v| v.chars().take(200).collect::<String>())
    };
    let mut o = Observation::new(ip, iface);
    o.friendly_name = field("friendlyName");
    o.vendor = field("manufacturer");
    if o.vendor.is_some() {
        o.vendor_source = Some("UPnP".into());
    }
    let name = field("modelName");
    let number = field("modelNumber");
    o.model = match (name, number) {
        (Some(name), Some(number)) if !name.contains(&number) => Some(format!("{name} {number}")),
        (Some(name), _) => Some(name),
        (None, Some(number)) => Some(number),
        _ => None,
    };
    if o.model.is_some() {
        o.model_source = Some("UPnP".into());
    }
    if let Some(kind) = field("deviceType") {
        o.findings.push(format!("UPnP: {kind}"));
    }
    o.services.push("UPnP / SSDP".into());
    Some(o)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn validates_description_location() {
        let ip = "192.168.1.5".parse().unwrap();
        assert_eq!(
            local_http_location("http://192.168.1.5:8080/root.xml", ip),
            Some((8080, "/root.xml".into()))
        );
        assert!(local_http_location("http://192.168.1.6/root.xml", ip).is_none());
        assert!(local_http_location("http://192.168.1.5/\r\nInjected", ip).is_none());
    }
    #[test]
    fn parses_device_metadata() {
        let xml="<root><device><friendlyName>Living Room</friendlyName><manufacturer>Acme</manufacturer><modelName>Box</modelName><modelNumber>4</modelNumber><deviceType>urn:camera</deviceType></device></root>";
        let o = parse_description(xml, "192.168.1.5".parse().unwrap(), "en0").unwrap();
        assert_eq!(o.friendly_name.as_deref(), Some("Living Room"));
        assert_eq!(o.vendor.as_deref(), Some("Acme"));
        assert_eq!(o.model.as_deref(), Some("Box 4"));
    }
}
