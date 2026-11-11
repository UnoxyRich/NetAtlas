use crate::model::{Observation, Port};
use std::net::Ipv4Addr;

// XML preserves version and script output that nmap's grepable format drops.
pub fn parse_nmap(xml: &str, ip: Ipv4Addr, interface: &str) -> Result<Observation, String> {
    // Nmap emits this fixed, empty doctype; keep arbitrary DTDs disabled.
    let xml = xml.replace("<!DOCTYPE nmaprun>", "");
    let doc = roxmltree::Document::parse(&xml).map_err(|e| format!("Invalid nmap output: {e}"))?;
    let host = doc
        .descendants()
        .find(|n| {
            n.has_tag_name("host")
                && n.children().any(|a| {
                    a.has_tag_name("address") && a.attribute("addr") == Some(&ip.to_string())
                })
        })
        .ok_or_else(|| "No host result (scan may have timed out)".to_owned())?;
    let mut o = Observation::new(ip, interface);
    // A successful nmap exit can still contain an incomplete host scan.
    if let Some(scan) = doc
        .descendants()
        .find(|n| n.has_tag_name("scaninfo") && n.attribute("protocol") == Some("tcp"))
    {
        let expected = scan
            .attribute("numservices")
            .and_then(|s| s.parse::<usize>().ok())
            .ok_or("Invalid scan scope")?;
        let scope = parse_port_scope(scan.attribute("services").ok_or("Missing scan scope")?)?;
        let observed: usize = host
            .descendants()
            .filter(|n| n.has_tag_name("extraports"))
            .filter_map(|n| n.attribute("count").and_then(|v| v.parse::<usize>().ok()))
            .sum::<usize>()
            + host
                .descendants()
                .filter(|n| n.has_tag_name("port") && n.attribute("protocol") == Some("tcp"))
                .count();
        if expected != scope.len() || observed != expected {
            return Err(format!("Incomplete TCP scan ({observed}/{expected} ports)"));
        }
        o.port_scope = scope;
    }
    for h in host.descendants().filter(|n| n.has_tag_name("hostname")) {
        if let Some(name) = h.attribute("name").filter(|s| !s.is_empty()) {
            if o.name.is_none() {
                o.name = Some(name.to_owned());
            } else if o.name.as_deref() != Some(name) && !o.aliases.iter().any(|s| s == name) {
                o.aliases.push(name.to_owned());
            }
        }
    }
    if let Some(os) = host.descendants().find(|n| n.has_tag_name("osmatch")) {
        if let Some(name) = os.attribute("name") {
            let accuracy = os
                .attribute("accuracy")
                .map(|a| format!(" ({a}% fingerprint match)"))
                .unwrap_or_default();
            o.os = Some(format!("{name}{accuracy}"));
        }
    }
    let mut counts = std::collections::BTreeMap::<String, u32>::new();
    for extra in host.descendants().filter(|n| n.has_tag_name("extraports")) {
        if let (Some(state), Some(count)) = (
            extra.attribute("state"),
            extra.attribute("count").and_then(|s| s.parse::<u32>().ok()),
        ) {
            *counts.entry(state.to_owned()).or_default() += count;
        }
    }
    for port in host.descendants().filter(|n| n.has_tag_name("port")) {
        if let Some(state) = port
            .children()
            .find(|n| n.has_tag_name("state"))
            .and_then(|n| n.attribute("state"))
        {
            *counts.entry(state.to_owned()).or_default() += 1;
        }
    }
    if !counts.is_empty() {
        o.port_summary = Some(
            counts
                .into_iter()
                .map(|(state, count)| format!("{count} {state}"))
                .collect::<Vec<_>>()
                .join(" · "),
        );
    }
    for port in host.descendants().filter(|n| n.has_tag_name("port")) {
        if !port
            .children()
            .any(|n| n.has_tag_name("state") && n.attribute("state") == Some("open"))
        {
            continue;
        }
        let Some(number) = port.attribute("portid").and_then(|s| s.parse().ok()) else {
            continue;
        };
        let service = port.children().find(|n| n.has_tag_name("service"));
        let attr = |key| {
            service
                .and_then(|n| n.attribute(key))
                .map(decode_nmap_text)
                .unwrap_or_default()
        };
        let mut p = Port {
            number,
            protocol: port.attribute("protocol").unwrap_or("tcp").into(),
            service: attr("name"),
            service_source: attr("method"),
            product: attr("product"),
            version: attr("version"),
            extra: attr("extrainfo"),
            findings: vec![],
            finding_times: Default::default(),
            observed_at: None,
            fingerprinted_at: None,
        };
        if let Some(svc) = service {
            if let Some(device_type) = svc.attribute("devicetype") {
                add_unique(&mut o.findings, format!("Device type: {device_type}"));
            }
            if o.model.is_none()
                && ["printer", "camera", "router", "switch", "storage-misc"]
                    .contains(&svc.attribute("devicetype").unwrap_or(""))
                && !p.product.is_empty()
            {
                o.model = Some(p.product.clone());
                o.model_source = Some("service fingerprint".into());
            }
            for cpe in svc.children().filter(|n| n.has_tag_name("cpe")) {
                if let Some(value) = cpe.text() {
                    add_unique(&mut p.findings, format!("CPE: {value}"));
                }
            }
        }
        for script in port.children().filter(|n| n.has_tag_name("script")) {
            if script_failed(script) {
                let id = script.attribute("id").unwrap_or("unknown script");
                add_unique(
                    &mut o.scan_warnings,
                    format!("{id} ({number}/{})", p.protocol),
                );
                if !o.failed_ports.contains(&number) {
                    o.failed_ports.push(number);
                }
            } else if let Some(value) = script_summary(script) {
                add_unique(&mut p.findings, value);
            }
        }
        o.ports.push(p);
    }
    for script in host
        .descendants()
        .filter(|n| n.has_tag_name("hostscript"))
        .flat_map(|n| n.children().filter(|s| s.has_tag_name("script")))
    {
        if script_failed(script) {
            let id = script.attribute("id").unwrap_or("unknown script");
            add_unique(&mut o.scan_warnings, format!("{id} (host check)"));
            continue;
        }
        if let Some(output) = script.attribute("output") {
            let decoded = decode_nmap_text(output);
            for line in decoded.lines() {
                if let Some((key, value)) = line.trim().split_once(':') {
                    let value = value.trim();
                    if !value.is_empty()
                        && key.eq_ignore_ascii_case("computer name")
                        && o.name.is_none()
                    {
                        o.name = Some(value.to_owned());
                    }
                    if !value.is_empty() && key.eq_ignore_ascii_case("os") && o.os.is_none() {
                        o.os = Some(value.to_owned());
                    }
                }
            }
        }
        if let Some(value) = script_summary(script) {
            add_unique(&mut o.findings, value);
        }
    }
    Ok(o)
}
fn parse_port_scope(value: &str) -> Result<Vec<u16>, String> {
    let mut seen = vec![false; 65536];
    for part in value.split(',') {
        let (start, end) = if let Some((a, b)) = part.split_once('-') {
            (
                a.parse::<u16>().map_err(|_| "Invalid scan scope")?,
                b.parse::<u16>().map_err(|_| "Invalid scan scope")?,
            )
        } else {
            let p = part.parse::<u16>().map_err(|_| "Invalid scan scope")?;
            (p, p)
        };
        if start == 0 || start > end {
            return Err("Invalid scan scope".into());
        }
        for port in start..=end {
            seen[usize::from(port)] = true;
        }
    }
    Ok(seen
        .into_iter()
        .enumerate()
        .filter_map(|(p, yes)| yes.then_some(p as u16))
        .collect())
}
/// Nmap renders non-ASCII response bytes as consecutive \xNN sequences in XML.
/// Decode only valid, printable UTF-8 sequences; keep control or invalid bytes escaped.
fn decode_nmap_text(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(input.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' && bytes.get(i + 1) == Some(&b'x') {
            let start = i;
            let mut encoded = Vec::new();
            while i + 3 < bytes.len() && bytes[i] == b'\\' && bytes[i + 1] == b'x' {
                let high = (bytes[i + 2] as char).to_digit(16);
                let low = (bytes[i + 3] as char).to_digit(16);
                let (Some(high), Some(low)) = (high, low) else {
                    break;
                };
                encoded.push((high * 16 + low) as u8);
                i += 4;
            }
            if !encoded.is_empty() {
                if encoded.iter().any(|b| *b >= 0x80) {
                    if let Ok(text) = std::str::from_utf8(&encoded) {
                        for ch in text.chars() {
                            if ch.is_control() {
                                for byte in ch.to_string().bytes() {
                                    out.push_str(&format!("\\x{byte:02X}"));
                                }
                            } else {
                                out.push(ch);
                            }
                        }
                        continue;
                    }
                }
                out.push_str(&input[start..i]);
                continue;
            }
        }
        let ch = input[i..].chars().next().unwrap();
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}
fn script_failed(script: roxmltree::Node<'_, '_>) -> bool {
    script.attribute("output").is_some_and(|output| {
        output
            .trim_start()
            .to_ascii_lowercase()
            .starts_with("error:")
    })
}
fn script_summary(script: roxmltree::Node<'_, '_>) -> Option<String> {
    let id = script.attribute("id")?;
    let output = script.attribute("output")?.trim();
    if output.is_empty() {
        return None;
    }
    // Bound long certificate or server responses before storing and rendering them.
    let decoded = decode_nmap_text(output);
    let value: String = decoded
        .chars()
        .filter(|c| !c.is_control() || *c == '\n')
        .take(1200)
        .collect();
    Some(format!("{id}: {value}"))
}
fn add_unique(values: &mut Vec<String>, value: String) {
    if !values.contains(&value) {
        values.push(value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_os_ports_web_and_host_names() {
        let xml = r#"<?xml version="1.0"?><nmaprun><host><address addr="192.168.1.9" addrtype="ipv4"/><hostnames><hostname name="nas.local"/><hostname name="files.local"/></hostnames><ports><port protocol="tcp" portid="80"><state state="open"/><service name="http" product="nginx" version="1.24"><cpe>cpe:/a:nginx:nginx:1.24</cpe></service><script id="http-title" output="My &amp; NAS"/></port><port protocol="tcp" portid="443"><state state="closed"/></port></ports><os><osmatch name="Linux 5.x" accuracy="95"/></os><hostscript><script id="smb-os-discovery" output="Computer name: FILES&#xa;OS: Linux"/></hostscript></host></nmaprun>"#;
        let result = parse_nmap(xml, "192.168.1.9".parse().unwrap(), "en0").unwrap();
        assert_eq!(result.name.as_deref(), Some("nas.local"));
        assert_eq!(result.aliases, ["files.local"]);
        assert_eq!(
            result.os.as_deref(),
            Some("Linux 5.x (95% fingerprint match)")
        );
        assert_eq!(result.ports.len(), 1);
        assert!(result.ports[0].summary().contains("nginx 1.24"));
        assert!(result.ports[0]
            .findings
            .iter()
            .any(|s| s.contains("My & NAS")));
        assert!(result
            .findings
            .iter()
            .any(|s| s.contains("Computer name: FILES")));
    }
    #[test]
    fn missing_host_is_not_success() {
        assert!(parse_nmap("<nmaprun/>", "192.168.1.9".parse().unwrap(), "en0").is_err());
    }
    #[test]
    fn parses_local_nmap_xml_when_available() {
        let Ok(output) = std::process::Command::new("nmap")
            .args(["-n", "-Pn", "-sT", "-p", "1", "-oX", "-", "127.0.0.1"])
            .output()
        else {
            return;
        };
        assert!(output.status.success());
        let xml = String::from_utf8(output.stdout).unwrap();
        assert!(parse_nmap(&xml, "127.0.0.1".parse().unwrap(), "lo0").is_ok());
    }
    #[test]
    #[ignore = "runs nmap against an ephemeral loopback HTTP server"]
    fn recognizes_live_web_service() {
        use std::{
            io::{Read, Write},
            net::TcpListener,
            sync::{
                atomic::{AtomicBool, Ordering},
                Arc,
            },
            thread,
            time::Duration,
        };
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        listener.set_nonblocking(true).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = stop.clone();
        let server = thread::spawn(move || {
            while !stopped.load(Ordering::Relaxed) {
                if let Ok((mut stream, _)) = listener.accept() {
                    let _ = stream.set_read_timeout(Some(Duration::from_millis(500)));
                    let mut buf = [0; 1024];
                    let _ = stream.read(&mut buf);
                    let body = "<html><title>NetAtlas Local Test</title></html>";
                    let _=write!(stream,"HTTP/1.1 200 OK\r\nServer: NetAtlas-Test\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",body.len(),body);
                } else {
                    thread::sleep(Duration::from_millis(10));
                }
            }
        });
        let output = std::process::Command::new("nmap")
            .args([
                "-n",
                "-Pn",
                "-sT",
                "-sV",
                "--version-light",
                "--host-timeout",
                "30s",
                "-p",
                &port.to_string(),
                "--script",
                "http-title,http-server-header",
                "-oX",
                "-",
                "127.0.0.1",
            ])
            .output()
            .unwrap();
        stop.store(true, Ordering::Relaxed);
        server.join().unwrap();
        assert!(output.status.success());
        let xml = String::from_utf8(output.stdout).unwrap();
        let o = parse_nmap(&xml, "127.0.0.1".parse().unwrap(), "lo0").unwrap();
        let p = o
            .ports
            .iter()
            .find(|p| p.number == port)
            .expect("open HTTP port");
        assert!(
            p.findings.iter().any(|f| f.contains("NetAtlas Local Test")),
            "{:?}",
            p.findings
        );
    }
    #[test]
    fn script_errors_are_reported_as_warnings_not_service_data() {
        let xml = r#"<nmaprun><host><address addr="192.168.1.9"/><ports><port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/><script id="rpcinfo" output="ERROR: Script execution failed (use -d to debug)"/><script id="ssh-hostkey" output="SHA256:abc"/></port></ports></host></nmaprun>"#;
        let o = parse_nmap(xml, "192.168.1.9".parse().unwrap(), "en0").unwrap();
        assert_eq!(o.scan_warnings, ["rpcinfo (22/tcp)"]);
        assert_eq!(o.failed_ports, [22]);
        assert_eq!(o.ports[0].findings, ["ssh-hostkey: SHA256:abc"]);
    }
    #[test]
    fn rejects_incomplete_scan_and_tracks_exact_port_scope() {
        let partial = r#"<nmaprun><scaninfo protocol="tcp" numservices="4" services="22,80,62078-62079"/><host><address addr="192.168.1.9"/><ports><extraports state="closed" count="2"/><port protocol="tcp" portid="22"><state state="open"/></port></ports></host></nmaprun>"#;
        let ip = "192.168.1.9".parse().unwrap();
        assert!(parse_nmap(partial, ip, "en0").unwrap_err().contains("3/4"));
        let complete = partial.replace("count=\"2\"", "count=\"3\"");
        let o = parse_nmap(&complete, ip, "en0").unwrap();
        assert_eq!(o.port_scope, [22, 80, 62078, 62079]);
    }
    #[test]
    fn decodes_nmap_utf8_escapes_without_emitting_control_bytes() {
        assert_eq!(
            decode_nmap_text(r"\xE5\xB0\x8F\xE7\xB1\xB3 router"),
            "小米 router"
        );
        assert_eq!(
            decode_nmap_text(r"literal \x1B and invalid \xFF"),
            r"literal \x1B and invalid \xFF"
        );
        assert_eq!(decode_nmap_text(r"\x中文"), r"\x中文");
        assert_eq!(decode_nmap_text(r"\xE5\xB0\x8F\x0A"), "小\\x0A");
        let xml = r#"<nmaprun><host><address addr="192.168.1.9"/><ports><port protocol="tcp" portid="80"><state state="open"/><script id="http-title" output="\xE5\xB0\x8F\xE7\xB1\xB3"/></port></ports></host></nmaprun>"#;
        let o = parse_nmap(xml, "192.168.1.9".parse().unwrap(), "en0").unwrap();
        assert_eq!(o.ports[0].findings, ["http-title: 小米"]);
    }
}
