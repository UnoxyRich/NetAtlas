//! Names from IANA's Service Name and Transport Protocol Port Number Registry.
//! A registration describes an assignment, not proof of the service on a host.
use std::{collections::HashMap, sync::OnceLock};

const IANA_CSV: &[u8] = include_bytes!("../data/service-names-port-numbers.csv");
#[derive(Debug, Clone, PartialEq, Eq)]
struct Assignment {
    name: String,
    description: String,
}
#[derive(Default)]
struct Registry {
    ports: HashMap<(u16, String), Vec<Assignment>>,
    services: HashMap<(String, String), String>,
}
impl Registry {
    fn parse(data: &[u8]) -> Self {
        let mut registry = Self::default();
        let mut reader = csv::ReaderBuilder::new().flexible(true).from_reader(data);
        for row in reader.records().flatten() {
            let name = row.get(0).unwrap_or("").trim().to_ascii_lowercase();
            let ports = row.get(1).unwrap_or("").trim();
            let protocol = row.get(2).unwrap_or("").trim().to_ascii_lowercase();
            let description = row
                .get(3)
                .unwrap_or("")
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ");
            if name.is_empty() || description.is_empty() {
                continue;
            }
            let key = (name.clone(), protocol.clone());
            // Service-only registrations are the most useful descriptions for DNS-SD.
            if ports.is_empty() {
                registry.services.insert(key, description.clone());
            } else {
                registry
                    .services
                    .entry(key)
                    .or_insert_with(|| description.clone());
            }
            if protocol != "tcp" && protocol != "udp" {
                continue;
            }
            let (start, end) = match ports.split_once('-') {
                Some((a, b)) => match (a.parse::<u16>(), b.parse::<u16>()) {
                    (Ok(a), Ok(b)) if a <= b && b - a <= 4096 => (a, b),
                    _ => continue,
                },
                None => match ports.parse::<u16>() {
                    Ok(port) => (port, port),
                    Err(_) => continue,
                },
            };
            let entry = Assignment { name, description };
            for port in start..=end {
                let entries = registry.ports.entry((port, protocol.clone())).or_default();
                if !entries.iter().any(|existing| existing.name == entry.name) {
                    entries.push(entry.clone());
                }
            }
        }
        registry
    }
    fn port_names(&self, port: u16, protocol: &str) -> Option<&[Assignment]> {
        self.ports
            .get(&(port, protocol.to_ascii_lowercase()))
            .map(Vec::as_slice)
    }
    fn service_description(&self, name: &str, protocol: &str) -> Option<&str> {
        let name = name.to_ascii_lowercase();
        let protocol = protocol.to_ascii_lowercase();
        self.services
            .get(&(name.clone(), protocol))
            .or_else(|| self.services.get(&(name, String::new())))
            .map(String::as_str)
    }
}
fn registry() -> &'static Registry {
    static REGISTRY: OnceLock<Registry> = OnceLock::new();
    REGISTRY.get_or_init(|| Registry::parse(IANA_CSV))
}

/// Registered names for this port, independent of any service fingerprint.
pub fn registered_names(port: u16, protocol: &str) -> Option<String> {
    let records = registry().port_names(port, protocol)?;
    let mut names = records
        .iter()
        .take(3)
        .map(|r| r.name.as_str())
        .collect::<Vec<_>>()
        .join(", ");
    if records.len() > 3 {
        names.push_str(&format!(" +{}", records.len() - 3));
    }
    Some(names)
}
/// Expand a DNS-SD service name using its service registration, not the port assignment.
pub fn describe_advertised(value: &str) -> String {
    let Some((service, port_part)) = value.split_once(" :") else {
        return value.to_owned();
    };
    let Some(service) = service.strip_prefix('_') else {
        return value.to_owned();
    };
    let Some((name, protocol)) = service.split_once("._") else {
        return value.to_owned();
    };
    let protocol = protocol.trim_end_matches(".local.");
    if protocol != "tcp" && protocol != "udp" {
        return value.to_owned();
    }
    let Some(port) = port_part
        .split_whitespace()
        .next()
        .and_then(|s| s.parse::<u16>().ok())
    else {
        return value.to_owned();
    };
    let detail = registry()
        .service_description(name, protocol)
        .map(|s| format!(" · {s}"))
        .unwrap_or_default();
    format!("{name} · {port}/{protocol} (advertised){detail}")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn recognizes_port_protocol_aliases_and_ranges() {
        let registry = registry();
        assert_eq!(registry.port_names(22, "tcp").unwrap()[0].name, "ssh");
        assert!(registry
            .port_names(80, "tcp")
            .unwrap()
            .iter()
            .any(|a| a.name == "http"));
        assert_eq!(registry.port_names(6001, "tcp").unwrap()[0].name, "x11");
        assert!(registry.port_names(49165, "tcp").is_none());
        assert!(registry.port_names(22, "nonsense").is_none());
    }
    #[test]
    fn advertised_name_is_not_replaced_by_unrelated_port_assignment() {
        let output = describe_advertised("_airplay._tcp :7000 (advertised)");
        assert!(output.starts_with("airplay · 7000/tcp (advertised)"));
        assert!(output.contains("streaming"));
        assert!(!output.contains("afs3"));
        assert!(describe_advertised("_smb._tcp :445 (advertised)").contains("Server Message Block"));
        assert_eq!(
            describe_advertised("_companion-link._tcp :49165 (advertised)"),
            "companion-link · 49165/tcp (advertised)"
        );
    }
    #[test]
    fn parser_handles_quoted_csv_and_wildcard_protocol() {
        let data=b"Service Name,Port Number,Transport Protocol,Description\r\nfoo,42,tcp,\"A service, with comma\"\r\nfoo,,,Generic foo\r\nbar,99-100,udp,Example\r\n";
        let parsed = Registry::parse(data);
        assert_eq!(
            parsed.port_names(42, "tcp").unwrap()[0].description,
            "A service, with comma"
        );
        assert_eq!(
            parsed.service_description("foo", "udp"),
            Some("Generic foo")
        );
        assert_eq!(parsed.port_names(100, "udp").unwrap()[0].name, "bar");
        assert!(parsed.port_names(100, "tcp").is_none());
    }
}
