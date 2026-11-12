use crate::model::{Device, DeviceKind};

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DeviceFilter {
    pub expression: String,
    terms: Vec<Term>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
enum Term {
    Types(Vec<DeviceKind>),
    Ports(Vec<u16>),
    Service(String),
    Online,
    Open,
    Text(String),
}
impl DeviceFilter {
    pub fn parse(input: &str) -> Result<Self, String> {
        let mut terms = Vec::new();
        for token in input.split_whitespace() {
            let token = token.to_lowercase();
            if token == "online" || token == "active" {
                terms.push(Term::Online);
                continue;
            }
            if token == "open" || token == "ports:open" {
                terms.push(Term::Open);
                continue;
            }
            if let Some((field, value)) = token.split_once(':') {
                if value.is_empty() {
                    return Err(format!("{field}: needs a value"));
                }
                match field {
                    "type" => {
                        let types = value
                            .split(',')
                            .map(parse_kind)
                            .collect::<Result<Vec<_>, _>>()?
                            .into_iter()
                            .flatten()
                            .collect();
                        terms.push(Term::Types(types));
                    }
                    "port" | "tcp" => {
                        let ports = value
                            .split(',')
                            .map(|v| {
                                v.parse::<u16>()
                                    .ok()
                                    .filter(|p| *p != 0)
                                    .ok_or_else(|| format!("Invalid TCP port: {v}"))
                            })
                            .collect::<Result<Vec<_>, _>>()?;
                        terms.push(Term::Ports(ports));
                    }
                    "service" => terms.push(Term::Service(value.to_owned())),
                    _ => return Err(format!("Unknown filter: {field}")),
                }
            } else {
                terms.push(Term::Text(token));
            }
        }
        Ok(Self {
            expression: input.trim().to_string(),
            terms,
        })
    }
    pub fn is_empty(&self) -> bool {
        self.terms.is_empty()
    }
    pub fn matches(&self, d: &Device) -> bool {
        self.terms.iter().all(|term| match term {
            Term::Types(kinds) => kinds.contains(&d.kind),
            Term::Ports(ports) => d
                .ports
                .iter()
                .any(|p| p.protocol.eq_ignore_ascii_case("tcp") && ports.contains(&p.number)),
            Term::Service(s) => service_matches(d, s),
            Term::Online => d.online(),
            Term::Open => !d.ports.is_empty(),
            Term::Text(s) => searchable(d).contains(s),
        })
    }
    // Unknown types are still eligible for targeted checks; new evidence can change them.
    pub fn candidate(&self, d: &Device) -> bool {
        self.terms.iter().all(|term| match term {
            Term::Types(kinds) => d.kind == DeviceKind::Unknown || kinds.contains(&d.kind),
            Term::Online => d.online() || !d.confirmed,
            Term::Ports(_) | Term::Service(_) | Term::Open | Term::Text(_) => true,
        })
    }
    pub fn targeted_ports(&self) -> Vec<u16> {
        let mut ports = Vec::new();
        for term in &self.terms {
            match term {
                Term::Ports(values) => ports.extend(values),
                Term::Service(value) => ports.extend_from_slice(match value.as_str() {
                    "http" | "web" => &[80, 443, 8000, 8080, 8443],
                    "https" => &[443, 8443],
                    "ssh" => &[22],
                    "smb" => &[139, 445],
                    "rdp" => &[3389],
                    "vnc" | "rfb" => &[5900],
                    "mqtt" => &[1883, 8883],
                    "ipp" | "printer" => &[631, 9100],
                    "rtsp" => &[554, 5000, 7000],
                    "dns" => &[53],
                    "telnet" => &[23],
                    _ => &[],
                }),
                _ => (),
            }
        }
        ports.sort_unstable();
        ports.dedup();
        ports
    }
}
fn service_matches(d: &Device, search: &str) -> bool {
    let aliases: &[&str] = match search {
        "web" => &["http"],
        "dns" => &["dns", "domain"],
        "printer" => &["printer", "ipp", "jetdirect", "pdl"],
        "vnc" => &["vnc", "rfb"],
        _ => &[search],
    };
    d.services
        .iter()
        .any(|s| aliases.iter().any(|alias| s.to_lowercase().contains(alias)))
        || d.ports.iter().any(|p| {
            let text =
                format!("{} {} {} {}", p.service, p.product, p.version, p.extra).to_lowercase();
            aliases.iter().any(|alias| text.contains(alias))
        })
}
pub fn matches_search(d: &Device, search: &str) -> bool {
    if search.trim().is_empty() {
        return true;
    }
    let content = searchable(d);
    search
        .to_lowercase()
        .split_whitespace()
        .all(|word| content.contains(word))
}
fn searchable(d: &Device) -> String {
    format!(
        "{} {} {} {} {} {} {} {} {} {} {} {} {} {} {}",
        d.display_name(),
        d.ip,
        d.kind.label(),
        d.interface,
        d.manufacturer().unwrap_or(""),
        d.name.as_deref().unwrap_or(""),
        d.model.as_deref().unwrap_or(""),
        d.mac.as_deref().unwrap_or(""),
        d.vendor.as_deref().unwrap_or(""),
        d.model_claims.join(" "),
        d.services.join(" "),
        d.os.as_deref().unwrap_or(""),
        d.aliases.join(" "),
        d.findings.join(" "),
        d.ports
            .iter()
            .map(|port| port.summary())
            .collect::<Vec<_>>()
            .join(" ")
    )
    .to_lowercase()
}
fn parse_kind(value: &str) -> Result<Vec<DeviceKind>, String> {
    Ok(match value {
        "pc" => vec![DeviceKind::Computer, DeviceKind::Windows],
        "phone" => vec![DeviceKind::Phone, DeviceKind::Iphone],
        _ => vec![match value {
            "router" | "gateway" => DeviceKind::Router,
            "switch" => DeviceKind::Switch,
            "printer" => DeviceKind::Printer,
            "nas" => DeviceKind::Nas,
            "mac" => DeviceKind::Mac,
            "iphone" => DeviceKind::Iphone,
            "ipad" => DeviceKind::Ipad,
            "speaker" => DeviceKind::Speaker,
            "windows" => DeviceKind::Windows,
            "computer" => DeviceKind::Computer,
            "raspberrypi" | "raspberry-pi" | "raspberry" | "pi" => DeviceKind::RaspberryPi,
            "camera" => DeviceKind::Camera,
            "tv" => DeviceKind::Tv,
            "unknown" => DeviceKind::Unknown,
            _ => return Err(format!("Unknown device type: {value}")),
        }],
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{DeviceStore, Observation, Port};
    fn device() -> Device {
        let mut store = DeviceStore::default();
        let mut o = Observation::new("192.168.1.4".parse().unwrap(), "en0");
        o.name = Some("Office printer".into());
        o.ports_scanned = true;
        o.ports.push(Port {
            number: 631,
            protocol: "tcp".into(),
            service: "ipp".into(),
            ..Default::default()
        });
        store.observe(o);
        store.snapshot().remove(0)
    }
    #[test]
    fn combines_types_ports_and_services() {
        let d = device();
        assert!(
            DeviceFilter::parse("type:printer,mac port:631 service:ipp open online")
                .unwrap()
                .matches(&d)
        );
        assert!(!DeviceFilter::parse("type:mac port:631")
            .unwrap()
            .matches(&d));
        assert!(!DeviceFilter::parse("port:80").unwrap().matches(&d));
        assert_eq!(
            DeviceFilter::parse("service:http port:62078")
                .unwrap()
                .targeted_ports(),
            vec![80, 443, 8000, 8080, 8443, 62078]
        );
    }
    #[test]
    fn search_covers_os_ports_names_and_vendor() {
        let mut d = device();
        d.os = Some("Linux 6.1".into());
        d.vendor = Some("Acme".into());
        assert!(matches_search(&d, "linux 631 acme"));
        assert!(matches_search(&d, "office printer"));
        assert!(!matches_search(&d, "windows 631"));
        assert!(DeviceFilter::parse("service:printer").unwrap().matches(&d));
    }
    #[test]
    fn rejects_invalid_filters() {
        for value in [
            "port:0",
            "port:65536",
            "type:fridge",
            "service:",
            "ports:all",
        ] {
            assert!(DeviceFilter::parse(value).is_err());
        }
    }
}
