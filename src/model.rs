use std::{collections::BTreeMap, net::Ipv4Addr, time::Instant};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeviceKind {
    Router,
    Switch,
    Printer,
    Nas,
    Mac,
    Iphone,
    Ipad,
    Speaker,
    Windows,
    Computer,
    RaspberryPi,
    Phone,
    Camera,
    Tv,
    Unknown,
}
impl DeviceKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::Router => "Router",
            Self::Switch => "Switch",
            Self::Printer => "Printer",
            Self::Nas => "NAS",
            Self::Mac => "Mac",
            Self::Iphone => "iPhone",
            Self::Ipad => "iPad",
            Self::Speaker => "Speaker",
            Self::Windows => "Windows PC",
            Self::Computer => "Computer",
            Self::RaspberryPi => "Raspberry Pi",
            Self::Phone => "Phone",
            Self::Camera => "Camera",
            Self::Tv => "TV",
            Self::Unknown => "Device",
        }
    }
    pub fn icon(self) -> &'static str {
        match self {
            Self::Router => "󰑩",
            Self::Switch => "󰒍",
            Self::Printer => "󰐪",
            Self::Nas => "󰋊",
            Self::Mac => "󰀶",
            Self::Iphone => "󰏲",
            Self::Ipad => "󰓶",
            Self::Speaker => "󰓃",
            Self::Windows => "󰍲",
            Self::Computer => "󰟀",
            Self::RaspberryPi => "󰐿",
            Self::Phone => "󰄜",
            Self::Camera => "󰄀",
            Self::Tv => "󰔌",
            Self::Unknown => "󰇅",
        }
    }
}
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Port {
    pub number: u16,
    pub protocol: String,
    pub service: String,
    pub service_source: String,
    pub product: String,
    pub version: String,
    pub extra: String,
    pub findings: Vec<String>,
    pub finding_times: BTreeMap<String, Instant>,
    pub observed_at: Option<Instant>,
    pub fingerprinted_at: Option<Instant>,
}
impl Port {
    pub fn summary(&self) -> String {
        [
            format!("{}/{}", self.number, self.protocol),
            if self.service_source == "table" && !self.service.is_empty() {
                format!("{} (port guess)", self.service)
            } else {
                self.service.clone()
            },
            self.product.clone(),
            self.version.clone(),
            self.extra.clone(),
        ]
        .into_iter()
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
    }
}
#[derive(Clone, Debug)]
pub struct Observation {
    pub ip: Ipv4Addr,
    pub interface: String,
    pub mac: Option<String>,
    pub name: Option<String>,
    pub friendly_name: Option<String>,
    pub vendor: Option<String>,
    pub vendor_source: Option<String>,
    pub services: Vec<String>,
    pub model: Option<String>,
    pub model_source: Option<String>,
    pub os: Option<String>,
    pub aliases: Vec<String>,
    pub findings: Vec<String>,
    pub scan_warnings: Vec<String>,
    pub failed_ports: Vec<u16>,
    pub scan_retried: bool,
    pub scan_status: Option<String>,
    pub gateway: bool,
    pub local: bool,
    pub ports: Vec<Port>,
    pub ports_complete: bool,
    pub port_scope: Vec<u16>,
    pub ports_scanned: bool,
    pub port_summary: Option<String>,
    pub confirmed: bool,
}
impl Observation {
    pub fn new(ip: Ipv4Addr, interface: &str) -> Self {
        Self {
            ip,
            interface: interface.into(),
            mac: None,
            name: None,
            friendly_name: None,
            vendor: None,
            vendor_source: None,
            services: vec![],
            model: None,
            model_source: None,
            os: None,
            aliases: vec![],
            findings: vec![],
            scan_warnings: vec![],
            failed_ports: vec![],
            scan_retried: false,
            scan_status: None,
            gateway: false,
            local: false,
            ports: vec![],
            ports_complete: false,
            port_scope: vec![],
            ports_scanned: false,
            port_summary: None,
            confirmed: true,
        }
    }
}
#[derive(Clone, Debug)]
pub struct Device {
    pub id: u64,
    pub ip: Ipv4Addr,
    pub interface: String,
    pub mac: Option<String>,
    pub name: Option<String>,
    pub friendly_name: Option<String>,
    pub vendor: Option<String>,
    pub vendor_source: Option<String>,
    pub services: Vec<String>,
    pub model: Option<String>,
    pub model_claims: Vec<String>,
    pub os: Option<String>,
    pub aliases: Vec<String>,
    pub findings: Vec<String>,
    pub scan_warnings: Vec<String>,
    pub scan_status: Option<String>,
    pub ports: Vec<Port>,
    pub ports_scanned_at: Option<Instant>,
    pub port_summary: Option<String>,
    pub port_summary_at: Option<Instant>,
    pub kind: DeviceKind,
    pub kind_reason: &'static str,
    pub gateway: bool,
    pub local: bool,
    pub last_seen: Instant,
    pub confirmed: bool,
    displaced: bool,
}
impl Device {
    pub fn online(&self) -> bool {
        self.local || (self.confirmed && self.last_seen.elapsed().as_secs() < 180)
    }
    pub fn display_name(&self) -> String {
        match (&self.friendly_name, &self.name) {
            (Some(friendly), Some(hostname)) => {
                return if name_quality(friendly) >= name_quality(hostname) {
                    friendly.clone()
                } else {
                    hostname.clone()
                }
            }
            (Some(name), None) | (None, Some(name)) => return name.clone(),
            (None, None) => {}
        }
        if self.local {
            return "This device".into();
        }
        if self.gateway {
            return "Gateway".into();
        }
        let vendor = self.manufacturer().or(self.vendor.as_deref());
        let model = self
            .model
            .as_deref()
            .filter(|model| !self.model_conflicts(model));
        match (vendor, model) {
            (Some(vendor), Some(model))
                if model.to_lowercase().contains(&vendor.to_lowercase()) =>
            {
                format!("{model} (?)")
            }
            (Some(vendor), Some(model)) => format!("{vendor} · {model} (?)"),
            (Some(vendor), None) => format!("{vendor} device"),
            (None, Some(model)) => format!("{model} (?)"),
            (None, None) => self.kind.label().into(),
        }
    }
    fn model_conflicts(&self, model: &str) -> bool {
        let vendor = self.manufacturer().unwrap_or("").to_lowercase();
        vendor.contains("raspberry pi")
            && ["macpro", "macbook", "imac", "macmini"]
                .iter()
                .any(|term| model.to_lowercase().contains(term))
    }
    // This is a triage order based on observed exposure, not a vulnerability score.
    pub fn priority(&self) -> (u8, &'static str) {
        if self.gateway || matches!(self.kind, DeviceKind::Router) {
            return (0, "Gateway / router");
        }
        let detected_web = self
            .ports
            .iter()
            .any(|p| p.service_source == "probed" && p.service.to_lowercase().contains("http"));
        let advertised_web = self.services.iter().any(|s| {
            ["_http.", "_https.", "_http-alt."]
                .iter()
                .any(|prefix| s.starts_with(prefix))
        });
        let common_web_port = self
            .ports
            .iter()
            .any(|p| [80, 443, 8000, 8080, 8443].contains(&p.number));
        if detected_web {
            return (1, "Web service detected");
        }
        if advertised_web {
            return (1, "Web service advertised");
        }
        if common_web_port {
            return (1, "Common web port open");
        }
        if !self.ports.is_empty()
            || self.services.iter().any(|s| {
                ["_ssh.", "_smb.", "_nfs.", "_rdp.", "_rfb.", "_rtsp."]
                    .iter()
                    .any(|prefix| s.starts_with(prefix))
            })
        {
            return (2, "Open or advertised services");
        }
        if matches!(
            self.kind,
            DeviceKind::Switch
                | DeviceKind::Nas
                | DeviceKind::Camera
                | DeviceKind::Printer
                | DeviceKind::Computer
                | DeviceKind::Windows
                | DeviceKind::Mac
                | DeviceKind::RaspberryPi
        ) {
            return (3, "Device type");
        }
        if matches!(
            self.kind,
            DeviceKind::Iphone
                | DeviceKind::Ipad
                | DeviceKind::Phone
                | DeviceKind::Tv
                | DeviceKind::Speaker
        ) {
            return (5, "No higher-priority service observed");
        }
        (4, "Unknown exposure")
    }
    pub fn manufacturer(&self) -> Option<&str> {
        let mac = self.mac.as_deref()?;
        let first = u8::from_str_radix(mac.split(':').next()?, 16).ok()?;
        if first & 2 != 0 {
            return None;
        }
        oui_data::lookup(mac).map(|r| r.organization())
    }
}
#[derive(Default)]
pub struct DeviceStore {
    devices: BTreeMap<u64, Device>,
    next_id: u64,
}
impl DeviceStore {
    pub fn observe(&mut self, o: Observation) {
        // A stale neighbor-cache entry must not replace a currently confirmed owner.
        if !o.confirmed
            && o.mac.as_ref().is_some_and(|mac| {
                self.devices.values().any(|d| {
                    !d.displaced
                        && d.interface == o.interface
                        && d.ip == o.ip
                        && d.online()
                        && d.mac.as_ref().is_some_and(|current| current != mac)
                })
            })
        {
            return;
        }
        // A MAC match is stronger than a provisional, IP-only observation.
        let matching_mac = o.mac.as_ref().and_then(|mac| {
            self.devices
                .values()
                .find(|d| d.interface == o.interface && d.mac.as_ref() == Some(mac))
                .map(|d| d.id)
        });
        let matching_ip = self
            .devices
            .values()
            .filter(|d| {
                !d.displaced
                    && d.interface == o.interface
                    && d.ip == o.ip
                    && (o.mac.is_none() || d.mac.is_none() || d.mac == o.mac)
            })
            .max_by_key(|d| d.last_seen)
            .map(|d| d.id);
        let id = matching_mac.or(matching_ip).unwrap_or_else(|| {
            self.next_id += 1;
            self.next_id
        });
        if o.mac.is_some() {
            // Keep historical identities, but only show the most recently observed MAC for an IP.
            for d in self
                .devices
                .values_mut()
                .filter(|d| d.id != id && d.interface == o.interface && d.ip == o.ip)
            {
                d.displaced = true;
            }
        }
        let d = self.devices.entry(id).or_insert_with(|| Device {
            id,
            ip: o.ip,
            interface: o.interface.clone(),
            mac: None,
            name: None,
            friendly_name: None,
            vendor: None,
            vendor_source: None,
            services: vec![],
            model: None,
            model_claims: vec![],
            os: None,
            aliases: vec![],
            findings: vec![],
            scan_warnings: vec![],
            scan_status: None,
            ports: vec![],
            ports_scanned_at: None,
            port_summary: None,
            port_summary_at: None,
            kind: DeviceKind::Unknown,
            kind_reason: "No identifying evidence",
            gateway: false,
            local: false,
            last_seen: Instant::now(),
            confirmed: false,
            displaced: false,
        });
        d.displaced = false;
        if d.ip != o.ip {
            d.gateway = o.gateway;
            d.local = o.local;
        }
        d.ip = o.ip;
        d.gateway |= o.gateway;
        d.local |= o.local;
        let confirmed = o.confirmed;
        merge_details(d, o);
        if confirmed {
            d.confirmed = true;
            d.last_seen = Instant::now();
        }
    }
    pub fn enrich(&mut self, o: Observation) {
        if let Some(d) = self
            .devices
            .values_mut()
            .filter(|d| {
                !d.displaced && d.ip == o.ip && d.interface == o.interface && d.mac == o.mac
            })
            .max_by_key(|d| d.last_seen)
        {
            let responded = o.ports_scanned && !o.ports.is_empty();
            merge_details(d, o);
            if responded {
                d.confirmed = true;
                d.last_seen = Instant::now();
            }
        }
    }
    pub fn remove_service(&mut self, ip: Ipv4Addr, interface: &str, service: &str) {
        if let Some(device) = self
            .devices
            .values_mut()
            .find(|d| !d.displaced && d.ip == ip && d.interface == interface)
        {
            device.services.retain(|item| item != service);
            (device.kind, device.kind_reason) = classify(device);
        }
    }
    pub fn active_mac(&self, ip: Ipv4Addr, interface: &str) -> Option<String> {
        self.devices
            .values()
            .find(|d| !d.displaced && d.ip == ip && d.interface == interface)
            .and_then(|d| d.mac.clone())
    }
    pub fn set_scan_status_for(
        &mut self,
        ip: Ipv4Addr,
        interface: &str,
        mac: Option<&str>,
        status: String,
    ) {
        if let Some(d) = self
            .devices
            .values_mut()
            .filter(|d| {
                !d.displaced && d.ip == ip && d.interface == interface && d.mac.as_deref() == mac
            })
            .max_by_key(|d| d.last_seen)
        {
            d.scan_status = Some(status);
        }
    }
    pub fn snapshot(&self) -> Vec<Device> {
        self.devices
            .values()
            .filter(|d| !d.displaced)
            .cloned()
            .collect()
    }
}
fn meaningful_name(value: &str) -> bool {
    let normalized = value
        .trim()
        .replace('\\', "")
        .trim_end_matches('.')
        .to_lowercase();
    !normalized.is_empty()
        && ![
            "?",
            "(none)",
            "(none).local",
            "unknown",
            "unknown.local",
            "localhost",
            "localhost.local",
        ]
        .contains(&normalized.as_str())
}

/// Prefer readable hostnames to generated Bonjour identifiers, without guessing their meaning.
fn name_quality(value: &str) -> u8 {
    if !meaningful_name(value) {
        return 0;
    }
    let normalized = value.trim().trim_end_matches('.').to_ascii_lowercase();
    let host = normalized.strip_suffix(".local").unwrap_or(&normalized);
    let leading = host.split(['-', '_', '.']).next().unwrap_or("");
    if leading.len() >= 12 && leading.bytes().all(|b| b.is_ascii_hexdigit()) {
        return 1;
    }
    let compact: String = host.chars().filter(|c| *c != '-').collect();
    if compact.len() >= 16 && compact.bytes().all(|b| b.is_ascii_hexdigit()) {
        return 1;
    }
    2
}

fn merge_details(d: &mut Device, o: Observation) {
    if o.mac.is_some() {
        d.mac = o.mac;
    }
    if let Some(name) = o.name.filter(|s| meaningful_name(s)) {
        match d.name.as_ref() {
            None => d.name = Some(name),
            Some(existing) if *existing != name && name_quality(&name) > name_quality(existing) => {
                let previous = d.name.replace(name).unwrap();
                if !d.aliases.contains(&previous) {
                    d.aliases.push(previous);
                }
            }
            Some(existing) if *existing != name && !d.aliases.contains(&name) => {
                d.aliases.push(name)
            }
            _ => {}
        }
    }
    if let Some(name) = o.friendly_name.filter(|s| meaningful_name(s)) {
        if d.friendly_name
            .as_ref()
            .is_none_or(|existing| name_quality(&name) > name_quality(existing))
        {
            d.friendly_name = Some(name);
        }
    }
    if o.vendor.is_some() {
        d.vendor = o.vendor;
        d.vendor_source = o.vendor_source;
    }
    if let Some(model) = o.model {
        let claim = format!(
            "{} ({})",
            model,
            o.model_source.as_deref().unwrap_or("advertised")
        );
        if !d.model_claims.contains(&claim) {
            d.model_claims.push(claim);
        }
        d.model = Some(model);
    }
    if o.os.is_some() {
        d.os = o.os;
    }
    if o.scan_status.is_some() {
        d.scan_status = o.scan_status;
    }
    for (target, additions) in [
        (&mut d.services, o.services),
        (&mut d.aliases, o.aliases),
        (&mut d.findings, o.findings),
    ] {
        for value in additions {
            if !value.is_empty() && !target.contains(&value) {
                target.push(value);
            }
        }
    }
    let now = Instant::now();
    if o.ports_complete {
        if o.port_scope.is_empty() {
            d.ports.clear();
        }
        d.scan_warnings.clear();
        d.port_summary_at = o.port_summary.as_ref().map(|_| now);
        d.port_summary = o.port_summary;
    }
    if !o.port_scope.is_empty() {
        // Keep previously fingerprinted details for ports still observed open.
        d.ports.retain(|p| {
            p.protocol != "tcp"
                || !o.port_scope.contains(&p.number)
                || o.ports
                    .iter()
                    .any(|new| new.protocol == p.protocol && new.number == p.number)
        });
    }
    if o.ports_scanned {
        d.ports_scanned_at = Some(now);
    }
    for warning in o.scan_warnings {
        if !d.scan_warnings.contains(&warning) {
            d.scan_warnings.push(warning);
        }
    }
    for mut port in o.ports {
        if o.ports_scanned {
            port.observed_at = Some(now);
        }
        if !port.product.is_empty() || !port.version.is_empty() || !port.extra.is_empty() {
            port.fingerprinted_at = Some(now);
        }
        if o.ports_scanned {
            for finding in &port.findings {
                port.finding_times.insert(finding.clone(), now);
            }
        }
        if let Some(existing) = d
            .ports
            .iter_mut()
            .find(|p| p.number == port.number && p.protocol == port.protocol)
        {
            if o.ports_complete {
                *existing = port;
                continue;
            }
            existing.observed_at = port.observed_at.or(existing.observed_at);
            // A table guess must not overwrite a prior active service fingerprint.
            if port.service_source == "probed" || existing.service_source != "probed" {
                if !port.service.is_empty() {
                    if port.service_source == "probed"
                        && existing.service_source == "probed"
                        && port.service != existing.service
                    {
                        existing.product.clear();
                        existing.version.clear();
                        existing.extra.clear();
                        existing.findings.clear();
                        existing.finding_times.clear();
                        existing.fingerprinted_at = None;
                    }
                    existing.service = port.service;
                    existing.service_source = port.service_source;
                }
                if !port.product.is_empty() {
                    existing.product = port.product;
                }
                if !port.version.is_empty() {
                    existing.version = port.version;
                }
                if !port.extra.is_empty() {
                    existing.extra = port.extra;
                }
                existing.fingerprinted_at = port.fingerprinted_at.or(existing.fingerprinted_at);
            }
            for finding in port.findings {
                if let Some((id, _)) = finding.split_once(": ") {
                    if id != "CPE" {
                        // A newer result from the same script replaces its old result.
                        existing.findings.retain(|prior| {
                            prior == &finding
                                || prior
                                    .split_once(": ")
                                    .is_none_or(|(old_id, _)| old_id != id)
                        });
                        existing
                            .finding_times
                            .retain(|prior, _| existing.findings.contains(prior));
                    }
                }
                if let Some(time) = port.finding_times.get(&finding) {
                    existing.finding_times.insert(finding.clone(), *time);
                }
                if !existing.findings.contains(&finding) {
                    existing.findings.push(finding);
                }
            }
        } else {
            d.ports.push(port);
        }
    }
    d.ports.sort_by_key(|p| p.number);
    (d.kind, d.kind_reason) = classify(d);
}

fn classify(d: &Device) -> (DeviceKind, &'static str) {
    if d.gateway {
        return (DeviceKind::Router, "Configured gateway");
    }
    if d.local && cfg!(target_os = "macos") {
        return (DeviceKind::Mac, "Local macOS host");
    }
    let names = format!(
        "{} {}",
        d.name.as_deref().unwrap_or(""),
        d.friendly_name.as_deref().unwrap_or("")
    )
    .to_lowercase();
    let vendor = format!(
        "{} {}",
        d.manufacturer().unwrap_or(""),
        d.vendor.as_deref().unwrap_or("")
    )
    .to_lowercase();
    let model = d.model.as_deref().unwrap_or("").to_lowercase();
    let os = d.os.as_deref().unwrap_or("").to_lowercase();
    let evidence = format!(
        "{} {} {} {} {}",
        names,
        model,
        d.services.join(" "),
        d.ports
            .iter()
            .map(Port::summary)
            .collect::<Vec<_>>()
            .join(" "),
        d.findings.join(" ")
    )
    .to_lowercase();
    if names.contains("raspberry") {
        return (DeviceKind::RaspberryPi, "Device name");
    }
    if vendor.contains("raspberry pi") {
        return (DeviceKind::RaspberryPi, "MAC or vendor claim");
    }
    if names.contains("iphone") {
        return (DeviceKind::Iphone, "Device name");
    }
    if model.starts_with("iphone") {
        return (DeviceKind::Iphone, "Advertised model");
    }
    if names.contains("ipad") {
        return (DeviceKind::Ipad, "Device name");
    }
    if model.starts_with("ipad") {
        return (DeviceKind::Ipad, "Advertised model");
    }
    if ["apple-tv", "apple tv", "appletv", "smart tv"]
        .iter()
        .any(|s| names.contains(s))
    {
        return (DeviceKind::Tv, "Device name");
    }
    if model.starts_with("appletv") {
        return (DeviceKind::Tv, "Advertised model");
    }
    if names.contains("homepod") {
        return (DeviceKind::Speaker, "Device name");
    }
    if model.starts_with("audioaccessory") {
        return (DeviceKind::Speaker, "Advertised model");
    }
    let mac_named = [
        "macbook",
        "macmini",
        "mac-mini",
        "mac mini",
        "macstudio",
        "mac-studio",
        "mac studio",
        "macpro",
        "mac-pro",
        "imac",
    ]
    .iter()
    .any(|s| names.contains(s));
    let apple_model = model.starts_with("macbook")
        || model.starts_with("imac")
        || model.strip_prefix("mac").is_some_and(|tail| {
            tail.chars().next().is_some_and(|c| c.is_ascii_digit()) && tail.contains(',')
        });
    if mac_named {
        return (DeviceKind::Mac, "Device name");
    }
    if apple_model && !d.model_conflicts(&model) {
        return (DeviceKind::Mac, "Advertised model");
    }
    if ["_ipp.", "_ipps.", "_printer.", "_pdl-datastream."]
        .iter()
        .any(|s| evidence.contains(s))
    {
        return (DeviceKind::Printer, "Advertised printer service");
    }
    if names.contains("printer") || model.contains("printer") {
        return (DeviceKind::Printer, "Name or model");
    }
    if d.ports
        .iter()
        .any(|p| p.protocol == "tcp" && p.number == 9100)
    {
        return (DeviceKind::Printer, "Open port 9100");
    }
    if ["synology", "diskstation", "qnap", "_nfs.", " nas"]
        .iter()
        .any(|s| evidence.contains(s))
    {
        return (DeviceKind::Nas, "Name, model or NFS service");
    }
    if names.contains("switch") || model.contains("switch") {
        return (DeviceKind::Switch, "Name or model");
    }
    if names.contains("windows") {
        return (DeviceKind::Windows, "Device name");
    }
    if os.contains("windows") {
        return (DeviceKind::Windows, "OS fingerprint");
    }
    if names.contains("router") || names.contains("gateway") {
        return (DeviceKind::Router, "Device name");
    }
    if ["camera", "ezvizc", "_rtsp.", "554/tcp"]
        .iter()
        .any(|s| evidence.contains(s))
    {
        return (DeviceKind::Camera, "Name, model or RTSP service");
    }
    if names.contains("android") || names.contains("phone") {
        return (DeviceKind::Phone, "Device name");
    }
    if os.contains("mac os x") || os.contains("macos") {
        return (DeviceKind::Mac, "OS fingerprint");
    }
    if evidence.contains("_workstation.") {
        return (DeviceKind::Computer, "Workstation service");
    }
    (DeviceKind::Unknown, "No identifying evidence")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn classifies_identity_without_trusting_advertised_mac_model() {
        let mut s = DeviceStore::default();
        let mut o = Observation::new("192.168.1.57".parse().unwrap(), "en0");
        o.name = Some("raspberry.local".into());
        o.mac = Some("2C:CF:67:A8:1F:C5".into());
        o.model = Some("MacPro".into());
        o.model_source = Some("mDNS".into());
        s.observe(o);
        let d = &s.snapshot()[0];
        assert_eq!(d.kind, DeviceKind::RaspberryPi);
        assert_eq!(d.model_claims, ["MacPro (mDNS)"]);
        let mut s = DeviceStore::default();
        let mut o = Observation::new("192.168.1.93".parse().unwrap(), "en0");
        o.name = Some("WilliamdeMac-mini.local".into());
        s.observe(o);
        assert_eq!(s.snapshot()[0].kind, DeviceKind::Mac);
    }
    #[test]
    fn same_mac_moves_but_distinct_mac_does_not_merge() {
        let mut s = DeviceStore::default();
        let mut o = Observation::new("192.168.1.2".parse().unwrap(), "en0");
        o.mac = Some("00:11:22:33:44:55".into());
        s.observe(o.clone());
        o.ip = "192.168.1.3".parse().unwrap();
        s.observe(o.clone());
        assert_eq!(s.snapshot().len(), 1);
        o.mac = Some("00:11:22:33:44:66".into());
        s.observe(o);
        assert_eq!(s.devices.len(), 2);
        assert_eq!(s.snapshot().len(), 1);
        assert_eq!(s.snapshot()[0].mac.as_deref(), Some("00:11:22:33:44:66"));
    }
    #[test]
    fn complete_scan_removes_old_ports_and_quick_scan_keeps_details() {
        let mut s = DeviceStore::default();
        let ip = "192.168.1.9".parse().unwrap();
        let mut o = Observation::new(ip, "en0");
        o.ports_scanned = true;
        o.ports.push(Port {
            number: 80,
            protocol: "tcp".into(),
            service: "http".into(),
            product: "nginx".into(),
            findings: vec!["http-title: Home".into()],
            ..Default::default()
        });
        s.observe(o);
        let mut quick = Observation::new(ip, "en0");
        quick.ports_scanned = true;
        quick.ports.push(Port {
            number: 80,
            protocol: "tcp".into(),
            service: "http".into(),
            ..Default::default()
        });
        s.enrich(quick);
        let devices = s.snapshot();
        assert_eq!(devices[0].ports[0].product, "nginx");
        assert!(!devices[0].ports[0].findings.is_empty());
        let mut deep = Observation::new(ip, "en0");
        deep.ports_scanned = true;
        deep.ports_complete = true;
        s.enrich(deep);
        assert!(s.snapshot()[0].ports.is_empty());
    }
    #[test]
    fn delayed_enrichment_does_not_attach_to_replacement_mac() {
        let mut s = DeviceStore::default();
        let ip = "192.168.1.5".parse().unwrap();
        let mut old = Observation::new(ip, "en0");
        old.mac = Some("00:11:22:33:44:55".into());
        s.observe(old.clone());
        let mut new = Observation::new(ip, "en0");
        new.mac = Some("00:11:22:33:44:66".into());
        s.observe(new);
        old.name = Some("old-host".into());
        s.enrich(old);
        let devices = s.snapshot();
        assert!(devices
            .iter()
            .find(|d| d.mac.as_deref() == Some("00:11:22:33:44:66"))
            .unwrap()
            .name
            .is_none());
    }
    #[test]
    fn uses_vendor_model_fallback_and_sorts_by_observed_exposure() {
        let mut s = DeviceStore::default();
        let ip = "192.168.1.9".parse().unwrap();
        let mut o = Observation::new(ip, "en0");
        o.vendor = Some("Acme".into());
        o.model = Some("Cam 2".into());
        o.name = Some("(none).local".into());
        s.observe(o);
        let mut d = s.snapshot().remove(0);
        assert_eq!(d.display_name(), "Acme · Cam 2 (?)");
        let phone_priority = {
            d.kind = DeviceKind::Iphone;
            d.priority().0
        };
        d.ports.push(Port {
            number: 443,
            protocol: "tcp".into(),
            service: "https".into(),
            ..Default::default()
        });
        assert!(d.priority().0 < phone_priority);
        let mut pi = Observation::new("192.168.1.57".parse().unwrap(), "en0");
        pi.mac = Some("2C:CF:67:A8:1F:C5".into());
        pi.model = Some("MacPro".into());
        s.observe(pi);
        let devices = s.snapshot();
        let pi = devices
            .iter()
            .find(|d| d.ip.to_string() == "192.168.1.57")
            .unwrap();
        assert!(!pi.display_name().contains("MacPro"));
    }
    #[test]
    fn bonjour_claim_does_not_mark_device_online() {
        let mut s = DeviceStore::default();
        let mut o = Observation::new("192.168.1.4".parse().unwrap(), "en0");
        o.confirmed = false;
        s.observe(o.clone());
        assert!(!s.snapshot()[0].online());
        o.confirmed = true;
        s.observe(o);
        assert!(s.snapshot()[0].online());
    }
    #[test]
    fn mac_match_wins_over_provisional_ip_and_delayed_ping_does_not_restore_old_mac() {
        let mut s = DeviceStore::default();
        let mut old = Observation::new("192.168.1.10".parse().unwrap(), "en0");
        old.mac = Some("00:11:22:33:44:55".into());
        s.observe(old.clone());
        let mut current = Observation::new(old.ip, "en0");
        current.mac = Some("00:11:22:33:44:66".into());
        s.observe(current);
        let ping = Observation::new(old.ip, "en0");
        s.observe(ping);
        let visible = s.snapshot();
        assert_eq!(visible.len(), 1);
        assert_eq!(visible[0].mac.as_deref(), Some("00:11:22:33:44:66"));
        old.ip = "192.168.1.11".parse().unwrap();
        s.observe(Observation::new(old.ip, "en0"));
        s.observe(old);
        assert_eq!(
            s.snapshot()
                .iter()
                .filter(|d| d.ip.to_string() == "192.168.1.11")
                .count(),
            1
        );
        assert_eq!(s.devices.len(), 3);
    }
    #[test]
    fn complete_top_ports_scan_preserves_device_specific_ports_outside_scope() {
        let mut store = DeviceStore::default();
        let ip = "192.168.1.2".parse().unwrap();
        let mut first = Observation::new(ip, "en0");
        first.ports = vec![
            Port {
                number: 80,
                protocol: "tcp".into(),
                ..Default::default()
            },
            Port {
                number: 62078,
                protocol: "tcp".into(),
                ..Default::default()
            },
        ];
        store.observe(first);
        let mut next = Observation::new(ip, "en0");
        next.ports_complete = true;
        next.port_scope = vec![22, 80, 443];
        store.enrich(next);
        assert_eq!(
            store.snapshot()[0]
                .ports
                .iter()
                .map(|p| p.number)
                .collect::<Vec<_>>(),
            vec![62078]
        );
    }
    #[test]
    fn explicit_device_names_and_models_override_ambiguous_os_and_services() {
        let mut store = DeviceStore::default();
        let ip = "192.168.1.9".parse().unwrap();
        let mut tv = Observation::new(ip, "en0");
        tv.name = Some("Apple-TV.local".into());
        tv.os = Some("Apple macOS 12 (100% match)".into());
        tv.services.push("_ipp._tcp :631 (advertised)".into());
        store.observe(tv);
        assert_eq!(store.snapshot()[0].kind, DeviceKind::Tv);
        let mut tablet = Observation::new("192.168.1.10".parse().unwrap(), "en0");
        tablet.model = Some("iPad14,3".into());
        store.observe(tablet);
        assert_eq!(
            store
                .snapshot()
                .iter()
                .find(|d| d.ip.to_string() == "192.168.1.10")
                .unwrap()
                .kind,
            DeviceKind::Ipad
        );
        let mut studio = Observation::new("192.168.1.11".parse().unwrap(), "en0");
        studio.model = Some("Mac16,9".into());
        store.observe(studio);
        assert_eq!(
            store
                .snapshot()
                .iter()
                .find(|d| d.ip.to_string() == "192.168.1.11")
                .unwrap()
                .kind,
            DeviceKind::Mac
        );
    }
    #[test]
    fn readable_hostname_replaces_generated_bonjour_name() {
        let mut store = DeviceStore::default();
        let ip = "192.168.1.161".parse().unwrap();
        let mut a = Observation::new(ip, "en0");
        a.name = Some("5347944a98ed441e844427002b4f6ad5-hap.local".into());
        store.observe(a);
        let mut b = Observation::new(ip, "en0");
        b.name = Some("homeassistant.local".into());
        store.observe(b);
        assert_eq!(store.snapshot()[0].display_name(), "homeassistant.local");
    }
    #[test]
    fn camera_vendor_alone_does_not_prove_camera_type() {
        let mut store = DeviceStore::default();
        let mut o = Observation::new("192.168.1.28".parse().unwrap(), "en0");
        o.vendor = Some("Hangzhou Ezviz Software".into());
        store.observe(o);
        assert_eq!(store.snapshot()[0].kind, DeviceKind::Unknown);
    }
    #[test]
    fn cached_neighbor_is_unconfirmed_until_a_real_response() {
        let mut store = DeviceStore::default();
        let ip = "192.168.1.2".parse().unwrap();
        let mut cache = Observation::new(ip, "en0");
        cache.mac = Some("00:11:22:33:44:55".into());
        cache.confirmed = false;
        store.observe(cache.clone());
        let mut name = Observation::new(ip, "en0");
        name.name = Some("host.local".into());
        store.enrich(name);
        assert!(!store.snapshot()[0].online());
        let mut ports = Observation::new(ip, "en0");
        ports.mac = cache.mac.clone();
        ports.ports_scanned = true;
        ports.ports.push(Port {
            number: 22,
            protocol: "tcp".into(),
            ..Default::default()
        });
        store.enrich(ports);
        assert!(store.snapshot()[0].online());
        store.devices.values_mut().next().unwrap().last_seen =
            Instant::now() - std::time::Duration::from_secs(181);
        store.observe(cache);
        assert!(!store.snapshot()[0].online());
    }
    #[test]
    fn vendor_alone_is_not_enough_to_identify_a_nas() {
        let mut store = DeviceStore::default();
        let mut o = Observation::new("192.168.1.40".parse().unwrap(), "en0");
        o.vendor = Some("Synology Incorporated".into());
        store.observe(o);
        assert_eq!(store.snapshot()[0].kind, DeviceKind::Unknown);
    }
    #[test]
    fn stale_cache_cannot_displace_a_confirmed_mac() {
        let mut store = DeviceStore::default();
        let ip = "192.168.1.7".parse().unwrap();
        let mut active = Observation::new(ip, "en0");
        active.mac = Some("00:11:22:33:44:55".into());
        store.observe(active);
        let mut cache = Observation::new(ip, "en0");
        cache.mac = Some("00:11:22:33:44:66".into());
        cache.confirmed = false;
        store.observe(cache);
        assert_eq!(
            store.snapshot()[0].mac.as_deref(),
            Some("00:11:22:33:44:55")
        );
    }
    #[test]
    fn unknown_identity_scan_cannot_attach_after_mac_becomes_known() {
        let mut store = DeviceStore::default();
        let ip = "192.168.1.7".parse().unwrap();
        let mut active = Observation::new(ip, "en0");
        active.mac = Some("00:11:22:33:44:55".into());
        store.observe(active);
        let mut stale = Observation::new(ip, "en0");
        stale.name = Some("stale.local".into());
        store.enrich(stale);
        assert!(store.snapshot()[0].name.is_none());
        assert_eq!(
            store.active_mac(ip, "en0").as_deref(),
            Some("00:11:22:33:44:55")
        );
    }
    #[test]
    fn known_identity_scan_cannot_attach_to_an_unknown_new_occupant() {
        let mut store = DeviceStore::default();
        let ip = "192.168.1.7".parse().unwrap();
        store.observe(Observation::new(ip, "en0"));
        let mut stale = Observation::new(ip, "en0");
        stale.mac = Some("00:11:22:33:44:55".into());
        stale.name = Some("old.local".into());
        store.enrich(stale);
        assert!(store.snapshot()[0].name.is_none());
        assert!(store.snapshot()[0].mac.is_none());
    }
    #[test]
    fn removed_printer_service_updates_type_without_affecting_other_services() {
        let mut store = DeviceStore::default();
        let ip = "192.168.1.2".parse().unwrap();
        let mut o = Observation::new(ip, "en0");
        o.services = vec![
            "_ipp._tcp :631 (advertised)".into(),
            "_http._tcp :80 (advertised)".into(),
        ];
        store.observe(o);
        assert_eq!(store.snapshot()[0].kind, DeviceKind::Printer);
        store.remove_service(ip, "en0", "_ipp._tcp :631 (advertised)");
        let d = &store.snapshot()[0];
        assert_eq!(d.kind, DeviceKind::Unknown);
        assert_eq!(d.services, ["_http._tcp :80 (advertised)"]);
    }
    #[test]
    fn scoped_rescan_preserves_rich_details_and_their_timestamp() {
        let mut store = DeviceStore::default();
        let ip = "192.168.1.3".parse().unwrap();
        let mut first = Observation::new(ip, "en0");
        first.ports_scanned = true;
        first.ports.push(Port {
            number: 443,
            protocol: "tcp".into(),
            service: "https".into(),
            service_source: "probed".into(),
            product: "nginx".into(),
            findings: vec!["ssl-cert: subject".into()],
            ..Default::default()
        });
        store.observe(first);
        let old = Instant::now() - std::time::Duration::from_secs(60);
        let existing = &mut store.devices.values_mut().next().unwrap().ports[0];
        existing.fingerprinted_at = Some(old);
        existing
            .finding_times
            .insert("ssl-cert: subject".into(), old);
        let mut next = Observation::new(ip, "en0");
        next.ports_scanned = true;
        next.port_scope = vec![443];
        next.ports.push(Port {
            number: 443,
            protocol: "tcp".into(),
            service: "https".into(),
            service_source: "table".into(),
            ..Default::default()
        });
        store.enrich(next);
        let port = &store.snapshot()[0].ports[0];
        assert_eq!(port.product, "nginx");
        assert_eq!(port.service_source, "probed");
        assert_eq!(port.fingerprinted_at, Some(old));
        assert_eq!(port.findings, ["ssl-cert: subject"]);
        assert_eq!(port.finding_times.get("ssl-cert: subject"), Some(&old));
        assert!(port.observed_at.unwrap() > old);
    }
    #[test]
    fn newer_script_output_replaces_older_result_for_same_port() {
        let mut store = DeviceStore::default();
        let ip = "192.168.1.3".parse().unwrap();
        let mut first = Observation::new(ip, "en0");
        first.ports_scanned = true;
        first.ports.push(Port {
            number: 443,
            protocol: "tcp".into(),
            findings: vec!["ssl-cert: old".into(), "http-title: title".into()],
            ..Default::default()
        });
        store.observe(first);
        let mut next = Observation::new(ip, "en0");
        next.ports_scanned = true;
        next.port_scope = vec![443];
        next.ports.push(Port {
            number: 443,
            protocol: "tcp".into(),
            findings: vec!["ssl-cert: new".into()],
            ..Default::default()
        });
        store.enrich(next);
        let port = &store.snapshot()[0].ports[0];
        assert!(!port.findings.contains(&"ssl-cert: old".into()));
        assert!(port.findings.contains(&"ssl-cert: new".into()));
        assert!(port.findings.contains(&"http-title: title".into()));
    }
}
