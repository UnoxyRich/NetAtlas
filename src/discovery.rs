use crate::model::{Device, DeviceStore, Observation};
use crossbeam_channel::{bounded, unbounded, Receiver, Sender};
use if_addrs::{get_if_addrs, IfAddr};
use mdns_sd::{ServiceDaemon, ServiceEvent};
use pnet_datalink::{
    self as datalink, Channel, Config, DataLinkReceiver, DataLinkSender, NetworkInterface,
};
use pnet_packet::{
    arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket},
    ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket},
    MutablePacket, Packet,
};
use std::{
    collections::{HashMap, HashSet},
    io::Read,
    net::{Ipv4Addr, UdpSocket},
    process::{Command, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::{Duration, Instant},
};

const RATE: u64 = 200;
// Additional device and homelab ports are not all included in nmap's top 1,000.
const DEVICE_PORTS: &[u16] = &[
    548, 3689, 5000, 5001, 7000, 7001, 7100, 8006, 8008, 8009, 8096, 8123, 8443, 9100, 9443, 9999,
    32400, 62078, 62079,
];
const SERVICES: &[&str] = &[
    "_ipp._tcp.local.",
    "_ipps._tcp.local.",
    "_printer._tcp.local.",
    "_pdl-datastream._tcp.local.",
    "_airplay._tcp.local.",
    "_raop._tcp.local.",
    "_smb._tcp.local.",
    "_afpovertcp._tcp.local.",
    "_nfs._tcp.local.",
    "_device-info._tcp.local.",
    "_workstation._tcp.local.",
    "_http._tcp.local.",
    "_ssh._tcp.local.",
    "_sftp-ssh._tcp.local.",
    "_http-alt._tcp.local.",
    "_https._tcp.local.",
    "_rfb._tcp.local.",
    "_rdp._tcp.local.",
    "_rtsp._tcp.local.",
    "_googlecast._tcp.local.",
    "_homekit._tcp.local.",
    "_hap._tcp.local.",
    "_spotify-connect._tcp.local.",
    "_companion-link._tcp.local.",
    "_apple-mobdev2._tcp.local.",
    "_adisk._tcp.local.",
    "_mediaremotetv._tcp.local.",
    "_home-assistant._tcp.local.",
    "_esphomelib._tcp.local.",
    "_matter._tcp.local.",
    "_sonos._tcp.local.",
    "_uscan._tcp.local.",
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Network {
    pub interface: String,
    pub address: Ipv4Addr,
    pub mask: Ipv4Addr,
    pub gateway: Option<Ipv4Addr>,
    pub vlan: Option<String>,
}
impl Network {
    pub fn prefix(&self) -> u32 {
        u32::from(self.mask).leading_ones()
    }
    pub fn cidr(&self) -> String {
        format!(
            "{}/{}",
            Ipv4Addr::from(u32::from(self.address) & u32::from(self.mask)),
            self.prefix()
        )
    }
    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        u32::from(ip) & u32::from(self.mask) == u32::from(self.address) & u32::from(self.mask)
    }
}
#[derive(Clone, Debug)]
pub struct Snapshot {
    pub devices: Vec<Device>,
    pub networks: Vec<Network>,
    pub status: String,
    pub warnings: Vec<String>,
}
impl Default for Snapshot {
    fn default() -> Self {
        Self {
            devices: vec![],
            networks: vec![],
            status: "Finding interfaces…".into(),
            warnings: vec![],
        }
    }
}
pub(crate) enum Message {
    Found(Observation),
    Enriched(Observation),
    ServiceGone(Ipv4Addr, String, String),
    ScanStatus(Ipv4Addr, String, Option<String>, String),
    ScanDone(Ipv4Addr, String, Option<String>),
    Status(String),
    Warning(String),
    Networks(Vec<Network>),
}
pub struct Scanner {
    pub updates: Receiver<Snapshot>,
    stop: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<()>>,
}
impl Scanner {
    pub fn start() -> Self {
        let (out, updates) = bounded(1);
        let stop = Arc::new(AtomicBool::new(false));
        let s = stop.clone();
        let worker = thread::spawn(move || controller(out, s));
        Self {
            updates,
            stop,
            worker: Some(worker),
        }
    }
}
impl Drop for Scanner {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}
fn controller(updates: Sender<Snapshot>, stop: Arc<AtomicBool>) {
    let (tx, rx) = unbounded();
    type Job = (Ipv4Addr, String, Option<String>);
    let (jobs, jobs_rx) = bounded::<Job>(4096);
    let (deep_jobs, deep_rx) = bounded::<Job>(4096);
    let (ping_jobs, ping_rx) = bounded::<Job>(4096);
    let nmap_version = Command::new("nmap")
        .arg("--version")
        .stderr(Stdio::null())
        .output()
        .ok()
        .filter(|o| o.status.success());
    let has_nmap = nmap_version.is_some();
    let broken_nmap = nmap_version
        .as_ref()
        .is_some_and(|o| has_nse_regression(&String::from_utf8_lossy(&o.stdout)));
    let privileged = Command::new("id")
        .arg("-u")
        .output()
        .ok()
        .is_some_and(|o| String::from_utf8_lossy(&o.stdout).trim() == "0");
    let mut workers = Vec::new();
    for _ in 0..4 {
        let (tx, stop, rx, deep) = (tx.clone(), stop.clone(), jobs_rx.clone(), deep_jobs.clone());
        workers.push(thread::spawn(move || {
            fingerprint_worker(rx, deep, tx, stop, has_nmap)
        }));
    }
    for _ in 0..8 {
        let (tx, stop, rx) = (tx.clone(), stop.clone(), deep_rx.clone());
        workers.push(thread::spawn(move || deep_worker(rx, tx, stop, privileged)));
    }
    for _ in 0..4 {
        let (tx, stop, rx) = (tx.clone(), stop.clone(), ping_rx.clone());
        workers.push(thread::spawn(move || ping_worker(rx, tx, stop)));
    }
    {
        let tx = tx.clone();
        let stop = stop.clone();
        workers.push(thread::spawn(move || discovery_loop(tx, stop)));
    }
    {
        let tx = tx.clone();
        let stop = stop.clone();
        workers.push(thread::spawn(move || mdns_loop(tx, stop)));
    }
    {
        let tx = tx.clone();
        let stop = stop.clone();
        workers.push(thread::spawn(move || crate::ssdp::monitor(tx, stop)));
    }
    let mut store = DeviceStore::default();
    let mut snap = Snapshot::default();
    let mut scheduled = HashMap::<(Ipv4Addr, String), Instant>::new();
    let mut inflight = HashSet::<(Ipv4Addr, String)>::new();
    if !has_nmap {
        snap.warnings
            .push("nmap not found; service probing disabled".into());
    }
    if broken_nmap {
        snap.warnings
            .push("Nmap 7.992 has broken version scripts; upgrade to 7.993 or newer".into());
    }
    if !privileged && has_nmap {
        snap.warnings
            .push("OS fingerprinting requires elevated privileges".into());
    }
    let mut pinged = HashMap::<(Ipv4Addr, String), Instant>::new();
    let mut active_macs = HashMap::<(Ipv4Addr, String), String>::new();
    let mut dirty = true;
    while !stop.load(Ordering::Relaxed) {
        if let Ok(message) = rx.recv_timeout(Duration::from_millis(1)) {
            match message {
                Message::Found(o) => {
                    let key = (o.ip, o.interface.clone());
                    let local = o.local;
                    let previous = active_macs.get(&key).cloned();
                    store.observe(o);
                    let current = store.active_mac(key.0, &key.1);
                    if identity_changed(previous.as_deref(), current.as_deref()) {
                        scheduled.remove(&key);
                    }
                    if let Some(mac) = &current {
                        active_macs.insert(key.clone(), mac.clone());
                    } else {
                        active_macs.remove(&key);
                    }
                    let queue_scan = !inflight.contains(&key)
                        && scheduled
                            .get(&key)
                            .is_none_or(|t| t.elapsed() > Duration::from_secs(900));
                    let queue_ping = !local
                        && pinged
                            .get(&key)
                            .is_none_or(|t| t.elapsed() > Duration::from_secs(10));
                    let job = (key.0, key.1.clone(), current);
                    if queue_ping && ping_jobs.try_send(job.clone()).is_ok() {
                        pinged.insert(key.clone(), Instant::now());
                    }
                    if queue_scan && jobs.try_send(job.clone()).is_ok() {
                        inflight.insert(key.clone());
                        if has_nmap {
                            store.set_scan_status_for(
                                key.0,
                                &key.1,
                                job.2.as_deref(),
                                "Queued".into(),
                            );
                        }
                    }
                }
                Message::ScanStatus(ip, iface, mac, status) => {
                    store.set_scan_status_for(ip, &iface, mac.as_deref(), status);
                }
                Message::Enriched(o) => store.enrich(o),
                Message::ServiceGone(ip, interface, service) => {
                    store.remove_service(ip, &interface, &service)
                }
                Message::ScanDone(ip, iface, mac) => {
                    let key = (ip, iface);
                    inflight.remove(&key);
                    // An old scan must not impose a cooldown on a replacement device.
                    if mac.as_deref() == active_macs.get(&key).map(String::as_str) {
                        scheduled.insert(key, Instant::now());
                    }
                }
                Message::Networks(n) => {
                    snap.networks = n;
                }
                Message::Status(s) => snap.status = s,
                Message::Warning(w) => {
                    if !snap.warnings.contains(&w) {
                        snap.warnings.push(w);
                    }
                }
            }
            dirty = true;
        }
        if dirty && publish_snapshot(&store, &mut snap, &updates) {
            dirty = false;
        }
    }
    for worker in workers {
        let _ = worker.join();
    }
}
fn publish_snapshot(
    store: &DeviceStore,
    snapshot: &mut Snapshot,
    updates: &Sender<Snapshot>,
) -> bool {
    if updates.is_full() {
        return false;
    }
    snapshot.devices = store.snapshot();
    updates.try_send(snapshot.clone()).is_ok()
}
fn identity_changed(previous: Option<&str>, current: Option<&str>) -> bool {
    previous.is_some() && previous != current
}
fn has_nse_regression(version: &str) -> bool {
    version
        .lines()
        .next()
        .and_then(|line| line.strip_prefix("Nmap version "))
        .and_then(|s| s.split_whitespace().next())
        .is_some_and(|token| {
            token
                .split(|c: char| !c.is_ascii_digit() && c != '.')
                .next()
                == Some("7.992")
        })
}
fn route() -> (Option<String>, Option<Ipv4Addr>) {
    #[cfg(target_os = "macos")]
    let result = Command::new("/sbin/route")
        .args(["-n", "get", "-inet", "default"])
        .output();
    #[cfg(target_os = "linux")]
    let result = Command::new("ip")
        .args(["-4", "route", "show", "default"])
        .output();
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    let result: std::io::Result<std::process::Output> = Err(std::io::Error::other("unsupported"));
    let Ok(o) = result else { return (None, None) };
    let text = String::from_utf8_lossy(&o.stdout);
    #[cfg(target_os = "macos")]
    {
        let mut i = None;
        let mut g = None;
        for line in text.lines() {
            if let Some((k, v)) = line.trim().split_once(':') {
                match k {
                    "interface" => i = Some(v.trim().to_owned()),
                    "gateway" => g = v.trim().parse().ok(),
                    _ => {}
                }
            }
        }
        (i, g)
    }
    #[cfg(target_os = "linux")]
    {
        let fields: Vec<_> = text.split_whitespace().collect();
        let i = fields
            .windows(2)
            .find(|w| w[0] == "dev")
            .map(|w| w[1].to_string());
        let g = fields
            .windows(2)
            .find(|w| w[0] == "via")
            .and_then(|w| w[1].parse().ok());
        (i, g)
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = text;
        (None, None)
    }
}
fn vlan(name: &str) -> Option<String> {
    #[cfg(target_os = "macos")]
    {
        let o = Command::new("/sbin/ifconfig").arg(name).output().ok()?;
        let s = String::from_utf8_lossy(&o.stdout);
        let fields: Vec<_> = s.split_whitespace().collect();
        fields
            .windows(2)
            .find(|w| w[0] == "vlan:")
            .map(|w| w[1].to_string())
    }
    #[cfg(target_os = "linux")]
    {
        let s = std::fs::read_to_string(format!("/proc/net/vlan/{name}")).ok()?;
        let fields: Vec<_> = s.split_whitespace().collect();
        fields
            .windows(2)
            .find(|w| w[0] == "VID:")
            .map(|w| w[1].to_string())
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = name;
        None
    }
}
fn parse_dhcp_router(output: &str, address: Ipv4Addr, mask: Ipv4Addr) -> Option<Ipv4Addr> {
    output
        .split_whitespace()
        .filter_map(|s| s.parse::<Ipv4Addr>().ok())
        .find(|ip| {
            *ip != address
                && !ip.is_unspecified()
                && u32::from(*ip) & u32::from(mask) == u32::from(address) & u32::from(mask)
        })
}
fn dhcp_gateway(interface: &str, address: Ipv4Addr, mask: Ipv4Addr) -> Option<Ipv4Addr> {
    #[cfg(target_os = "macos")]
    {
        let output = Command::new("/usr/sbin/ipconfig")
            .args(["getoption", interface, "router"])
            .stderr(Stdio::null())
            .output()
            .ok()?;
        if !output.status.success() {
            return None;
        }
        parse_dhcp_router(&String::from_utf8_lossy(&output.stdout), address, mask)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (interface, address, mask);
        None
    }
}
pub(crate) fn networks() -> Vec<Network> {
    let (default_iface, gateway) = route();
    let interfaces = datalink::interfaces();
    let Ok(addrs) = get_if_addrs() else {
        return vec![];
    };
    let mut out = vec![];
    for a in addrs {
        if let IfAddr::V4(v4) = a.addr {
            if v4.ip.is_loopback() || v4.ip.is_unspecified() || v4.ip.is_multicast() {
                continue;
            }
            if !interfaces.iter().any(|i| {
                i.name == a.name
                    && i.is_up()
                    && !i.is_loopback()
                    && !i.is_point_to_point()
                    && i.is_broadcast()
                    && i.mac.is_some()
            }) {
                continue;
            }
            let p = u32::from(v4.netmask).leading_ones();
            if u32::from(v4.netmask) != u32::MAX.checked_shl(32 - p).unwrap_or(0) {
                continue;
            }
            let routed_gateway = if default_iface.as_ref() == Some(&a.name) {
                gateway
            } else {
                None
            };
            let gateway = dhcp_gateway(&a.name, v4.ip, v4.netmask).or(routed_gateway.filter(|g| {
                u32::from(*g) & u32::from(v4.netmask) == u32::from(v4.ip) & u32::from(v4.netmask)
            }));
            out.push(Network {
                interface: a.name.clone(),
                address: v4.ip,
                mask: v4.netmask,
                gateway,
                vlan: vlan(&a.name),
            });
        }
    }
    out.sort_by(|a, b| {
        a.interface
            .cmp(&b.interface)
            .then(a.address.cmp(&b.address))
    });
    out
}
fn targets(n: &Network) -> (Vec<Ipv4Addr>, bool) {
    let limited = n.prefix() < 20;
    let p = if limited { 24 } else { n.prefix() };
    let mask = u32::MAX.checked_shl(32 - p).unwrap_or(0);
    let first = u32::from(n.address) & mask;
    let last = first | !mask;
    let (first, last) = if p >= 31 {
        (first, last)
    } else {
        (first + 1, last - 1)
    };
    ((first..=last).map(Ipv4Addr::from).collect(), limited)
}
fn discovery_loop(tx: Sender<Message>, stop: Arc<AtomicBool>) {
    while !stop.load(Ordering::Relaxed) {
        let nets = networks();
        let _ = tx.send(Message::Networks(nets.clone()));
        if nets.is_empty() {
            let _ = tx.send(Message::Status("No active IPv4 Ethernet interfaces".into()));
            sleep_stop(&stop, Duration::from_secs(5));
            continue;
        }
        for n in &nets {
            if stop.load(Ordering::Relaxed) {
                break;
            }
            let (hosts, limited) = targets(n);
            if limited {
                let _ = tx.send(Message::Warning(format!(
                    "{}: large subnet limited to local /24",
                    n.interface
                )));
            }
            let mut me = Observation::new(n.address, &n.interface);
            me.local = true;
            me.gateway = n.gateway == Some(n.address);
            me.mac = datalink::interfaces()
                .iter()
                .find(|i| i.name == n.interface)
                .and_then(|i| i.mac)
                .map(|m| m.to_string().to_uppercase());
            let _ = tx.send(Message::Found(me));
            let _ = tx.send(Message::Status(format!(
                "Scanning {} · {} targets · up to {} IP/s",
                n.interface,
                hosts.len(),
                RATE
            )));
            let iface = datalink::interfaces()
                .into_iter()
                .find(|i| i.name == n.interface);
            let raw_ok = match iface.and_then(|i| open_channel(&i).map(|c| (i, c))) {
                Some((iface, (sender, receiver))) => {
                    arp_sweep(n, &iface, &hosts, sender, receiver, &tx, &stop)
                }
                None => false,
            };
            if !raw_ok && !stop.load(Ordering::Relaxed) {
                let _=tx.send(Message::Warning("ARP unavailable: using neighbor cache, which may be stale; run with sudo for live replies".into()));
                fallback_sweep(n, hosts, &tx, &stop);
            }
        }
    }
}
fn open_channel(
    i: &NetworkInterface,
) -> Option<(Box<dyn DataLinkSender>, Box<dyn DataLinkReceiver>)> {
    let config = Config {
        read_timeout: Some(Duration::from_millis(5)),
        ..Default::default()
    };
    match datalink::channel(i, config).ok()? {
        Channel::Ethernet(tx, rx) => Some((tx, rx)),
        _ => None,
    }
}
fn arp_sweep(
    n: &Network,
    iface: &NetworkInterface,
    hosts: &[Ipv4Addr],
    mut sender: Box<dyn DataLinkSender>,
    mut receiver: Box<dyn DataLinkReceiver>,
    tx: &Sender<Message>,
    stop: &AtomicBool,
) -> bool {
    let Some(mac) = iface.mac else { return false };
    let mut index = 0;
    let mut next = Instant::now();
    let mut done = None;
    while !stop.load(Ordering::Relaxed) {
        if index < hosts.len() && Instant::now() >= next {
            let ip = hosts[index];
            index += 1;
            next = Instant::now() + Duration::from_millis(1000 / RATE);
            if ip != n.address {
                let mut buffer = [0u8; 42];
                {
                    let mut eth = MutableEthernetPacket::new(&mut buffer).unwrap();
                    eth.set_destination(pnet_datalink::MacAddr::broadcast());
                    eth.set_source(mac);
                    eth.set_ethertype(EtherTypes::Arp);
                    let mut arp = MutableArpPacket::new(eth.payload_mut()).unwrap();
                    arp.set_hardware_type(ArpHardwareTypes::Ethernet);
                    arp.set_protocol_type(EtherTypes::Ipv4);
                    arp.set_hw_addr_len(6);
                    arp.set_proto_addr_len(4);
                    arp.set_operation(ArpOperations::Request);
                    arp.set_sender_hw_addr(mac);
                    arp.set_sender_proto_addr(n.address);
                    arp.set_target_hw_addr(pnet_datalink::MacAddr::zero());
                    arp.set_target_proto_addr(ip);
                }
                if !matches!(sender.send_to(&buffer, None), Some(Ok(()))) {
                    return false;
                }
            }
            if index == hosts.len() {
                if done.is_none() {
                    done = Some(Instant::now());
                }
                // Keep probing while collecting replies from the end of this pass.
                index = 0;
            }
        }
        if let Ok(frame) = receiver.next() {
            if let Some(eth) = EthernetPacket::new(frame) {
                if eth.get_ethertype() == EtherTypes::Arp {
                    if let Some(arp) = ArpPacket::new(eth.payload()) {
                        let ip = arp.get_sender_proto_addr();
                        let source = arp.get_sender_hw_addr();
                        if arp.get_operation() == ArpOperations::Reply
                            && n.contains(ip)
                            && arp.get_target_proto_addr() == n.address
                            && source != mac
                        {
                            let mut o = Observation::new(ip, &n.interface);
                            o.mac = Some(source.to_string().to_uppercase());
                            o.gateway = n.gateway == Some(ip);
                            let _ = tx.send(Message::Found(o));
                        }
                    }
                }
            }
        }
        if done.is_some_and(|d| d.elapsed() >= Duration::from_millis(700)) {
            break;
        }
    }
    true
}
fn fallback_sweep(n: &Network, hosts: Vec<Ipv4Addr>, tx: &Sender<Message>, stop: &AtomicBool) {
    let Ok(sock) = UdpSocket::bind((n.address, 0)) else {
        return;
    };
    for ip in hosts {
        if stop.load(Ordering::Relaxed) {
            return;
        }
        let _ = sock.send_to(&[0], (ip, 9));
        thread::sleep(Duration::from_millis(1000 / RATE));
    }
    #[cfg(target_os = "macos")]
    let result = Command::new("/usr/sbin/arp")
        .args(["-an", "-i", &n.interface])
        .output();
    #[cfg(target_os = "linux")]
    let result = Command::new("ip")
        .args(["neigh", "show", "dev", &n.interface])
        .output();
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    let result: std::io::Result<std::process::Output> = Err(std::io::Error::other("unsupported"));
    if let Ok(out) = result {
        for (ip, mac, name) in parse_neighbors(&String::from_utf8_lossy(&out.stdout)) {
            if n.contains(ip) {
                let mut o = Observation::new(ip, &n.interface);
                o.mac = Some(mac);
                o.name = name;
                // A cached neighbor may be stale; ICMP or an open TCP port confirms presence.
                o.confirmed = false;
                o.gateway = n.gateway == Some(ip);
                let _ = tx.send(Message::Found(o));
            }
        }
    }
}
fn parse_neighbors(output: &str) -> Vec<(Ipv4Addr, String, Option<String>)> {
    output
        .lines()
        .filter_map(|line| {
            let fields: Vec<_> = line.split_whitespace().collect();
            let (ip, mac, name) = if line.contains(" at ") {
                let ip = line.split('(').nth(1)?.split(')').next()?.parse().ok()?;
                let mac = line.split(" at ").nth(1)?.split_whitespace().next()?;
                let name = line.split(" (").next()?.trim();
                (
                    ip,
                    mac,
                    (!name.is_empty() && name != "?").then(|| name.to_owned()),
                )
            } else {
                if line.contains("FAILED") || line.contains("INCOMPLETE") {
                    return None;
                }
                (
                    fields.first()?.parse().ok()?,
                    *fields.get(fields.iter().position(|s| *s == "lladdr")? + 1)?,
                    None,
                )
            };
            let parts: Vec<_> = mac
                .split(':')
                .map(|s| u8::from_str_radix(s, 16))
                .collect::<Result<_, _>>()
                .ok()?;
            if parts.len() != 6 || parts[0] & 1 != 0 || parts.iter().all(|b| *b == 0) {
                return None;
            }
            Some((
                ip,
                parts
                    .iter()
                    .map(|b| format!("{b:02X}"))
                    .collect::<Vec<_>>()
                    .join(":"),
                name,
            ))
        })
        .collect()
}
fn mdns_loop(tx: Sender<Message>, stop: Arc<AtomicBool>) {
    let Ok(daemon) = ServiceDaemon::new() else {
        let _ = tx.send(Message::Warning("mDNS unavailable".into()));
        return;
    };
    let mut receivers: Vec<_> = SERVICES
        .iter()
        .filter_map(|s| daemon.browse(s).ok())
        .collect();
    let meta = daemon.browse("_services._dns-sd._udp.local.").ok();
    let mut service_types: HashSet<String> = SERVICES.iter().map(|s| s.to_lowercase()).collect();
    let mut nets = vec![];
    let mut next = Instant::now();
    let mut instances = HashMap::<String, Vec<MdnsMapping>>::new();
    while !stop.load(Ordering::Relaxed) {
        if Instant::now() >= next {
            nets = networks();
            next = Instant::now() + Duration::from_secs(15);
        }
        if let Some(meta) = &meta {
            while let Ok(event) = meta.try_recv() {
                if let ServiceEvent::ServiceFound(_, service) = event {
                    let name = service.to_lowercase();
                    if name.len() <= 100
                        && (name.ends_with("._tcp.local.") || name.ends_with("._udp.local."))
                        && service_types.len() < 128
                        && service_types.insert(name.clone())
                    {
                        if let Ok(receiver) = daemon.browse(&name) {
                            receivers.push(receiver);
                        }
                    }
                }
            }
        }
        for rx in &receivers {
            while let Ok(event) = rx.try_recv() {
                match event {
                    ServiceEvent::ServiceResolved(info) => {
                        let key = info.get_fullname().to_ascii_lowercase();
                        let mut mappings = Vec::new();
                        for ip in info.get_addresses_v4() {
                            for n in nets.iter().filter(|n| n.contains(*ip)) {
                                let mut o = Observation::new(*ip, &n.interface);
                                o.confirmed = false; // Bonjour sleep proxies may answer for another device.
                                let hostname = info.get_hostname().trim_end_matches('.');
                                if !hostname.is_empty() {
                                    o.name = Some(hostname.into());
                                }
                                let instance = info
                                    .get_fullname()
                                    .strip_suffix(info.get_type())
                                    .unwrap_or("")
                                    .trim_end_matches('.');
                                if !instance.is_empty()
                                    && instance.len() <= 100
                                    && !instance.starts_with('_')
                                {
                                    o.aliases.push(instance.to_owned());
                                    if ["_ipp.", "_ipps.", "_airplay.", "_googlecast."]
                                        .iter()
                                        .any(|prefix| info.get_type().starts_with(prefix))
                                    {
                                        o.friendly_name = Some(instance.to_owned());
                                    }
                                }
                                o.model = [
                                    "model", "ty", "product", "usb_MDL", "usb_mdl", "am", "md",
                                    "rpmd",
                                ]
                                .iter()
                                .find_map(|key| {
                                    info.get_property_val_str(key)
                                        .map(str::trim)
                                        .filter(|v| !v.is_empty())
                                        .map(|v| {
                                            v.trim_matches(|c| c == '(' || c == ')').to_owned()
                                        })
                                });
                                if o.model.is_some() {
                                    o.model_source = Some("mDNS".into());
                                }
                                if let Some(vendor) =
                                    ["manufacturer", "usb_mfg"].iter().find_map(|key| {
                                        info.get_property_val_str(key)
                                            .filter(|v| !v.trim().is_empty())
                                    })
                                {
                                    o.vendor = Some(vendor.to_owned());
                                    o.vendor_source = Some("mDNS".into());
                                }
                                let service = info.get_type().trim_end_matches(".local.");
                                let service =
                                    format!("{} :{} (advertised)", service, info.get_port());
                                mappings.push((*ip, n.interface.clone(), service.clone()));
                                o.services.push(service);
                                o.gateway = n.gateway == Some(*ip);
                                o.local = n.address == *ip;
                                let _ = tx.send(Message::Found(o));
                            }
                        }
                        let previous = instances.insert(key, mappings).unwrap_or_default();
                        publish_withdrawn(&instances, previous, &tx);
                    }
                    ServiceEvent::ServiceRemoved(_, fullname) => {
                        let previous = instances
                            .remove(&fullname.to_ascii_lowercase())
                            .unwrap_or_default();
                        publish_withdrawn(&instances, previous, &tx);
                    }
                    _ => {}
                }
            }
        }
        sleep_stop(&stop, Duration::from_millis(100));
    }
    let _ = daemon.shutdown();
}
type MdnsMapping = (Ipv4Addr, String, String);
fn publish_withdrawn(
    instances: &HashMap<String, Vec<MdnsMapping>>,
    previous: Vec<MdnsMapping>,
    tx: &Sender<Message>,
) {
    for (ip, interface, service) in previous {
        if !instances.values().any(|entries| {
            entries
                .iter()
                .any(|(other_ip, other_interface, other_service)| {
                    *other_ip == ip && *other_interface == interface && *other_service == service
                })
        }) {
            let _ = tx.send(Message::ServiceGone(ip, interface, service));
        }
    }
}
type ScanJob = (Ipv4Addr, String, Option<String>);
fn fingerprint_worker(
    rx: Receiver<ScanJob>,
    deep: Sender<ScanJob>,
    tx: Sender<Message>,
    stop: Arc<AtomicBool>,
    has_nmap: bool,
) {
    while !stop.load(Ordering::Relaxed) {
        let Ok((ip, iface, mac)) = rx.recv_timeout(Duration::from_millis(100)) else {
            continue;
        };
        if let Some(name) = system_reverse_name(ip, &stop) {
            let mut o = Observation::new(ip, &iface);
            o.mac = mac.clone();
            o.name = Some(name);
            let _ = tx.send(Message::Enriched(o));
        }
        if let Ok(output) = Command::new("dig")
            .args(["+time=1", "+tries=1", "+short", "-x", &ip.to_string()])
            .stderr(Stdio::null())
            .output()
        {
            let name = String::from_utf8_lossy(&output.stdout)
                .lines()
                .next()
                .unwrap_or("")
                .trim()
                .trim_end_matches('.')
                .to_owned();
            if !name.is_empty() && !name.starts_with(';') {
                let mut o = Observation::new(ip, &iface);
                o.mac = mac.clone();
                o.name = Some(name);
                let _ = tx.send(Message::Enriched(o));
            }
        }
        if !has_nmap || stop.load(Ordering::Relaxed) {
            let _ = tx.send(Message::ScanDone(ip, iface, mac));
            continue;
        }
        let _ = tx.send(Message::ScanStatus(
            ip,
            iface.clone(),
            mac.clone(),
            "Quick scan".into(),
        ));
        match run_nmap(ip, &stop, ScanPhase::Quick, false) {
            Ok(mut o) => {
                o.interface = iface.clone();
                o.mac = mac.clone();
                let _ = tx.send(Message::Enriched(o));
            }
            Err(e) => {
                let _ = tx.send(Message::ScanStatus(
                    ip,
                    iface.clone(),
                    mac.clone(),
                    format!("Quick scan: {e}"),
                ));
            }
        }
        if !stop.load(Ordering::Relaxed) {
            let _ = tx.send(Message::ScanStatus(
                ip,
                iface.clone(),
                mac.clone(),
                "Deep scan queued".into(),
            ));
            if deep.try_send((ip, iface.clone(), mac.clone())).is_err() {
                let _ = tx.send(Message::ScanStatus(
                    ip,
                    iface.clone(),
                    mac.clone(),
                    "Deep scan queue full".into(),
                ));
                let _ = tx.send(Message::ScanDone(ip, iface, mac));
            }
        }
    }
}
fn system_reverse_name(ip: Ipv4Addr, stop: &AtomicBool) -> Option<String> {
    #[cfg(target_os = "macos")]
    {
        let mut child = Command::new("/usr/bin/dscacheutil")
            .args(["-q", "host", "-a", "ip_address", &ip.to_string()])
            .stderr(Stdio::null())
            .stdout(Stdio::piped())
            .spawn()
            .ok()?;
        let started = Instant::now();
        loop {
            if stop.load(Ordering::Relaxed) || started.elapsed() > Duration::from_millis(1500) {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
            match child.try_wait() {
                Ok(Some(_)) => break,
                Ok(None) => thread::sleep(Duration::from_millis(20)),
                Err(_) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return None;
                }
            }
        }
        let output = child.wait_with_output().ok()?;
        String::from_utf8_lossy(&output.stdout)
            .lines()
            .filter_map(|line| line.strip_prefix("name:"))
            .map(str::trim)
            .find(|s| !s.is_empty())
            .map(str::to_owned)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (ip, stop);
        None
    }
}
fn deep_worker(
    rx: Receiver<ScanJob>,
    tx: Sender<Message>,
    stop: Arc<AtomicBool>,
    privileged: bool,
) {
    while !stop.load(Ordering::Relaxed) {
        let Ok((ip, iface, mac)) = rx.recv_timeout(Duration::from_millis(100)) else {
            continue;
        };
        let _ = tx.send(Message::ScanStatus(
            ip,
            iface.clone(),
            mac.clone(),
            "Deep scan".into(),
        ));
        let mut status = match run_nmap(ip, &stop, ScanPhase::Deep, privileged) {
            Ok(mut o) => {
                o.interface = iface.clone();
                o.mac = mac.clone();
                o.ports_complete = true;
                let status = if !o.scan_warnings.is_empty() {
                    "Partial · some nmap checks failed"
                } else if o.scan_retried {
                    "Complete · retry attempted"
                } else if privileged {
                    "Complete"
                } else {
                    "Complete · OS scan needs sudo"
                };
                let _ = tx.send(Message::Enriched(o));
                status.to_owned()
            }
            Err(e) => format!("Deep scan: {e}"),
        };
        if !stop.load(Ordering::Relaxed) {
            let _ = tx.send(Message::ScanStatus(
                ip,
                iface.clone(),
                mac.clone(),
                "Device-specific ports".into(),
            ));
            match run_nmap(ip, &stop, ScanPhase::DevicePorts, false) {
                Ok(mut o) => {
                    o.interface = iface.clone();
                    o.mac = mac.clone();
                    o.port_scope = DEVICE_PORTS.to_vec();
                    if !o.scan_warnings.is_empty() {
                        status.push_str(" · device checks partial");
                    } else if o.scan_retried {
                        status.push_str(" · device checks retried");
                    }
                    let _ = tx.send(Message::Enriched(o));
                }
                Err(_) => status.push_str(" · device ports incomplete"),
            }
        }
        let _ = tx.send(Message::ScanStatus(ip, iface.clone(), mac.clone(), status));
        let _ = tx.send(Message::ScanDone(ip, iface, mac));
    }
}
#[derive(Clone, Copy)]
enum ScanPhase {
    Quick,
    DevicePorts,
    Deep,
}
fn run_nmap(
    ip: Ipv4Addr,
    stop: &AtomicBool,
    phase: ScanPhase,
    privileged: bool,
) -> Result<Observation, String> {
    run_nmap_using(std::ffi::OsStr::new("nmap"), ip, stop, phase, privileged)
}
fn run_nmap_using(
    program: &std::ffi::OsStr,
    ip: Ipv4Addr,
    stop: &AtomicBool,
    phase: ScanPhase,
    privileged: bool,
) -> Result<Observation, String> {
    let mut result = run_nmap_once(program, ip, stop, phase, privileged, None)?;
    let ports: Vec<_> = result.failed_ports.iter().copied().take(32).collect();
    if !ports.is_empty() && !stop.load(Ordering::Relaxed) {
        result.scan_retried = true;
        match run_nmap_once(program, ip, stop, phase, false, Some(&ports)) {
            Ok(retry) => merge_retry(&mut result, retry, &ports),
            Err(error) => result.scan_warnings.push(format!("Retry failed: {error}")),
        }
    }
    Ok(result)
}
fn merge_retry(result: &mut Observation, retry: Observation, ports: &[u16]) {
    // Replace warnings only for ports actually retried; host warnings remain visible.
    // A missing script result is not proof of success: NSE may have skipped it.
    result.scan_warnings.retain(|warning| {
        let Some((id, location)) = warning.rsplit_once(" (") else {
            return true;
        };
        let Some(number) = location
            .strip_suffix("/tcp)")
            .and_then(|s| s.parse::<u16>().ok())
        else {
            return true;
        };
        !ports.contains(&number)
            || !retry.ports.iter().any(|p| {
                p.protocol == "tcp"
                    && p.number == number
                    && p.findings
                        .iter()
                        .any(|finding| finding.starts_with(&format!("{id}: ")))
            })
    });
    for warning in retry.scan_warnings {
        if !result.scan_warnings.contains(&warning) {
            result.scan_warnings.push(warning);
        }
    }
    result.failed_ports.retain(|port| {
        result
            .scan_warnings
            .iter()
            .any(|warning| warning.ends_with(&format!("({port}/tcp)")))
    });
    for port in retry.failed_ports {
        if !result.failed_ports.contains(&port) {
            result.failed_ports.push(port);
        }
    }
    for new_port in retry.ports {
        if let Some(old) = result
            .ports
            .iter_mut()
            .find(|old| old.number == new_port.number && old.protocol == new_port.protocol)
        {
            for finding in new_port.findings {
                if !old.findings.contains(&finding) {
                    old.findings.push(finding);
                }
            }
            if old.product.is_empty() && !new_port.product.is_empty() {
                old.product = new_port.product;
                old.version = new_port.version;
                old.extra = new_port.extra;
            }
        }
    }
}
fn run_nmap_once(
    program: &std::ffi::OsStr,
    ip: Ipv4Addr,
    stop: &AtomicBool,
    phase: ScanPhase,
    privileged: bool,
    retry_ports: Option<&[u16]>,
) -> Result<Observation, String> {
    let mut command = Command::new(program);
    command.args([
        "-n",
        "-Pn",
        "-sT",
        "-sV",
        "--max-retries",
        "1",
        "--max-parallelism",
        "64",
        "-oX",
        "-",
    ]);
    let port_list = retry_ports.map(|ports| {
        ports
            .iter()
            .map(u16::to_string)
            .collect::<Vec<_>>()
            .join(",")
    });
    match phase {
        ScanPhase::Deep => {
            command.args([
                "--version-all",
                "--host-timeout",
                if retry_ports.is_some() { "45s" } else { "180s" },
                "--script",
                "http-title,http-server-header,ssl-cert,smb-os-discovery,nbstat",
            ]);
            if let Some(ports) = &port_list {
                command.args(["-p", ports]);
            } else {
                command.args(["--top-ports", "1000"]);
            }
            if privileged && retry_ports.is_none() {
                command.args(["-O", "--osscan-guess"]);
            }
        }
        ScanPhase::Quick => {
            command.args(["--version-light", "--host-timeout", "45s"]);
            if let Some(ports) = &port_list {
                command.args(["-p", ports]);
            } else {
                command.args(["--top-ports", "100"]);
            }
        }
        ScanPhase::DevicePorts => {
            let ports = port_list.unwrap_or_else(|| {
                DEVICE_PORTS
                    .iter()
                    .map(u16::to_string)
                    .collect::<Vec<_>>()
                    .join(",")
            });
            command.args([
                "--version-light",
                "--host-timeout",
                "45s",
                "--script",
                "http-title,http-server-header,ssl-cert",
                "-p",
                &ports,
            ]);
        }
    }
    let mut child = command
        .arg(ip.to_string())
        .stderr(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|e| format!("could not start nmap: {e}"))?;
    let mut stdout = child.stdout.take().ok_or("nmap output unavailable")?;
    let mut stderr = child.stderr.take().ok_or("nmap diagnostics unavailable")?;
    let reader = thread::spawn(move || {
        let mut data = String::new();
        let _ = stdout.read_to_string(&mut data);
        data
    });
    let diagnostics = thread::spawn(move || {
        let mut data = String::new();
        let _ = stderr.read_to_string(&mut data);
        data
    });
    let started = Instant::now();
    let timeout = if matches!(phase, ScanPhase::Deep) && retry_ports.is_none() {
        Duration::from_secs(195)
    } else {
        Duration::from_secs(55)
    };
    let mut timed_out = false;
    let status = loop {
        if stop.load(Ordering::Relaxed) || started.elapsed() >= timeout {
            timed_out = !stop.load(Ordering::Relaxed);
            let _ = child.kill();
            let _ = child.wait();
            break None;
        }
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) => thread::sleep(Duration::from_millis(20)),
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
        }
    };
    let output = reader.join().unwrap_or_default();
    let diagnostics = diagnostics.join().unwrap_or_default();
    if timed_out {
        return Err("timed out".into());
    }
    if !status.is_some_and(|s| s.success()) {
        let reason = diagnostics
            .lines()
            .find(|line| !line.trim().is_empty() && !line.starts_with("Warning:"))
            .unwrap_or("failed or interrupted");
        return Err(reason.chars().take(160).collect());
    }
    let mut result = crate::fingerprint::parse_nmap(&output, ip, "")?;
    result.ports_scanned = true;
    Ok(result)
}
fn ping_worker(rx: Receiver<ScanJob>, tx: Sender<Message>, stop: Arc<AtomicBool>) {
    while !stop.load(Ordering::Relaxed) {
        let Ok((ip, iface, _mac)) = rx.recv_timeout(Duration::from_millis(100)) else {
            continue;
        };
        #[cfg(target_os = "macos")]
        let wait = "1000";
        #[cfg(not(target_os = "macos"))]
        let wait = "1";
        if Command::new("ping")
            .args(["-n", "-c", "1", "-W", wait, &ip.to_string()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
        {
            // An ICMP reply proves the IP responded, not which MAC owns it.
            let o = Observation::new(ip, &iface);
            let _ = tx.send(Message::Found(o));
        }
    }
}
fn sleep_stop(stop: &AtomicBool, d: Duration) {
    let start = Instant::now();
    while !stop.load(Ordering::Relaxed) && start.elapsed() < d {
        thread::sleep(Duration::from_millis(50).min(d.saturating_sub(start.elapsed())));
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn net() -> Network {
        Network {
            interface: "en0".into(),
            address: "192.168.31.86".parse().unwrap(),
            mask: "255.255.255.0".parse().unwrap(),
            gateway: None,
            vlan: None,
        }
    }
    #[test]
    fn dhcp_router_must_be_on_the_interface_subnet() {
        let address = "192.168.31.86".parse().unwrap();
        let mask = "255.255.255.0".parse().unwrap();
        assert_eq!(
            parse_dhcp_router("10.0.0.1 192.168.31.1", address, mask),
            Some("192.168.31.1".parse().unwrap())
        );
        assert_eq!(parse_dhcp_router("10.0.0.1", address, mask), None);
    }
    #[test]
    fn range_and_large_limit() {
        let mut n = net();
        assert_eq!(targets(&n).0.len(), 254);
        n.mask = "255.0.0.0".parse().unwrap();
        assert!(targets(&n).1);
        assert_eq!(targets(&n).0.len(), 254);
    }
    #[test]
    fn parses_mac_and_skips_incomplete() {
        let v=parse_neighbors("foo.local (192.168.31.7) at a:b:0:12:34:ef on en0\n? (192.168.31.8) at (incomplete) on en0\n? (192.168.31.255) at ff:ff:ff:ff:ff:ff on en0");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].1, "0A:0B:00:12:34:EF");
        assert_eq!(v[0].2.as_deref(), Some("foo.local"));
    }
    #[test]
    #[ignore = "runs nmap against a loopback device-specific port"]
    fn scans_apple_device_port_on_loopback() {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        let Ok(listener) = TcpListener::bind("127.0.0.1:62078") else {
            return;
        };
        listener.set_nonblocking(true).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = stop.clone();
        let server = thread::spawn(move || {
            while !stopped.load(Ordering::Relaxed) {
                if let Ok((mut stream, _)) = listener.accept() {
                    let _ = stream.set_read_timeout(Some(Duration::from_millis(500)));
                    let mut input = [0; 1024];
                    let _ = stream.read(&mut input);
                    let _ = stream.write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    );
                } else {
                    thread::sleep(Duration::from_millis(10));
                }
            }
        });
        let result = run_nmap(
            "127.0.0.1".parse().unwrap(),
            &stop,
            ScanPhase::DevicePorts,
            false,
        );
        stop.store(true, Ordering::Relaxed);
        server.join().unwrap();
        let result = result.unwrap();
        assert!(result.ports.iter().any(|p| p.number == 62078));
    }
    #[test]
    fn retry_keeps_original_results_and_only_replaces_retried_errors() {
        let ip = "192.168.1.2".parse().unwrap();
        let mut first = Observation::new(ip, "en0");
        first.scan_warnings = vec![
            "rpcinfo (22/tcp)".into(),
            "nbstat (host check)".into(),
            "vmware-version (443/tcp)".into(),
        ];
        first.failed_ports = vec![22, 443];
        first.ports.push(crate::model::Port {
            number: 22,
            protocol: "tcp".into(),
            product: "OpenSSH".into(),
            ..Default::default()
        });
        let mut retry = Observation::new(ip, "en0");
        retry.ports.push(crate::model::Port {
            number: 22,
            protocol: "tcp".into(),
            findings: vec!["rpcinfo: verified".into()],
            ..Default::default()
        });
        merge_retry(&mut first, retry, &[22]);
        assert_eq!(
            first.scan_warnings,
            ["nbstat (host check)", "vmware-version (443/tcp)"]
        );
        assert_eq!(first.failed_ports, [443]);
        assert_eq!(first.ports[0].product, "OpenSSH");
        assert_eq!(first.ports[0].findings, ["rpcinfo: verified"]);
        merge_retry(&mut first, Observation::new(ip, "en0"), &[443]);
        assert!(first
            .scan_warnings
            .contains(&"vmware-version (443/tcp)".into()));
    }
    #[cfg(unix)]
    #[test]
    fn retries_real_child_process_and_preserves_failed_check_diagnostics() {
        use std::{
            fs,
            os::unix::fs::PermissionsExt,
            time::{SystemTime, UNIX_EPOCH},
        };
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "netatlas-nmap-test-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir(&dir).unwrap();
        let binary = dir.join("nmap");
        let script = r##"#!/bin/sh
if [ ! -e "$0.called" ]; then
  touch "$0.called"
  printf '%s' '<nmaprun><host><address addr="127.0.0.1"/><ports><port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH"/><script id="rpcinfo" output="ERROR: Script execution failed (use -d to debug)"/></port></ports></host></nmaprun>'
else
  touch "$0.retried"
  printf '%s' '<nmaprun><host><address addr="127.0.0.1"/><ports><port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/><script id="rpcinfo" output="ERROR: Script execution failed (use -d to debug)"/></port></ports></host></nmaprun>'
fi
"##;
        fs::write(&binary, script).unwrap();
        fs::set_permissions(&binary, fs::Permissions::from_mode(0o700)).unwrap();
        let result = run_nmap_using(
            binary.as_os_str(),
            "127.0.0.1".parse().unwrap(),
            &AtomicBool::new(false),
            ScanPhase::Quick,
            false,
        )
        .unwrap();
        assert!(result.scan_retried);
        assert!(dir.join("nmap.retried").exists());
        assert_eq!(result.scan_warnings, ["rpcinfo (22/tcp)"]);
        assert_eq!(result.ports[0].product, "OpenSSH");
        fs::write(
            &binary,
            "#!/bin/sh\necho 'nmap data unavailable' >&2\nexit 1\n",
        )
        .unwrap();
        let error = run_nmap_using(
            binary.as_os_str(),
            "127.0.0.1".parse().unwrap(),
            &AtomicBool::new(false),
            ScanPhase::Quick,
            false,
        )
        .unwrap_err();
        assert!(error.contains("nmap data unavailable"));
        fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn warns_only_for_nmap_release_with_broken_version_scripts() {
        assert!(has_nse_regression(
            "Nmap version 7.992 ( https://nmap.org )"
        ));
        assert!(has_nse_regression(
            "Nmap version 7.992SVN ( https://nmap.org )"
        ));
        assert!(!has_nse_regression(
            "Nmap version 7.993 ( https://nmap.org )"
        ));
        assert!(!has_nse_regression(
            "Nmap version 7.99 ( https://nmap.org )"
        ));
    }
    #[test]
    fn scan_cooldown_is_invalidated_when_a_known_address_changes_owner() {
        assert!(identity_changed(Some("old"), Some("new")));
        assert!(identity_changed(Some("old"), None));
        assert!(!identity_changed(Some("old"), Some("old")));
        assert!(!identity_changed(None, Some("first observed")));
    }
    #[test]
    fn service_withdrawal_preserves_other_instances_of_same_service() {
        let (tx, rx) = unbounded();
        let ip = "192.168.1.2".parse().unwrap();
        let entry = (
            ip,
            "en0".to_owned(),
            "_ipp._tcp :631 (advertised)".to_owned(),
        );
        let mut instances = HashMap::new();
        instances.insert("second".into(), vec![entry.clone()]);
        publish_withdrawn(&instances, vec![entry.clone()], &tx);
        assert!(rx.try_recv().is_err());
        instances.clear();
        publish_withdrawn(&instances, vec![entry], &tx);
        assert!(matches!(rx.try_recv(), Ok(Message::ServiceGone(_, _, _))));
    }
    #[test]
    fn a_full_ui_queue_does_not_lose_the_latest_snapshot() {
        let (tx, rx) = bounded(1);
        let mut snapshot = Snapshot::default();
        let mut store = DeviceStore::default();
        assert!(publish_snapshot(&store, &mut snapshot, &tx));
        store.observe(Observation::new("192.168.1.2".parse().unwrap(), "en0"));
        assert!(!publish_snapshot(&store, &mut snapshot, &tx));
        assert!(rx.try_recv().unwrap().devices.is_empty());
        assert!(publish_snapshot(&store, &mut snapshot, &tx));
        assert_eq!(rx.try_recv().unwrap().devices.len(), 1);
    }
}
