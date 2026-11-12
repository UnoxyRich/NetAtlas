use crate::discovery::Network;
use std::{net::Ipv4Addr, process::Command};

// Accept only private IPv4 networks; never infer a VLAN ID from an IP route.
pub fn parse_subnet(value: &str) -> Result<(Ipv4Addr, u32), String> {
    let (ip, prefix) = value
        .split_once('/')
        .ok_or("expected IPv4 CIDR, e.g. 192.168.40.0/24")?;
    let ip: Ipv4Addr = ip.parse().map_err(|_| "invalid IPv4 address")?;
    let prefix: u32 = prefix.parse().map_err(|_| "invalid prefix")?;
    if !(16..=30).contains(&prefix) {
        return Err("subnet prefix must be /16 through /30".into());
    }
    let mask = u32::MAX << (32 - prefix);
    let first = Ipv4Addr::from(u32::from(ip) & mask);
    let last = Ipv4Addr::from(u32::from(first) | !mask);
    if !first.is_private() || !last.is_private() {
        return Err("only private IPv4 subnets are supported".into());
    }
    Ok((first, prefix))
}

fn mask(prefix: u32) -> Ipv4Addr {
    Ipv4Addr::from(u32::MAX << (32 - prefix))
}
fn expand_bsd_destination(s: &str) -> Option<String> {
    let (address, explicit_prefix) = s.split_once('/').map_or((s, None), |(a, p)| (a, Some(p)));
    let mut parts: Vec<_> = address.split('.').collect();
    let implied_prefix = (parts.len() * 8).to_string();
    let prefix = explicit_prefix.unwrap_or(&implied_prefix);
    if parts.len() > 4 || parts.iter().any(|p| p.parse::<u8>().is_err()) {
        return None;
    }
    while parts.len() < 4 {
        parts.push("0");
    }
    Some(format!("{}/{}", parts.join("."), prefix))
}

fn parse_routes(text: &str, direct: &[Network], bsd: bool) -> Vec<Network> {
    let mut result = Vec::new();
    for line in text.lines() {
        let f: Vec<_> = line.split_whitespace().collect();
        let (dest, gateway, iface) = if bsd {
            if f.len() < 4 || !f[2].contains('U') || !f[2].contains('G') || f[2].contains('I') {
                continue;
            }
            let Some(dest) = expand_bsd_destination(f[0]) else {
                continue;
            };
            (dest, f[1].parse().ok(), f[3])
        } else {
            if f.len() < 5 || !f.contains(&"via") || !f.contains(&"dev") {
                continue;
            }
            let Some(vi) = f.iter().position(|x| *x == "via") else {
                continue;
            };
            let Some(di) = f.iter().position(|x| *x == "dev") else {
                continue;
            };
            let (Some(gw), Some(iface)) = (f.get(vi + 1), f.get(di + 1)) else {
                continue;
            };
            (f[0].to_string(), gw.parse().ok(), *iface)
        };
        let Ok((address, prefix)) = parse_subnet(&dest) else {
            continue;
        };
        // Broad routes such as 10/8 are often VPN policy routes, not evidence of populated subnets.
        if prefix < 20 {
            continue;
        }
        if !direct.iter().any(|n| n.interface == iface) {
            continue;
        }
        if direct
            .iter()
            .any(|n| n.interface == iface && n.contains(address) && n.prefix() <= prefix)
        {
            continue;
        }
        result.push(Network {
            interface: iface.to_owned(),
            address,
            mask: mask(prefix),
            gateway,
            vlan: None,
            routed: true,
        });
    }
    result
}

fn route_interface(ip: Ipv4Addr) -> Option<String> {
    #[cfg(target_os = "macos")]
    {
        let output = Command::new("/sbin/route")
            .args(["-n", "get", "-inet", &ip.to_string()])
            .output()
            .ok()?;
        if !output.status.success() {
            return None;
        }
        String::from_utf8_lossy(&output.stdout)
            .lines()
            .filter_map(|line| line.trim().strip_prefix("interface:"))
            .map(str::trim)
            .find(|s| !s.is_empty())
            .map(str::to_owned)
    }
    #[cfg(target_os = "linux")]
    {
        let output = Command::new("ip")
            .args(["-4", "route", "get", &ip.to_string()])
            .output()
            .ok()?;
        if !output.status.success() {
            return None;
        }
        let text = String::from_utf8_lossy(&output.stdout);
        let fields: Vec<_> = text.split_whitespace().collect();
        fields
            .windows(2)
            .find(|w| w[0] == "dev")
            .map(|w| w[1].to_owned())
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = ip;
        None
    }
}

pub fn discover(direct: &[Network], extra: &[String]) -> Vec<Network> {
    #[cfg(target_os = "macos")]
    let output = Command::new("/usr/sbin/netstat")
        .args(["-rn", "-f", "inet"])
        .output();
    #[cfg(target_os = "linux")]
    let output = Command::new("ip").args(["-4", "route", "show"]).output();
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    let output: std::io::Result<std::process::Output> = Err(std::io::Error::other("unsupported"));
    let mut routes = output
        .ok()
        .filter(|o| o.status.success())
        .map(|o| {
            parse_routes(
                &String::from_utf8_lossy(&o.stdout),
                direct,
                cfg!(target_os = "macos"),
            )
        })
        .unwrap_or_default();
    for value in extra {
        let Ok((address, prefix)) = parse_subnet(value) else {
            continue;
        };
        if direct
            .iter()
            .any(|n| n.contains(address) && n.prefix() <= prefix)
        {
            continue;
        }
        let Some(iface) = route_interface(Ipv4Addr::from(u32::from(address) + 1)) else {
            continue;
        };
        if direct.iter().any(|n| n.interface == iface) {
            routes.push(Network {
                interface: iface,
                address,
                mask: mask(prefix),
                gateway: None,
                vlan: None,
                routed: true,
            });
        }
    }
    routes.sort_by(|a, b| {
        a.interface
            .cmp(&b.interface)
            .then(a.address.cmp(&b.address))
            .then(a.prefix().cmp(&b.prefix()))
    });
    routes
        .dedup_by(|a, b| a.interface == b.interface && a.address == b.address && a.mask == b.mask);
    routes
}

#[cfg(test)]
mod tests {
    use super::*;
    fn local() -> Network {
        Network {
            interface: "en0".into(),
            address: "192.168.28.137".parse().unwrap(),
            mask: "255.255.252.0".parse().unwrap(),
            gateway: None,
            vlan: None,
            routed: false,
        }
    }
    #[test]
    fn parses_private_routes_and_excludes_inactive_or_broad() {
        let text="192.168.0/16 192.168.31.254 UGSc en0\n192.168.40 192.168.31.254 UGSc en0\n192.168.41/24 192.168.31.254 UGScI en0\n192.168.29/24 192.168.31.254 UGSc en0\n8.8.8/24 192.168.31.254 UGSc en0\n10.3.0/24 10.0.0.1 UGSc utun4";
        let v = parse_routes(text, &[local()], true);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].cidr(), "192.168.40.0/24");
        assert!(v[0].routed);
    }
    #[test]
    fn linux_routes_and_invalid_ranges() {
        let v=parse_routes("10.4.5.0/24 via 192.168.31.254 dev en0 proto static\n10.0.0.0/8 via 192.168.31.254 dev en0",&[local()],false);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].cidr(), "10.4.5.0/24");
        assert!(parse_subnet("8.8.8.0/24").is_err());
        assert!(parse_subnet("192.168.0.0/8").is_err());
    }
}
