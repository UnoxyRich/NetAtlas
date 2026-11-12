# NetAtlas

A live terminal map of connected and reachable routed IPv4 networks. Scanning starts automatically and runs continuously.

```sh
cargo build --release
sudo ./target/release/netatlas
```

Raw ARP and nmap OS fingerprinting normally require elevated privileges. Without raw ARP access, NetAtlas uses UDP and the operating system's neighbor cache; cached entries are unconfirmed until a ping or open TCP port verifies that the address responds. Install `nmap` for port and service scans. Nmap 7.992 has a version-script regression; use 7.993 or newer. NetBIOS node-status queries, the macOS system resolver and `dig` add device names when available. The map also uses mDNS and UPnP/SSDP for advertised names, models and services.

Try the interface without scanning with `cargo run -- --demo`. Add known reachable private subnets when they are not listed as specific routes:

```sh
sudo ./target/release/netatlas --subnet 192.168.40.0/24 --subnet 10.10.20.0/24
```

The operating system must have a route to each subnet; specifying a subnet does not bypass VLAN isolation or create routes.

- ↑/↓ or j/k: select a device; click a row with a mouse-enabled terminal
- Enter: open or close details on narrow terminals; Esc closes them
- Page Up/Down: scroll details
- i: toggle Nerd Font icons; q: quit

ARP sweeps run continuously, paced at up to 200 addresses per second. ICMP checks, mDNS and UPnP run independently. Results update as they arrive and are ordered by observed exposure: gateways and web services first, other network services next, then device types and phones. This is a monitoring order, not a vulnerability score; unknown devices do not imply low risk. When a name is unavailable, the map uses the MAC vendor and advertised model where available. Every discovered device, including phones and Macs, is queued for a quick scan of the top 100 TCP ports and a deeper scan of the top 1,000, plus device-specific ports such as 62078 (Apple device sync), AirPlay and common NAS and home-server ports. The deeper pass checks service versions, selected HTTP, certificate and SMB details, and OS fingerprints when privileged. Up to 32 quick and 32 deep nmap scans run concurrently; name lookups and up to 128 reachability checks run separately; up to 4,096 jobs can wait in each queue. Deep scans have a per-host timeout and repeat 15 minutes after completion. The UI polls for updates every millisecond; actual probe, scan and terminal refresh speeds depend on the system and network. Failed nmap checks are retried on affected ports; unresolved failures appear under scan diagnostics and mark the scan partial.

NetAtlas scans active Ethernet and configured VLAN interfaces, plus private routed subnets of /20 to /30 listed in the system routing table. Additional private /16 to /30 subnets can be supplied with `--subnet`. Broad routes are not treated as proof of a populated subnet. Routed networks use ICMP and TCP reachability rather than ARP; shared proxy-ARP replies are verified without assigning the proxy MAC to other devices. VLANs that are neither configured nor reachable by a route cannot be discovered, and map branches show subnet membership rather than physical links. Networks larger than /20 are scanned in rotating /24 blocks, starting with the interface’s block on connected networks. Device type, OS fingerprints and MAC-vendor lookups are estimates. Model claims show their source because advertised values can be misleading. Port results are timestamped and only cover scanned TCP ports; device information may be incomplete or change over time. Bonjour-only devices are unconfirmed until a separate live response is observed. Some devices use private MAC addresses or do not expose identifying information or open ports.

Research references: [lsnet](https://github.com/sanford/lsnet) (GPL-3.0), [Nmap service detection](https://nmap.org/book/man-version-detection.html), [Nmap OS detection](https://nmap.org/book/man-os-detection.html), and [Apple private Wi-Fi addresses](https://support.apple.com/en-gb/guide/iphone/iph6b324bb33/ios).

Port labels use the bundled [IANA service-name and port registry](https://www.iana.org/assignments/service-names-port-numbers). IANA assignments are shown separately from detected services, while advertised Bonjour types use their registered descriptions. Run `scripts/update-port-registry.sh` and rebuild to refresh the offline copy.
