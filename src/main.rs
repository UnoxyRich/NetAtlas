mod discovery;
mod fingerprint;
mod model;
mod netbios;
mod port_registry;
mod routes;
mod ssdp;
mod ui;

use std::io;
fn main() -> io::Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "--help" || a == "-h") {
        println!("NetAtlas — live local network map\n\nUsage: netatlas [--demo] [--subnet PRIVATE_CIDR]...\n\nRun with sudo for direct ARP discovery. nmap is optional.\nKeys: ↑/↓ select · Enter details · i icons · q quit");
        return Ok(());
    }
    let mut extra_subnets = Vec::new();
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--demo" => (),
            "--subnet" => {
                let subnet = iter.next().ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "--subnet needs a private IPv4 CIDR",
                    )
                })?;
                routes::parse_subnet(subnet)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
                extra_subnets.push(subnet.clone());
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("unknown argument: {arg}"),
                ))
            }
        }
    }
    ui::run(args.iter().any(|a| a == "--demo"), extra_subnets)
}
