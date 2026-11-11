mod discovery;
mod fingerprint;
mod model;
mod port_registry;
mod ssdp;
mod ui;

use std::io;
fn main() -> io::Result<()> {
    if std::env::args().any(|a| a == "--help" || a == "-h") {
        println!("NetAtlas — live local network map\n\nUsage: netatlas [--demo]\n\nRun with sudo for direct ARP discovery. nmap is optional.\nKeys: ↑/↓ select · Enter details · i icons · q quit");
        return Ok(());
    }
    ui::run(std::env::args().any(|a| a == "--demo"))
}
