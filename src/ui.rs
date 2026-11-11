use crate::{
    discovery::{Network, Scanner, Snapshot},
    model::{Device, DeviceKind, DeviceStore, Observation},
};
use crossterm::{
    event::{
        self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind, MouseButton,
        MouseEventKind,
    },
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Paragraph, Wrap},
    Frame, Terminal,
};
use std::{
    io,
    time::{Duration, Instant},
};

const GREEN: Color = Color::Rgb(119, 217, 166);
const MUTED: Color = Color::Rgb(130, 148, 145);
const AMBER: Color = Color::Rgb(237, 185, 103);
struct App {
    scanner: Option<Scanner>,
    snap: Snapshot,
    selected: Option<u64>,
    offset: usize,
    details_offset: u16,
    map_right: u16,
    rows: Vec<(u16, u64)>,
    nerd: bool,
    modal: bool,
}
impl App {
    fn new(demo: bool) -> Self {
        Self {
            scanner: (!demo).then(Scanner::start),
            snap: if demo {
                demo_snapshot()
            } else {
                Snapshot::default()
            },
            selected: None,
            offset: 0,
            details_offset: 0,
            map_right: 0,
            rows: vec![],
            nerd: false,
            modal: false,
        }
    }
    fn devices(&self) -> Vec<&Device> {
        let mut devices: Vec<_> = self
            .snap
            .devices
            .iter()
            .filter(|d| {
                self.snap
                    .networks
                    .iter()
                    .any(|n| n.interface == d.interface && n.contains(d.ip))
            })
            .collect();
        devices.sort_by(|a, b| {
            a.interface
                .cmp(&b.interface)
                .then_with(|| a.priority().0.cmp(&b.priority().0))
                .then_with(|| a.kind.label().cmp(b.kind.label()))
                .then_with(|| a.services.first().cmp(&b.services.first()))
                .then_with(|| {
                    a.ports
                        .first()
                        .map(|p| &p.service)
                        .cmp(&b.ports.first().map(|p| &p.service))
                })
                .then(a.ip.cmp(&b.ip))
        });
        devices
    }
    fn navigate(&mut self, delta: isize) {
        let ids: Vec<_> = self.devices().iter().map(|d| d.id).collect();
        if ids.is_empty() {
            return;
        }
        let index = self
            .selected
            .and_then(|id| ids.iter().position(|i| *i == id))
            .unwrap_or(if delta > 0 { ids.len() - 1 } else { 0 });
        self.selected =
            Some(ids[(index as isize + delta).clamp(0, ids.len() as isize - 1) as usize]);
        self.details_offset = 0;
    }
    fn update(&mut self) -> bool {
        let mut changed = false;
        if let Some(scanner) = &self.scanner {
            while let Ok(s) = scanner.updates.try_recv() {
                self.snap = s;
                changed = true;
            }
        }
        if !self
            .selected
            .is_some_and(|id| self.devices().iter().any(|d| d.id == id))
        {
            let next = self.devices().first().map(|d| d.id);
            if self.selected != next {
                self.selected = next;
                self.details_offset = 0;
                changed = true;
            }
        }
        changed
    }
    fn render(&mut self, f: &mut Frame) {
        let area = f.area();
        f.render_widget(
            Block::default().style(
                Style::default()
                    .bg(Color::Rgb(17, 23, 25))
                    .fg(Color::Rgb(225, 234, 228)),
            ),
            area,
        );
        if area.width < 45 || area.height < 8 {
            f.render_widget(Paragraph::new("Resize terminal to at least 45 × 8"), area);
            return;
        }
        let v = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3),
                Constraint::Min(3),
                Constraint::Length(2),
            ])
            .split(area);
        let header = Line::from(vec![
            Span::styled(
                " NETATLAS ",
                Style::default().fg(GREEN).add_modifier(Modifier::BOLD),
            ),
            Span::raw("  "),
            Span::styled(&self.snap.status, Style::default().fg(MUTED)),
        ]);
        f.render_widget(
            Paragraph::new(header).block(
                Block::default()
                    .borders(Borders::BOTTOM)
                    .border_style(Style::default().fg(Color::DarkGray)),
            ),
            v[0],
        );
        let wide = area.width >= 94;
        let parts = if wide {
            Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
                .split(v[1])
                .to_vec()
        } else {
            vec![v[1]]
        };
        self.render_map(f, parts[0]);
        if wide {
            self.render_details(f, parts[1]);
        } else if self.modal {
            let p = centered(area, 80, 80);
            f.render_widget(Clear, p);
            self.render_details(f, p);
        }
        let footer = if wide {
            " ↑↓ select   click device   PgUp/PgDn details   i icons   q quit "
        } else {
            " ↑↓ select   Enter details   PgUp/PgDn scroll   i icons   q quit "
        };
        let warning = self
            .snap
            .warnings
            .first()
            .map(|s| format!("  ⚠ {s}"))
            .unwrap_or_default();
        f.render_widget(
            Paragraph::new(vec![
                Line::styled(warning, Style::default().fg(AMBER)),
                Line::styled(footer, Style::default().fg(MUTED)),
            ]),
            v[2],
        );
    }
    fn render_map(&mut self, f: &mut Frame, area: Rect) {
        self.map_right = area.x + area.width;
        let block = Block::default()
            .title(format!(" Network map · {} devices ", self.devices().len()))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray));
        let inner = block.inner(area);
        f.render_widget(block, area);
        let mut lines: Vec<(Line<'static>, Option<u64>)> = vec![];
        for net in &self.snap.networks {
            let vlan = net
                .vlan
                .as_ref()
                .map(|v| format!(" · VLAN {v}"))
                .unwrap_or_default();
            lines.push((
                Line::styled(
                    format!(" ◉ {}  {}{}", net.interface, net.cidr(), vlan),
                    Style::default().fg(GREEN).add_modifier(Modifier::BOLD),
                ),
                None,
            ));
            let list: Vec<_> = self
                .devices()
                .into_iter()
                .filter(|d| d.interface == net.interface && net.contains(d.ip))
                .collect();
            if list.is_empty() {
                lines.push((
                    Line::styled("   └─ waiting for devices", Style::default().fg(MUTED)),
                    None,
                ));
            }
            for (idx, d) in list.iter().enumerate() {
                let branch = if idx + 1 == list.len() {
                    "└─"
                } else {
                    "├─"
                };
                let icon = if self.nerd {
                    d.kind.icon()
                } else {
                    ascii_icon(d.kind)
                };
                let selected = self.selected == Some(d.id);
                let status = if d.online() { "●" } else { "○" };
                let name = d.display_name();
                let line = Line::from(vec![
                    Span::styled(
                        format!("   {branch} "),
                        Style::default().fg(Color::DarkGray),
                    ),
                    Span::styled(format!("{icon} "), Style::default().fg(GREEN)),
                    Span::styled(
                        format!("{name}  "),
                        Style::default().add_modifier(if selected {
                            Modifier::BOLD
                        } else {
                            Modifier::empty()
                        }),
                    ),
                    Span::styled(
                        format!("{}  {status}", d.ip),
                        Style::default().fg(if d.online() { MUTED } else { Color::DarkGray }),
                    ),
                ]);
                lines.push((
                    if selected {
                        line.style(Style::default().bg(Color::Rgb(40, 61, 51)))
                    } else {
                        line
                    },
                    Some(d.id),
                ));
            }
            lines.push((Line::raw(""), None));
        }
        if self.snap.networks.is_empty() {
            lines.push((
                Line::styled(" Waiting for a local network…", Style::default().fg(MUTED)),
                None,
            ));
        }
        if let Some(pos) = lines
            .iter()
            .position(|(_, id)| *id == self.selected && id.is_some())
        {
            let h = inner.height as usize;
            if pos < self.offset {
                self.offset = pos;
            } else if h > 0 && pos >= self.offset + h {
                self.offset = pos + 1 - h;
            }
        }
        self.offset = self
            .offset
            .min(lines.len().saturating_sub(inner.height as usize));
        self.rows.clear();
        let shown: Vec<_> = lines
            .into_iter()
            .skip(self.offset)
            .take(inner.height as usize)
            .enumerate()
            .map(|(i, (line, id))| {
                if let Some(id) = id {
                    self.rows.push((inner.y + i as u16, id));
                }
                line
            })
            .collect();
        f.render_widget(Paragraph::new(shown), inner);
    }
    fn render_details(&self, f: &mut Frame, area: Rect) {
        let block = Block::default()
            .title(" Device details ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray));
        let inner = block.inner(area);
        f.render_widget(block, area);
        let Some(d) = self
            .selected
            .and_then(|id| self.snap.devices.iter().find(|d| d.id == id))
        else {
            f.render_widget(Paragraph::new(" Select a device"), inner);
            return;
        };
        let mut lines = vec![
            Line::from(vec![
                Span::styled(
                    format!(
                        " {}  ",
                        if self.nerd {
                            d.kind.icon()
                        } else {
                            ascii_icon(d.kind)
                        }
                    ),
                    Style::default().fg(GREEN),
                ),
                Span::styled(
                    d.display_name(),
                    Style::default()
                        .fg(Color::White)
                        .add_modifier(Modifier::BOLD),
                ),
            ]),
            Line::styled(
                format!(
                    " {} (estimated) · {}",
                    d.kind.label(),
                    if d.online() {
                        "Online"
                    } else if !d.confirmed {
                        "Unconfirmed"
                    } else {
                        "Last seen > 3m ago"
                    }
                ),
                Style::default().fg(GREEN),
            ),
            Line::raw(""),
        ];
        let mut row = |label: &str, value: String| {
            lines.push(Line::from(vec![
                Span::styled(format!(" {label:<13}"), Style::default().fg(MUTED)),
                Span::raw(value),
            ]));
        };
        row("IP", d.ip.to_string());
        row("MAC", d.mac.clone().unwrap_or_else(|| "—".into()));
        row("Interface", d.interface.clone());
        row("Type evidence", d.kind_reason.into());
        row("Priority", d.priority().1.into());
        row(
            "MAC vendor",
            d.manufacturer().unwrap_or("Unknown / private MAC").into(),
        );
        if let Some(vendor) = &d.vendor {
            row(
                "Vendor claim",
                format!(
                    "{} ({})",
                    vendor,
                    d.vendor_source.as_deref().unwrap_or("advertised")
                ),
            );
        }
        row("Hostname", d.name.clone().unwrap_or_else(|| "—".into()));
        if !d.aliases.is_empty() {
            row("Other names", d.aliases.join(", "));
        }
        if let Some(os) = &d.os {
            row("OS guess", os.clone());
        }
        if let Some(status) = &d.scan_status {
            row("Scan", status.clone());
        }
        if !d.model_claims.is_empty() {
            row("Model claims", d.model_claims.join("; "));
        }
        row(
            "Last seen",
            if d.confirmed {
                format!("{}s ago", d.last_seen.elapsed().as_secs())
            } else {
                "Unconfirmed".into()
            },
        );
        lines.push(Line::raw(""));
        lines.push(Line::styled(
            " Advertised services",
            Style::default().fg(MUTED).add_modifier(Modifier::BOLD),
        ));
        if d.services.is_empty() {
            lines.push(Line::styled(
                " None discovered",
                Style::default().fg(Color::DarkGray),
            ));
        }
        for s in &d.services {
            lines.push(Line::raw(format!(
                "  {}",
                crate::port_registry::describe_advertised(s)
            )));
        }
        lines.push(Line::raw(""));
        let port_title = d
            .ports_scanned_at
            .map(|t| {
                format!(
                    " Last observed open TCP ports · last scan {}s ago",
                    t.elapsed().as_secs()
                )
            })
            .unwrap_or_else(|| " Open TCP ports · waiting for scan".into());
        lines.push(Line::styled(
            port_title,
            Style::default().fg(MUTED).add_modifier(Modifier::BOLD),
        ));
        if let Some(summary) = &d.port_summary {
            lines.push(Line::styled(
                format!(
                    "  Top 1000 ({}s ago): {summary}",
                    d.port_summary_at
                        .map(|t| t.elapsed().as_secs())
                        .unwrap_or(0)
                ),
                Style::default().fg(MUTED),
            ));
        }
        if d.ports_scanned_at.is_some() && d.ports.is_empty() {
            lines.push(Line::styled(
                "  None found in scanned ports",
                Style::default().fg(Color::DarkGray),
            ));
        }
        for p in &d.ports {
            lines.push(Line::styled(
                format!(
                    "  {}{}{}",
                    p.summary(),
                    p.observed_at
                        .map(|t| format!(" · open {}s ago", t.elapsed().as_secs()))
                        .unwrap_or_default(),
                    match (p.observed_at, p.fingerprinted_at) {
                        (Some(observed), Some(fingerprinted))
                            if observed.saturating_duration_since(fingerprinted).as_secs() > 5 =>
                            format!(" · fingerprint {}s ago", fingerprinted.elapsed().as_secs()),
                        _ => String::new(),
                    }
                ),
                Style::default().fg(Color::White),
            ));
            if let Some(names) = crate::port_registry::registered_names(p.number, &p.protocol) {
                lines.push(Line::styled(
                    format!("    IANA assignment: {names}"),
                    Style::default().fg(MUTED),
                ));
            }
            for finding in &p.findings {
                for (index, line) in finding.lines().enumerate() {
                    let age = if index == 0 {
                        p.finding_times
                            .get(finding)
                            .map(|t| format!(" · {}s ago", t.elapsed().as_secs()))
                            .unwrap_or_default()
                    } else {
                        String::new()
                    };
                    lines.push(Line::raw(format!("    {line}{age}")));
                }
            }
        }
        if !d.scan_warnings.is_empty() {
            lines.push(Line::raw(""));
            lines.push(Line::styled(
                " Nmap checks that failed",
                Style::default().fg(AMBER).add_modifier(Modifier::BOLD),
            ));
            for warning in &d.scan_warnings {
                lines.push(Line::styled(
                    format!("  {warning}"),
                    Style::default().fg(AMBER),
                ));
            }
        }
        if !d.findings.is_empty() {
            lines.push(Line::raw(""));
            lines.push(Line::styled(
                " Fingerprints",
                Style::default().fg(MUTED).add_modifier(Modifier::BOLD),
            ));
            for finding in &d.findings {
                for line in finding.lines() {
                    lines.push(Line::raw(format!("  {line}")));
                }
            }
        }
        f.render_widget(
            Paragraph::new(lines)
                .wrap(Wrap { trim: false })
                .scroll((self.details_offset, 0)),
            inner,
        );
    }
}
fn ascii_icon(k: DeviceKind) -> &'static str {
    match k {
        DeviceKind::Router => "[R]",
        DeviceKind::Switch => "[S]",
        DeviceKind::Printer => "[P]",
        DeviceKind::Nas => "[N]",
        DeviceKind::Mac => "[M]",
        DeviceKind::Iphone => "[i]",
        DeviceKind::Ipad => "[iP]",
        DeviceKind::Speaker => "[♪]",
        DeviceKind::Windows => "[W]",
        DeviceKind::Computer => "[C]",
        DeviceKind::RaspberryPi => "[Rπ]",
        DeviceKind::Phone => "[p]",
        DeviceKind::Camera => "[◉]",
        DeviceKind::Tv => "[T]",
        DeviceKind::Unknown => "[?]",
    }
}
fn centered(r: Rect, px: u16, py: u16) -> Rect {
    let v = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - py) / 2),
            Constraint::Percentage(py),
            Constraint::Percentage((100 - py) / 2),
        ])
        .split(r);
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - px) / 2),
            Constraint::Percentage(px),
            Constraint::Percentage((100 - px) / 2),
        ])
        .split(v[1])[1]
}
pub fn run(demo: bool) -> io::Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    if let Err(e) = execute!(stdout, EnterAlternateScreen, EnableMouseCapture) {
        let _ = disable_raw_mode();
        return Err(e);
    }
    let mut terminal = match Terminal::new(CrosstermBackend::new(stdout)) {
        Ok(t) => t,
        Err(e) => {
            let _ = disable_raw_mode();
            let _ = execute!(io::stdout(), LeaveAlternateScreen, DisableMouseCapture);
            return Err(e);
        }
    };
    let result = run_loop(&mut terminal, App::new(demo));
    let _ = disable_raw_mode();
    let _ = execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    );
    let _ = terminal.show_cursor();
    result
}
fn run_loop(terminal: &mut Terminal<CrosstermBackend<io::Stdout>>, mut app: App) -> io::Result<()> {
    let mut redraw = true;
    let mut last_draw = Instant::now();
    loop {
        redraw |= app.update();
        if redraw || last_draw.elapsed() >= Duration::from_secs(1) {
            terminal.draw(|f| app.render(f))?;
            last_draw = Instant::now();
            redraw = false;
        }
        if !event::poll(Duration::from_millis(1))? {
            continue;
        }
        redraw = true;
        match event::read()? {
            Event::Key(k) if k.kind == KeyEventKind::Press => match k.code {
                KeyCode::Char('q') => break,
                KeyCode::Esc => app.modal = false,
                KeyCode::Down | KeyCode::Char('j') => app.navigate(1),
                KeyCode::Up | KeyCode::Char('k') => app.navigate(-1),
                KeyCode::Enter => app.modal = !app.modal,
                KeyCode::Char('i') => app.nerd = !app.nerd,
                KeyCode::PageDown => app.details_offset = app.details_offset.saturating_add(5),
                KeyCode::PageUp => app.details_offset = app.details_offset.saturating_sub(5),
                _ => {}
            },
            Event::Mouse(m) => match m.kind {
                MouseEventKind::Down(MouseButton::Left) => {
                    if !app.modal && m.column < app.map_right {
                        if let Some((_, id)) = app.rows.iter().find(|(y, _)| *y == m.row) {
                            app.selected = Some(*id);
                            app.details_offset = 0;
                            if terminal.size()?.width < 94 {
                                app.modal = true;
                            }
                        }
                    }
                }
                MouseEventKind::ScrollDown => app.navigate(1),
                MouseEventKind::ScrollUp => app.navigate(-1),
                _ => {}
            },
            _ => {}
        }
    }
    Ok(())
}
fn demo_snapshot() -> Snapshot {
    let addr = |x| std::net::Ipv4Addr::new(192, 168, 31, x);
    let mut store = DeviceStore::default();
    for (ip, name, gateway, local) in [
        (1, "Gateway", true, false),
        (7, "MacBook Air", false, false),
        (21, "Office printer", false, false),
        (29, "ezviz camera", false, false),
        (86, "This Mac", false, true),
        (156, "richs-iPhone", false, false),
        (161, "DiskStation NAS", false, false),
    ] {
        let mut o = Observation::new(addr(ip), "en0");
        o.name = Some(name.into());
        o.gateway = gateway;
        o.local = local;
        if gateway {
            o.services.push("_http._tcp :80 (advertised)".into());
            o.ports.push(crate::model::Port {
                number: 80,
                protocol: "tcp".into(),
                service: "http".into(),
                service_source: "probed".into(),
                ..Default::default()
            });
            o.ports_scanned = true;
        }
        store.observe(o);
    }
    Snapshot {
        devices: store.snapshot(),
        networks: vec![Network {
            interface: "en0".into(),
            address: addr(86),
            mask: "255.255.255.0".parse().unwrap(),
            gateway: Some(addr(1)),
            vlan: None,
        }],
        status: "Demo · simulated devices".into(),
        warnings: vec![],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::backend::TestBackend;

    #[test]
    fn scan_failures_are_shown_as_diagnostics_not_service_results() {
        let mut app = App::new(true);
        let device = &mut app.snap.devices[0];
        device.scan_status = Some("Partial · some nmap checks failed".into());
        device.scan_warnings = vec!["rpcinfo (22/tcp)".into()];
        app.selected = Some(device.id);
        let mut terminal = Terminal::new(TestBackend::new(140, 45)).unwrap();
        terminal.draw(|frame| app.render(frame)).unwrap();
        let text: String = terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|cell| cell.symbol())
            .collect();
        assert!(text.contains("Partial · some nmap checks failed"));
        assert!(text.contains("Nmap checks that failed"));
        assert!(text.contains("rpcinfo (22/tcp)"));
        assert!(!text.contains("ERROR: Script execution failed"));
    }
}
