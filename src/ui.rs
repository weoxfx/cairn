//! Terminal UI: theme, compact header, cards, status lines and the secret screen.

use bitcoin::Network;
use console::{measure_text_width, style, Style, Term};
use dialoguer::{theme::ColorfulTheme, Input, Select};
use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::Duration;

static DISPLAY_NETWORK: Mutex<Network> = Mutex::new(Network::Bitcoin);

pub fn set_network(network: Network) {
    *DISPLAY_NETWORK.lock().unwrap_or_else(|e| e.into_inner()) = network;
}

pub fn display_network() -> Network {
    *DISPLAY_NETWORK.lock().unwrap_or_else(|e| e.into_inner())
}

pub fn theme() -> ColorfulTheme {
    ColorfulTheme {
        prompt_style: Style::new().cyan().bold(),
        prompt_prefix: style("›".to_string()).cyan().bold(),
        success_prefix: style("✓".to_string()).green().bold(),
        error_prefix: style("✗".to_string()).red().bold(),
        hint_style: Style::new().dim(),
        active_item_style: Style::new().cyan().bold(),
        inactive_item_style: Style::new().dim(),
        active_item_prefix: style("›".to_string()).cyan().bold(),
        ..ColorfulTheme::default()
    }
}

pub fn clear() {
    let _ = Term::stdout().clear_screen();
    print!("\x1b[3J");
}

/// Compact header: wordmark, version, chain and address format.
pub fn banner() {
    clear();
    let width = (Term::stdout().size().1 as usize)
        .saturating_sub(4)
        .clamp(34, 64);
    let version = style(format!("v{}", env!("CARGO_PKG_VERSION"))).dim();
    let subtitle = style("Bitcoin wallet").dim();
    let mainnet = display_network() == Network::Bitcoin;
    let badge = if mainnet {
        style(" MAINNET ").black().on_yellow().bold()
    } else {
        style(" TESTNET ").black().on_cyan().bold()
    };
    let format = if mainnet {
        "Native SegWit · BIP84"
    } else {
        "Testnet · Native SegWit · BIP84"
    };

    println!(
        "  {}  {}  {}   {}",
        style("◆").cyan().bold(),
        style("CAIRN").bold(),
        version,
        subtitle
    );
    println!("  {}", style("─".repeat(width)).dim());
    println!("  {}  {}\n", badge, style(format).dim());
}

pub fn section(title: &str) {
    println!("  {}", style(title).bold());
    println!(
        "  {}",
        style("─".repeat(measure_text_width(title).max(20))).dim()
    );
}

pub fn kv(key: &str, value: &str) {
    println!("  {:<16}{}", style(key).dim(), value);
}

pub fn hint(msg: &str) {
    println!("  {}", style(msg).dim());
}

pub fn warn(msg: &str) {
    println!("  {} {}", style("!").yellow().bold(), style(msg).yellow());
}

pub fn info(msg: &str) {
    println!("  {} {}", style("·").cyan().bold(), style(msg).dim());
}

pub fn ok(msg: &str) {
    println!("  {} {}", style("✓").green().bold(), msg);
}

pub fn fail(msg: &str) {
    println!("  {} {}", style("✗").red().bold(), style(msg).red());
}

pub fn pause() {
    let _: String = Input::with_theme(&theme())
        .with_prompt("Press Enter to continue")
        .allow_empty(true)
        .interact_text()
        .unwrap_or_default();
}

pub fn menu(items: &[&str]) -> Result<usize, String> {
    Select::with_theme(&theme())
        .items(items)
        .default(0)
        .interact()
        .map_err(|e| e.to_string())
}

/// Run `f` while an animated spinner shows on the terminal.
pub fn spin<T>(msg: &str, f: impl FnOnce() -> T) -> T {
    let done = AtomicBool::new(false);
    std::thread::scope(|s| {
        let handle = s.spawn(|| {
            let frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
            let term = Term::stdout();
            let mut i = 0usize;
            while !done.load(Ordering::Relaxed) {
                let _ = term.write_str(&format!(
                    "\r  {} {}",
                    style(frames[i % frames.len()]).cyan(),
                    style(msg).dim()
                ));
                i += 1;
                std::thread::sleep(Duration::from_millis(80));
            }
            let _ = term.write_str("\r");
            let _ = term.clear_line();
        });
        let result = f();
        done.store(true, Ordering::Relaxed);
        let _ = handle.join();
        result
    })
}

/// Rounded card with an optional title. Width is ANSI-aware.
pub fn card(title: &str, lines: &[String]) {
    let inner = lines
        .iter()
        .map(|l| measure_text_width(l))
        .max()
        .unwrap_or(0)
        .max(24);
    let top = if title.is_empty() {
        format!("╭{}╮", "─".repeat(inner + 2))
    } else {
        format!(
            "╭─ {title} {}╮",
            "─".repeat(inner.saturating_sub(title.chars().count() + 1))
        )
    };
    println!("  {}", style(top).dim());
    for line in lines {
        let pad = inner.saturating_sub(measure_text_width(line));
        println!("  │ {}{} │", line, " ".repeat(pad));
    }
    println!("  {}", style(format!("╰{}╯", "─".repeat(inner + 2))).dim());
}

/// Backwards-compatible plain box.
pub fn boxed(lines: &[String]) {
    card("", lines);
}

/// Show something secret on the terminal's alternate screen so it never
/// enters the scrollback, and wipe it afterwards.
pub fn secret_screen(f: impl FnOnce()) {
    print!("\x1b[?1049h\x1b[2J\x1b[H");
    let _ = std::io::stdout().flush();
    f();
    print!("\x1b[2J\x1b[?1049l");
    let _ = std::io::stdout().flush();
}

pub fn fmt_btc(sats: i64) -> String {
    let sign = if sats < 0 { "-" } else { "" };
    let a = sats.unsigned_abs();
    format!("{sign}{}.{:08}", a / 100_000_000, a % 100_000_000)
}

pub fn short(s: &str) -> String {
    if s.len() > 20 {
        format!("{}…{}", &s[..10], &s[s.len() - 6..])
    } else {
        s.to_string()
    }
}
