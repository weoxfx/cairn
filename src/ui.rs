//! Terminal UI: theme, app header, panels, tables, status lines and the secret
//! screen.
//!
//! Everything here is ANSI-aware: widths are measured with
//! [`measure_text_width`], so coloured cells still line up.

use bitcoin::Network;
use console::{measure_text_width, style, Style, Term};
use dialoguer::{theme::ColorfulTheme, Input, Select};
use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::Duration;

static DISPLAY_NETWORK: Mutex<Network> = Mutex::new(Network::Bitcoin);
static CONTEXT: Mutex<Option<String>> = Mutex::new(None);

pub fn set_network(network: Network) {
    *DISPLAY_NETWORK.lock().unwrap_or_else(|e| e.into_inner()) = network;
}

pub fn display_network() -> Network {
    *DISPLAY_NETWORK.lock().unwrap_or_else(|e| e.into_inner())
}

/// Breadcrumb shown under the header, e.g. `main · 73c5da0a`.
pub fn set_context(context: impl Into<String>) {
    *CONTEXT.lock().unwrap_or_else(|e| e.into_inner()) = Some(context.into());
}

fn context() -> Option<String> {
    CONTEXT.lock().unwrap_or_else(|e| e.into_inner()).clone()
}

/// Usable content width: terminal width minus the two-space margin, clamped so
/// the layout stays readable on tiny and very wide terminals.
pub fn width() -> usize {
    (Term::stdout().size().1 as usize)
        .saturating_sub(4)
        .clamp(40, 78)
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
        // Two-space margin, matching the rest of the layout; both prefixes are
        // the same width so the items stay aligned.
        active_item_prefix: style("  › ".to_string()).cyan().bold(),
        inactive_item_prefix: style("    ".to_string()),
        ..ColorfulTheme::default()
    }
}

pub fn clear() {
    let _ = Term::stdout().clear_screen();
    print!("\x1b[3J");
}

/// App header: wordmark, version, network badge, rule and breadcrumb line.
pub fn banner() {
    clear();
    let width = width();
    let mainnet = display_network() == Network::Bitcoin;
    let badge = if mainnet {
        style(" MAINNET ").black().on_yellow().bold().to_string()
    } else {
        style(" TESTNET ").black().on_cyan().bold().to_string()
    };
    let left = format!(
        "{}  {}  {}",
        style("◆").cyan().bold(),
        style("CAIRN").bold(),
        style(format!("v{}", env!("CARGO_PKG_VERSION"))).dim()
    );

    println!(
        "  {}{}{}",
        left,
        " ".repeat(width.saturating_sub(measure_text_width(&left) + measure_text_width(&badge))),
        badge
    );
    println!("  {}", style("━".repeat(width)).cyan().dim());

    let format = if mainnet {
        "Native SegWit · BIP84"
    } else {
        "Testnet · Native SegWit · BIP84"
    };
    let crumb = context().unwrap_or_else(|| "No wallet open".to_string());
    let crumb = style(crumb).bold().to_string();
    let right = style(format).dim().to_string();
    println!(
        "  {}{}{}\n",
        crumb,
        " ".repeat(width.saturating_sub(measure_text_width(&crumb) + measure_text_width(&right))),
        right
    );
}

pub fn section(title: &str) {
    println!("  {}", style(title).bold());
    println!(
        "  {}",
        style("─".repeat(measure_text_width(title).max(20))).dim()
    );
}

/// Dim label in a fixed column, value beside it.
pub fn kv(key: &str, value: &str) {
    println!("  {:<18}{}", style(key).dim(), value);
}

/// Two-column stat grid, used for balance breakdowns.
pub fn grid(items: &[(&str, &str)]) {
    let key_w = items
        .iter()
        .map(|(k, _)| measure_text_width(k))
        .max()
        .unwrap_or(0);
    let val_w = items
        .iter()
        .map(|(_, v)| measure_text_width(v))
        .max()
        .unwrap_or(0);
    for chunk in items.chunks(2) {
        let mut line = String::from("  ");
        for (i, (k, v)) in chunk.iter().enumerate() {
            if i > 0 {
                line.push_str("   ");
            }
            line.push_str(&style(format!("{k:<key_w$}")).dim().to_string());
            line.push_str("  ");
            line.push_str(&format!("{v:<val_w$}"));
        }
        println!("{}", line.trim_end());
    }
}

/// Header row plus thin rule, then aligned cells. ANSI in cells is accounted
/// for; the last column is never right-padded, so no trailing whitespace.
pub fn table(headers: &[&str], rows: &[Vec<String>], right: &[bool]) {
    let cols = headers.len();
    let mut widths: Vec<usize> = headers.iter().map(|h| measure_text_width(h)).collect();
    for row in rows {
        for (w, cell) in widths.iter_mut().zip(row.iter()).take(cols) {
            *w = (*w).max(measure_text_width(cell));
        }
    }
    let render = |cells: &[String], styled: bool| {
        let mut line = String::from("  ");
        for (i, width) in widths.iter().enumerate() {
            let raw = cells.get(i).cloned().unwrap_or_default();
            let cell = if styled {
                style(raw.to_uppercase()).dim().to_string()
            } else {
                raw
            };
            let pad = width.saturating_sub(measure_text_width(&cell));
            let is_right = right.get(i).copied().unwrap_or(false);
            if i > 0 {
                line.push_str("  ");
            }
            if is_right {
                line.push_str(&" ".repeat(pad));
                line.push_str(&cell);
            } else {
                line.push_str(&cell);
                if i + 1 < cols {
                    line.push_str(&" ".repeat(pad));
                }
            }
        }
        println!("{}", line.trim_end());
    };
    let head: Vec<String> = headers.iter().map(|h| h.to_string()).collect();
    render(&head, true);
    let total = widths.iter().sum::<usize>() + 2 * cols.saturating_sub(1);
    println!("  {}", style("─".repeat(total.min(width()))).dim());
    for row in rows {
        render(row, false);
    }
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

/// Rounded panel with an optional title. Width is ANSI-aware and widened when
/// the title is longer than the content, so the frame never breaks.
pub fn card(title: &str, lines: &[String]) {
    // A panel narrower than this reads as a stamp rather than a card, so short
    // content still gets a comfortable frame.
    let limit = width().saturating_sub(4);
    let floor = 44.min(limit);
    let inner = lines
        .iter()
        .map(|l| measure_text_width(l))
        .max()
        .unwrap_or(0)
        .max(floor)
        .max(measure_text_width(title) + 5)
        .min(limit);
    let top = if title.is_empty() {
        "─".repeat(inner + 2)
    } else {
        format!(
            "─ {} {}",
            style(title).bold(),
            "─".repeat(inner.saturating_sub(measure_text_width(title) + 3))
        )
    };
    println!("  {}", style(format!("╭{top}╮")).dim());
    for line in lines {
        let pad = inner.saturating_sub(measure_text_width(line));
        println!(
            "  {} {}{} {}",
            style("│").dim(),
            line,
            " ".repeat(pad),
            style("│").dim()
        );
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

/// `123 456` — sat amounts with thin grouping, easier to scan than 123456.
pub fn fmt_sats(sats: i64) -> String {
    let sign = if sats < 0 { "-" } else { "" };
    let digits = sats.unsigned_abs().to_string();
    let mut out = String::new();
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push('\u{2009}');
        }
        out.push(c);
    }
    format!("{sign}{out}")
}

pub fn short(s: &str) -> String {
    if s.len() > 20 {
        format!("{}…{}", &s[..10], &s[s.len() - 6..])
    } else {
        s.to_string()
    }
}
