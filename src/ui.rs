//! Terminal UI for CAIRN.
//!
//! Visual language: quiet and flat, in the spirit of OpenCode and Trust Wallet.
//! * No badges, banners or box drawing. Hierarchy comes from weight and dim.
//! * A centred balance, two-line activity rows, shaded panels for notices.
//! * One accent (cyan) used only for the selected item and testnet.
//! * A key-hint footer instead of instructions in prose.
//!
//! Every function from the previous version keeps its signature.

use bitcoin::Network;
use console::{colors_enabled, measure_text_width, style, Style, Term};
use dialoguer::{theme::ColorfulTheme, Confirm, Input, Select};
use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::Duration;

const MARGIN: &str = "  ";
const LABEL_W: usize = 18;
const PANEL_BG: &str = "\x1b[48;5;236m";
const RESET: &str = "\x1b[0m";

static DISPLAY_NETWORK: Mutex<Network> = Mutex::new(Network::Bitcoin);
static CONTEXT: Mutex<Option<String>> = Mutex::new(None);

// ───────────────────────────── state ─────────────────────────────

pub fn set_network(network: Network) {
    *DISPLAY_NETWORK.lock().unwrap_or_else(|e| e.into_inner()) = network;
}

pub fn display_network() -> Network {
    *DISPLAY_NETWORK.lock().unwrap_or_else(|e| e.into_inner())
}

/// Wallet label shown in the header, e.g. `main - 73c5da0a`.
pub fn set_context(context: impl Into<String>) {
    *CONTEXT.lock().unwrap_or_else(|e| e.into_inner()) = Some(context.into());
}

fn context() -> Option<String> {
    CONTEXT.lock().unwrap_or_else(|e| e.into_inner()).clone()
}

// ───────────────────────────── layout helpers ─────────────────────────────

/// Usable content width, clamped for tiny and very wide terminals.
pub fn width() -> usize {
    (Term::stdout().size().1 as usize)
        .saturating_sub(4)
        .clamp(40, 78)
}

fn pad_right(s: &str, w: usize) -> String {
    format!("{s}{}", " ".repeat(w.saturating_sub(measure_text_width(s))))
}

fn center(s: &str, w: usize) -> String {
    let pad = w.saturating_sub(measure_text_width(s)) / 2;
    format!("{}{s}", " ".repeat(pad))
}

/// `left ........ right`, `w` columns wide (at least a 2-space gap).
fn split_line(left: &str, right: &str, w: usize) -> String {
    let used = measure_text_width(left) + measure_text_width(right);
    format!("{left}{}{right}", " ".repeat(w.saturating_sub(used).max(2)))
}

/// Word-wrap to `max` columns. Words longer than `max` (addresses, txids) are
/// never split, so they stay copyable.
pub fn wrap(text: &str, max: usize) -> Vec<String> {
    let mut out = Vec::new();
    for para in text.split('\n') {
        let mut line = String::new();
        let mut len = 0usize;
        for word in para.split_whitespace() {
            let w = measure_text_width(word);
            if len == 0 {
                line.push_str(word);
                len = w;
            } else if len + 1 + w <= max {
                line.push(' ');
                line.push_str(word);
                len += 1 + w;
            } else {
                out.push(std::mem::take(&mut line));
                line.push_str(word);
                len = w;
            }
        }
        out.push(line);
    }
    out
}

/// Wrap only lines that are too wide; lines that fit are left untouched.
fn fit(text: &str, max: usize) -> Vec<String> {
    let mut out = Vec::new();
    for line in text.split('\n') {
        if measure_text_width(line) <= max {
            out.push(line.to_string());
        } else {
            out.extend(wrap(line, max));
        }
    }
    out
}

// ───────────────────────────── theme ─────────────────────────────

pub fn theme() -> ColorfulTheme {
    ColorfulTheme {
        prompt_style: Style::new().bold(),
        prompt_prefix: style("›".to_string()).cyan(),
        success_prefix: style("✓".to_string()).green(),
        error_prefix: style("✗".to_string()).red(),
        hint_style: Style::new().dim(),
        values_style: Style::new().cyan(),
        active_item_style: Style::new().bold(),
        inactive_item_style: Style::new().dim(),
        // Left accent bar on the selected row; both prefixes are 4 wide.
        active_item_prefix: style("  ▌ ".to_string()).cyan(),
        inactive_item_prefix: style("    ".to_string()),
        ..ColorfulTheme::default()
    }
}

// ───────────────────────────── screen ─────────────────────────────

pub fn clear() {
    let term = Term::stdout();
    if term.is_term() {
        let _ = term.clear_screen();
        print!("\x1b[3J");
    }
}

/// One quiet line. Mainnet is the normal state and stays dim; testnet is
/// called out so nobody mistakes play money for real money.
///
/// ```text
///   Cairn   main - 73c5da0a                              mainnet
/// ```
pub fn banner() {
    let testnet = display_network() != Network::Bitcoin;
    banner_with(if testnet { "testnet" } else { "mainnet" }, testnet);
}

/// Banner with an explicit right-hand status, for screens that are not on the
/// Bitcoin display network (EVM chains). `alert` paints the status like a
/// testnet, so a test chain is never mistaken for real money.
pub fn banner_with(status: &str, alert: bool) {
    clear();
    let w = width();
    let right = if alert {
        style(status).cyan().bold().to_string()
    } else {
        style(status).dim().to_string()
    };
    let crumb = context().unwrap_or_else(|| "No wallet open".to_string());
    let left = format!("{}   {}", style("Cairn").bold(), style(crumb).dim());
    println!("{MARGIN}{}\n", split_line(&left, &right, w));
}

/// Faint full-width rule. Use sparingly.
pub fn divider() {
    println!("{MARGIN}{}", style("─".repeat(width())).dim());
}

pub fn blank() {
    println!();
}

/// Bold heading with breathing room above. No underline.
pub fn section(title: &str) {
    println!();
    println!("{MARGIN}{}", style(title).bold());
    println!();
}

/// Wizard progress: `2/4  Confirm`.
pub fn step(current: usize, total: usize, title: &str) {
    println!(
        "{MARGIN}{}  {}\n",
        style(format!("{current}/{total}")).dim(),
        style(title).bold()
    );
}

// ───────────────────────────── data display ─────────────────────────────

/// Dim label in a fixed column, value beside it. Long values wrap with a
/// hanging indent.
pub fn kv(key: &str, value: &str) {
    let label = pad_right(&style(key).dim().to_string(), LABEL_W);
    let lines = fit(value, width().saturating_sub(LABEL_W));
    println!(
        "{MARGIN}{label}{}",
        lines.first().map(String::as_str).unwrap_or("")
    );
    for l in lines.iter().skip(1) {
        println!("{MARGIN}{}{l}", " ".repeat(LABEL_W));
    }
}

/// Centred headline balance, Trust-Wallet style.
///
/// ```text
///                       Total balance
///                    0.01234567 BTC
///                     1 234 567 sats
/// ```
pub fn hero(label: &str, sats: i64) {
    let w = width();
    println!();
    println!("{MARGIN}{}", center(&style(label).dim().to_string(), w));
    println!(
        "{MARGIN}{}",
        center(
            &format!("{} {}", style(fmt_btc(sats)).bold(), style("BTC").dim()),
            w
        )
    );
    println!(
        "{MARGIN}{}",
        center(
            &style(format!("{} sats", fmt_sats(sats))).dim().to_string(),
            w
        )
    );
    println!();
}

/// Two-line list row followed by a blank line:
///
/// ```text
///   Received                             +0.00500000 BTC
///   Nov 8 - Confirmed                             $312.40
/// ```
pub fn item(title: &str, subtitle: &str, value: &str, sub_value: &str) {
    let w = width();
    println!("{MARGIN}{}", split_line(title, value, w));
    println!(
        "{MARGIN}{}",
        split_line(
            &style(subtitle).dim().to_string(),
            &style(sub_value).dim().to_string(),
            w
        )
    );
    println!();
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
        let mut line = String::from(MARGIN);
        for (i, (k, v)) in chunk.iter().enumerate() {
            if i > 0 {
                line.push_str("    ");
            }
            line.push_str(&pad_right(&style(*k).dim().to_string(), key_w));
            line.push_str("  ");
            line.push_str(&pad_right(v, val_w));
        }
        println!("{}", line.trim_end());
    }
}

/// Dim header row, then aligned cells. No rules. The last column is never
/// right-padded, so there is no trailing whitespace.
pub fn table(headers: &[&str], rows: &[Vec<String>], right: &[bool]) {
    let cols = headers.len();
    let mut widths: Vec<usize> = headers.iter().map(|h| measure_text_width(h)).collect();
    for row in rows {
        for (w, cell) in widths.iter_mut().zip(row.iter()).take(cols) {
            *w = (*w).max(measure_text_width(cell));
        }
    }
    let render = |cells: &[String], header: bool| {
        let mut line = String::from(MARGIN);
        for (i, w) in widths.iter().enumerate() {
            let raw = cells.get(i).cloned().unwrap_or_default();
            let cell = if header {
                style(raw).dim().to_string()
            } else {
                raw
            };
            let pad = w.saturating_sub(measure_text_width(&cell));
            let is_right = right.get(i).copied().unwrap_or(false);
            if i > 0 {
                line.push_str("   ");
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
    for row in rows {
        render(row, false);
    }
}

/// Placeholder for an empty list.
pub fn empty(msg: &str) {
    println!("{MARGIN}{}", style(msg).dim());
}

/// Key hints footer, e.g. `keys(&[("↑↓", "move"), ("enter", "select")])`.
pub fn keys(binds: &[(&str, &str)]) {
    let parts: Vec<String> = binds
        .iter()
        .map(|(k, d)| format!("{k} {}", style(d).dim()))
        .collect();
    println!("{MARGIN}{}", parts.join("   "));
}

// ───────────────────────────── messages ─────────────────────────────

fn status(dot: String, msg: &str, paint: impl Fn(&str) -> String) {
    let lines = wrap(msg, width().saturating_sub(2));
    for (i, l) in lines.iter().enumerate() {
        if i == 0 {
            println!("{MARGIN}{dot} {}", paint(l));
        } else {
            println!("{MARGIN}  {}", paint(l));
        }
    }
}

pub fn hint(msg: &str) {
    for l in wrap(msg, width()) {
        println!("{MARGIN}{}", style(l).dim());
    }
}

pub fn info(msg: &str) {
    status(style("·").dim().to_string(), msg, |s| {
        style(s).dim().to_string()
    });
}

pub fn ok(msg: &str) {
    status(style("●").green().to_string(), msg, |s| s.to_string());
}

pub fn warn(msg: &str) {
    status(style("●").yellow().to_string(), msg, |s| s.to_string());
}

pub fn fail(msg: &str) {
    status(style("●").red().to_string(), msg, |s| s.to_string());
}

// ───────────────────────────── panels ─────────────────────────────

#[derive(Clone, Copy)]
pub enum Tone {
    Info,
    Success,
    Warning,
    Danger,
}

impl Tone {
    fn style(self) -> Style {
        match self {
            Tone::Info => Style::new().cyan(),
            Tone::Success => Style::new().green(),
            Tone::Warning => Style::new().yellow(),
            Tone::Danger => Style::new().red(),
        }
    }
}

/// One row of a shaded panel, exactly `w` columns wide. Inner resets are
/// followed by the background again so coloured text keeps the shading.
fn panel_row(line: &str, w: usize, bar: Option<Tone>) -> String {
    let pad = w.saturating_sub(4).saturating_sub(measure_text_width(line));
    if !colors_enabled() {
        let lead = if bar.is_some() { "▌ " } else { "  " };
        return format!("{lead}{line}");
    }
    let lead = match bar {
        Some(t) => t.style().on_color256(236).apply_to("▌").to_string(),
        None => format!("{PANEL_BG} "),
    };
    let body = line.replace(RESET, &format!("{RESET}{PANEL_BG}"));
    format!("{lead}{PANEL_BG} {body}{}  {RESET}", " ".repeat(pad))
}

fn panel(rows: &[String], bar: Option<Tone>) {
    let w = width();
    println!("{MARGIN}{}", panel_row("", w, bar));
    for r in rows {
        println!("{MARGIN}{}", panel_row(r, w, bar));
    }
    println!("{MARGIN}{}", panel_row("", w, bar));
}

/// Shaded panel with an optional bold title.
pub fn card(title: &str, lines: &[String]) {
    let inner = width().saturating_sub(4);
    let mut rows: Vec<String> = Vec::new();
    if !title.is_empty() {
        rows.push(style(title).bold().to_string());
    }
    for l in lines {
        rows.extend(fit(l, inner));
    }
    panel(&rows, None);
}

/// Backwards-compatible plain panel.
pub fn boxed(lines: &[String]) {
    card("", lines);
}

/// Shaded panel with a coloured left bar, for things the user must not miss.
pub fn callout(tone: Tone, title: &str, lines: &[String]) {
    let inner = width().saturating_sub(4);
    let mut rows: Vec<String> = vec![tone.style().bold().apply_to(title).to_string()];
    for l in lines {
        rows.extend(fit(l, inner));
    }
    panel(&rows, Some(tone));
}

// ───────────────────────────── input ─────────────────────────────

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

/// Menu with a question above it.
pub fn menu_titled(prompt: &str, items: &[&str]) -> Result<usize, String> {
    Select::with_theme(&theme())
        .with_prompt(prompt)
        .items(items)
        .default(0)
        .interact()
        .map_err(|e| e.to_string())
}

/// Yes/no question. Cancelling counts as "no".
pub fn confirm(prompt: &str, default: bool) -> bool {
    Confirm::with_theme(&theme())
        .with_prompt(prompt)
        .default(default)
        .interact()
        .unwrap_or(false)
}

/// Single-line text prompt.
pub fn ask(prompt: &str) -> Result<String, String> {
    Input::<String>::with_theme(&theme())
        .with_prompt(prompt)
        .interact_text()
        .map_err(|e| e.to_string())
}

// ───────────────────────────── progress ─────────────────────────────

struct StopOnDrop<'a>(&'a AtomicBool);

impl Drop for StopOnDrop<'_> {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Relaxed);
    }
}

/// Whether stdout is a real terminal, so the screen can be animated and filled
/// in as work happens instead of only when it finishes.
pub fn interactive() -> bool {
    Term::stdout().is_term()
}

/// Run `f` while a spinner shows. No animation when stdout isn't a terminal,
/// and a panic in `f` can't leave the spinner thread running.
pub fn spin<T>(msg: &str, f: impl FnOnce() -> T) -> T {
    if !interactive() {
        return f();
    }
    let done = AtomicBool::new(false);
    std::thread::scope(|s| {
        let handle = s.spawn(|| {
            let frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
            let term = Term::stdout();
            let _ = term.hide_cursor();
            let mut i = 0usize;
            while !done.load(Ordering::Relaxed) {
                let _ = term.write_str(&format!(
                    "\r{MARGIN}{} {}",
                    style(frames[i % frames.len()]).cyan(),
                    style(msg).dim()
                ));
                i += 1;
                std::thread::sleep(Duration::from_millis(80));
            }
            let _ = term.write_str("\r");
            let _ = term.clear_line();
            let _ = term.show_cursor();
        });
        let _guard = StopOnDrop(&done);
        let result = f();
        done.store(true, Ordering::Relaxed);
        let _ = handle.join();
        result
    })
}

// ───────────────────────────── secrets ─────────────────────────────

/// Leaves the alternate screen (and wipes it) when dropped, even on panic.
struct AltScreen;

impl AltScreen {
    fn enter() -> Self {
        print!("\x1b[?1049h\x1b[2J\x1b[H");
        let _ = std::io::stdout().flush();
        AltScreen
    }
}

impl Drop for AltScreen {
    fn drop(&mut self) {
        print!("\x1b[2J\x1b[?1049l");
        let _ = std::io::stdout().flush();
    }
}

/// Show something secret on the alternate screen so it never enters the
/// scrollback, and wipe it afterwards.
pub fn secret_screen(f: impl FnOnce()) {
    let _screen = AltScreen::enter();
    f();
}

// ───────────────────────────── formatting ─────────────────────────────

pub fn fmt_btc(sats: i64) -> String {
    let sign = if sats < 0 { "-" } else { "" };
    let a = sats.unsigned_abs();
    format!("{sign}{}.{:08}", a / 100_000_000, a % 100_000_000)
}

/// `1 234 567`: thin-space grouping, easier to scan.
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

/// `bc1qxy2kgd...x0wlh`. Counts characters, not bytes, so it can't panic on
/// multi-byte text.
pub fn short(s: &str) -> String {
    let n = s.chars().count();
    if n <= 20 {
        return s.to_string();
    }
    let head: String = s.chars().take(10).collect();
    let tail: String = s.chars().skip(n - 6).collect();
    format!("{head}…{tail}")
}

// ───────────────────────────── logo ─────────────────────────────

/// Big block-letter wordmark, centred. Show it once (startup or wallet
/// picker) and keep `banner()` for every other screen.
pub fn logo() {
    const C: [&str; 5] = [" █████", "██    ", "██    ", "██    ", " █████"];
    const A: [&str; 5] = [" ████ ", "██  ██", "██████", "██  ██", "██  ██"];
    const I: [&str; 5] = ["████", " ██ ", " ██ ", " ██ ", "████"];
    const R: [&str; 5] = ["█████ ", "██  ██", "█████ ", "██ ██ ", "██  ██"];
    const N: [&str; 5] = ["██  ██", "███ ██", "██████", "██ ███", "██  ██"];
    let w = width();
    println!();
    for row in 0..5 {
        let line = [C[row], A[row], I[row], R[row], N[row]].join("  ");
        println!(
            "{MARGIN}{}",
            center(&style(line).cyan().bold().to_string(), w)
        );
    }
    println!();
    println!(
        "{MARGIN}{}",
        center(&style("Bitcoin wallet").dim().to_string(), w)
    );
    println!();
}
