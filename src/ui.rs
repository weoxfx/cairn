//! Terminal UI helpers: theme, banner, spinner, boxes, secret screen.

use console::{measure_text_width, style, Term};
use dialoguer::{theme::ColorfulTheme, Input, Select};
use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

pub fn theme() -> ColorfulTheme {
    ColorfulTheme::default()
}

pub fn clear() {
    let _ = Term::stdout().clear_screen();
    print!("\x1b[3J");
}

pub fn banner() {
    clear();
    println!(
        "{}  {}",
        style("◆ CAIRN").cyan().bold(),
        style(" TESTNET ").black().on_yellow()
    );
    println!("{}\n", style("experimental · unaudited · no real funds").dim());
}

pub fn ok(msg: &str) {
    println!("{} {}", style("✔").green().bold(), msg);
}

pub fn fail(msg: &str) {
    println!("{} {}", style("✘").red().bold(), style(msg).red());
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
                let _ = term.write_str(&format!("\r{} {}", style(frames[i % frames.len()]).cyan(), style(msg).dim()));
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

/// Rounded box around lines (ANSI-aware width).
pub fn boxed(lines: &[String]) {
    let w = lines.iter().map(|l| measure_text_width(l)).max().unwrap_or(0).max(30);
    println!("╭{}╮", "─".repeat(w + 2));
    for l in lines {
        println!("│ {}{} │", l, " ".repeat(w - measure_text_width(l)));
    }
    println!("╰{}╯", "─".repeat(w + 2));
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

