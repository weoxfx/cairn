//! BIP329 transaction labels.
//!
//! Labels are stored as JSON Lines at `~/.cairn/labels.jsonl` using the BIP329
//! shape `{"type":"tx","ref":"<txid>","label":"..."}`. The file is written with
//! the same private, atomic helper as the wallet config, and labels are bounded
//! and stripped of terminal control characters before they can be displayed.

use crate::error::Result;

use crate::hardening;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

const MAX_LABEL_CHARS: usize = 200;
const MAX_LABEL_FILE: u64 = 1_000_000;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
struct Entry {
    #[serde(rename = "type")]
    kind: String,
    #[serde(rename = "ref")]
    reference: String,
    label: String,
}

pub struct Labels {
    entries: Vec<Entry>,
}

fn path() -> Result<PathBuf> {
    let home = std::env::var("HOME").map_err(|_| "HOME not set".to_string())?;
    let base = PathBuf::from(home).join(".cairn");
    hardening::ensure_private_dir(&base)?;
    Ok(base.join("labels.jsonl"))
}

pub fn valid_txid(txid: &str) -> bool {
    txid.len() == 64 && txid.bytes().all(|b| b.is_ascii_hexdigit())
}

fn clean_label(label: &str) -> Result<String> {
    let cleaned: String = label
        .chars()
        .filter(|c| !c.is_control())
        .take(MAX_LABEL_CHARS)
        .collect();
    let cleaned = cleaned.trim().to_string();
    if cleaned.is_empty() {
        return Err("Label cannot be empty".into());
    }
    Ok(cleaned)
}

impl Labels {
    pub fn empty() -> Self {
        Labels { entries: vec![] }
    }

    pub fn load() -> Result<Self> {
        let p = path()?;
        let data = match fs::read(&p) {
            Ok(d) => d,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Labels { entries: vec![] })
            }
            Err(e) => return Err(format!("cannot read labels: {e}").into()),
        };
        if data.len() as u64 > MAX_LABEL_FILE {
            return Err("labels file is unexpectedly large".into());
        }
        let text = String::from_utf8(data).map_err(|_| "labels file is not UTF-8".to_string())?;
        let mut entries = vec![];
        for line in text.lines() {
            if line.trim().is_empty() {
                continue;
            }
            let Ok(entry) = serde_json::from_str::<Entry>(line) else {
                continue; // ignore unknown or malformed BIP329 records
            };
            if entry.kind == "tx" && valid_txid(&entry.reference) {
                entries.push(entry);
            }
        }
        Ok(Labels { entries })
    }

    pub fn get(&self, txid: &str) -> Option<&str> {
        self.entries
            .iter()
            .rev()
            .find(|e| e.reference.eq_ignore_ascii_case(txid))
            .map(|e| e.label.as_str())
    }

    pub fn set(&mut self, txid: &str, label: &str) -> Result<()> {
        if !valid_txid(txid) {
            return Err("Not a valid transaction id".into());
        }
        let label = clean_label(label)?;
        self.entries
            .retain(|e| !e.reference.eq_ignore_ascii_case(txid));
        self.entries.push(Entry {
            kind: "tx".into(),
            reference: txid.to_ascii_lowercase(),
            label,
        });
        self.save()
    }

    pub fn remove(&mut self, txid: &str) -> Result<()> {
        self.entries
            .retain(|e| !e.reference.eq_ignore_ascii_case(txid));
        self.save()
    }

    fn save(&self) -> Result<()> {
        let mut out = String::new();
        for entry in &self.entries {
            out.push_str(&serde_json::to_string(entry).map_err(|e| e.to_string())?);
            out.push('\n');
        }
        hardening::write_private(&path()?, out.as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_home(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "cairn-labels-{}-{tag}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::env::set_var("HOME", &dir);
        dir
    }

    #[test]
    fn bip329_roundtrip_and_bounds() {
        let dir = temp_home("roundtrip");
        let txid = "ab".repeat(32);
        let mut labels = Labels::load().unwrap();
        assert!(labels.get(&txid).is_none());

        labels.set(&txid, "Rent payment").unwrap();
        assert_eq!(labels.get(&txid), Some("Rent payment"));

        // Re-labelling replaces the old record instead of duplicating it.
        labels.set(&txid, "Rent 2026").unwrap();
        let again = Labels::load().unwrap();
        assert_eq!(again.get(&txid), Some("Rent 2026"));

        // Control characters never reach the screen.
        let other = "cd".repeat(32);
        labels.set(&other, "bad\u{1b}[31m\nlabel").unwrap();
        assert_eq!(labels.get(&other), Some("bad[31mlabel"));

        assert!(labels.set("not-a-txid", "x").is_err());
        assert!(labels.set(&txid, "   ").is_err());

        labels.remove(&txid).unwrap();
        assert!(Labels::load().unwrap().get(&txid).is_none());

        let _ = fs::remove_dir_all(&dir);
    }
}
