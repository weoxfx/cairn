//! QR transport for offline PSBT exchange.
//!
//! A PSBT is split into small ASCII frames so each one fits a terminal-sized
//! QR code. Every frame carries a version, the frame count, its index and a
//! short SHA-256 checksum. The scanner accepts photos or screenshots and
//! reassembles frames in any order.
//!
//! This is transport, not encryption: QR contents are public data (an unsigned
//! or signed PSBT). The checksum detects corruption, while the normal wallet
//! verification protects against a malicious PSBT.

use bitcoin::hashes::{sha256, Hash};
use console::Term;
use image::GrayImage;
use qrcode::{render::unicode, QrCode};
use rqrr::PreparedImage;
use std::io::{IsTerminal, Write};
use std::time::Duration;

const PREFIX: &str = "CAIRN1";
const CHUNK_BYTES: usize = 200;
const MIN_CHUNK_BYTES: usize = 12;
const MAX_FRAMES: usize = 256;
const CHECKSUM_BYTES: usize = 8;
const FRAME_MILLIS: u64 = 1500;
const CYCLES: usize = 6;
const TARGET_CYCLE_MILLIS: u64 = 18_000;
const CHROME_ROWS: usize = 3;
const CHROME_COLS: usize = 2;

/// Split a PSBT into QR-sized text frames.
pub fn encode_frames(data: &[u8]) -> Result<Vec<String>, String> {
    encode_frames_with(data, CHUNK_BYTES)
}

fn encode_frames_with(data: &[u8], chunk_bytes: usize) -> Result<Vec<String>, String> {
    if data.is_empty() {
        return Err("nothing to encode".into());
    }
    let chunk_bytes = chunk_bytes.clamp(1, CHUNK_BYTES);
    let total = data.len().div_ceil(chunk_bytes);
    if total > MAX_FRAMES {
        return Err(format!(
            "PSBT is too large for QR transfer ({total} frames, max {MAX_FRAMES})"
        ));
    }
    let sum = checksum(data);
    Ok(data
        .chunks(chunk_bytes)
        .enumerate()
        .map(|(i, chunk)| format!("{PREFIX}:{total}:{i}:{sum}:{}", hex::encode_upper(chunk)))
        .collect())
}

/// Rebuild a PSBT from scanned frames, in any order and with duplicates.
pub fn reassemble(payloads: &[String]) -> Result<Vec<u8>, String> {
    if payloads.is_empty() {
        return Err("no QR frames were found".into());
    }
    let mut total: Option<usize> = None;
    let mut sum: Option<String> = None;
    let mut chunks: Vec<Option<Vec<u8>>> = Vec::new();

    for payload in payloads {
        let frame = parse_frame(payload)?;
        match total {
            None => {
                total = Some(frame.total);
                chunks.resize(frame.total, None);
            }
            Some(t) if t != frame.total => {
                return Err("QR frames disagree on the frame count".into());
            }
            Some(_) => {}
        }
        match &sum {
            None => sum = Some(frame.checksum),
            Some(s) if s != &frame.checksum => {
                return Err("QR frames belong to different PSBTs (checksum mismatch)".into());
            }
            Some(_) => {}
        }
        if let Some(prev) = &chunks[frame.index] {
            if prev != &frame.bytes {
                return Err(format!(
                    "QR frame {} appears twice with different data",
                    frame.index + 1
                ));
            }
        } else {
            chunks[frame.index] = Some(frame.bytes);
        }
    }

    let total = total.ok_or("no QR frames were found")?;
    let sum = sum.ok_or("no QR frames were found")?;
    let mut data = Vec::new();
    for (i, chunk) in chunks.iter().enumerate() {
        let chunk = chunk
            .as_ref()
            .ok_or_else(|| format!("missing QR frame {} of {total}", i + 1))?;
        data.extend_from_slice(chunk);
    }
    if checksum(&data) != sum {
        return Err("QR frames are corrupt (checksum mismatch)".into());
    }
    Ok(data)
}

struct Frame {
    total: usize,
    index: usize,
    checksum: String,
    bytes: Vec<u8>,
}

fn parse_frame(payload: &str) -> Result<Frame, String> {
    let payload = payload.trim();
    let mut parts = payload.splitn(5, ':');
    let prefix = parts.next().unwrap_or_default();
    if prefix != PREFIX {
        return Err("not a Cairn QR frame".into());
    }
    let total = parts
        .next()
        .ok_or("malformed QR frame: missing frame count")?
        .parse::<usize>()
        .map_err(|_| "malformed QR frame: bad frame count")?;
    if total == 0 || total > MAX_FRAMES {
        return Err(format!("malformed QR frame: invalid frame count {total}"));
    }
    let index = parts
        .next()
        .ok_or("malformed QR frame: missing frame index")?
        .parse::<usize>()
        .map_err(|_| "malformed QR frame: bad frame index")?;
    if index >= total {
        return Err("malformed QR frame: index out of range".into());
    }
    let checksum = parts
        .next()
        .ok_or("malformed QR frame: missing checksum")?
        .to_ascii_uppercase();
    if checksum.len() != CHECKSUM_BYTES * 2 || hex::decode(&checksum).is_err() {
        return Err("malformed QR frame: bad checksum".into());
    }
    let chunk = parts
        .next()
        .ok_or("malformed QR frame: missing data")?
        .trim();
    if chunk.is_empty() || chunk.len() > CHUNK_BYTES * 2 {
        return Err("malformed QR frame: bad data length".into());
    }
    let bytes = hex::decode(chunk).map_err(|_| "malformed QR frame: bad hex data")?;
    Ok(Frame {
        total,
        index,
        checksum,
        bytes,
    })
}

fn checksum(data: &[u8]) -> String {
    let hash = sha256::Hash::hash(data).to_byte_array();
    hex::encode_upper(&hash[..CHECKSUM_BYTES])
}

/// Render one frame as terminal art, without the surrounding chrome.
fn render(payload: &str) -> Result<String, String> {
    let code = QrCode::new(payload.as_bytes()).map_err(|e| e.to_string())?;
    Ok(code
        .render::<unicode::Dense1x2>()
        .dark_color(unicode::Dense1x2::Light)
        .light_color(unicode::Dense1x2::Dark)
        .quiet_zone(true)
        .build())
}

fn art_dimensions(art: &str) -> (usize, usize) {
    let mut width = 0;
    let mut height = 0;
    for line in art.lines() {
        width = width.max(line.chars().count());
        height += 1;
    }
    (width, height)
}

/// Largest chunk whose QR art fits the current terminal. Smaller terminals
/// need more, smaller frames; larger ones get the fewest possible frames.
fn chunk_for_terminal(data: &[u8], cols: usize, rows: usize) -> Result<usize, String> {
    let max_width = cols.saturating_sub(CHROME_COLS).max(1);
    let max_height = rows.saturating_sub(CHROME_ROWS).max(1);

    for chunk in (MIN_CHUNK_BYTES..=CHUNK_BYTES).rev().step_by(4) {
        let frames = encode_frames_with(data, chunk)?;
        let fits = frames.iter().all(|frame| {
            render(frame).is_ok_and(|art| {
                let (width, height) = art_dimensions(&art);
                width <= max_width && height <= max_height
            })
        });
        if fits {
            return Ok(chunk);
        }
    }

    let frames = encode_frames_with(data, MIN_CHUNK_BYTES)?;
    let (width, height) = frames
        .iter()
        .filter_map(|frame| render(frame).ok())
        .map(|art| art_dimensions(&art))
        .fold((0, 0), |(w, h), (fw, fh)| (w.max(fw), h.max(fh)));
    Err(format!(
        "this terminal is too small ({cols}x{rows}). Make it at least {}x{}, \
         or redirect `--qr-show` to a file and print the frames some other way",
        width + CHROME_COLS,
        height + CHROME_ROWS
    ))
}

/// Show every QR frame. Returns the number of frames displayed.
pub fn show(data: &[u8]) -> Result<usize, String> {
    let is_terminal = std::io::stdout().is_terminal();
    let frames = if is_terminal {
        // `console` reports (rows, columns).
        let (rows, cols) = Term::stdout().size_checked().unwrap_or((40, 80));
        let chunk = chunk_for_terminal(data, cols.into(), rows.into())?;
        encode_frames_with(data, chunk)?
    } else {
        encode_frames(data)?
    };
    let art: Vec<String> = frames
        .iter()
        .map(|frame| render(frame))
        .collect::<Result<_, _>>()?;

    if !is_terminal {
        for (i, image) in art.iter().enumerate() {
            println!("--- Cairn QR frame {}/{} ---", i + 1, art.len());
            println!("{image}");
        }
        return Ok(art.len());
    }

    if art.len() == 1 {
        crate::ui::clear();
        println!("Cairn PSBT QR");
        println!("{}", art[0]);
        return Ok(1);
    }

    let cycle_millis = FRAME_MILLIS * art.len() as u64;
    let cycles = (TARGET_CYCLE_MILLIS / cycle_millis).clamp(1, CYCLES as u64) as usize;
    for _ in 0..cycles {
        for (i, image) in art.iter().enumerate() {
            crate::ui::clear();
            println!(
                "Cairn PSBT QR — frame {}/{} — keep this window fully visible",
                i + 1,
                art.len()
            );
            println!("{image}");
            let _ = std::io::stdout().flush();
            std::thread::sleep(Duration::from_millis(FRAME_MILLIS));
        }
    }
    println!();
    Ok(art.len())
}

/// Read every QR code found in the given image files.
pub fn scan_images(paths: &[String]) -> Result<Vec<String>, String> {
    let mut payloads = Vec::new();
    for path in paths {
        let mut reader =
            image::ImageReader::open(path).map_err(|e| format!("cannot read image {path}: {e}"))?;
        let mut limits = image::Limits::default();
        limits.max_image_width = Some(8_000);
        limits.max_image_height = Some(8_000);
        reader.limits(limits);
        let img = reader
            .with_guessed_format()
            .map_err(|e| format!("cannot read image {path}: {e}"))?
            .decode()
            .map_err(|e| format!("cannot decode image {path}: {e}"))?
            .to_luma8();
        let found = decode_image(&img);
        if found.is_empty() {
            return Err(format!("no readable QR code found in {path}"));
        }
        payloads.extend(found);
    }
    Ok(payloads)
}

/// Try the image as-is, then inverted (terminals often show light-on-dark).
fn decode_image(img: &GrayImage) -> Vec<String> {
    let found = decode_luma(img, false);
    if found.is_empty() {
        decode_luma(img, true)
    } else {
        found
    }
}

fn decode_luma(img: &GrayImage, invert: bool) -> Vec<String> {
    let width = img.width() as usize;
    let height = img.height() as usize;
    let raw = img.as_raw();
    let mut prepared = PreparedImage::prepare_from_greyscale(width, height, |x, y| {
        let v = raw[y * width + x];
        if invert {
            255 - v
        } else {
            v
        }
    });
    prepared
        .detect_grids()
        .iter()
        .filter_map(|grid| grid.decode().ok().map(|(_, text)| text))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use image::Luma;

    fn bytes(n: usize) -> Vec<u8> {
        (0..n).map(|i| (i % 251) as u8).collect()
    }

    fn payload_image(payload: &str, invert: bool) -> GrayImage {
        let code = QrCode::new(payload.as_bytes()).unwrap();
        let modules = code.width() as u32;
        let colors = code.to_colors();
        let scale = 8u32;
        let quiet = 4 * scale;
        let size = modules * scale + 2 * quiet;
        let mut img = GrayImage::from_pixel(size, size, Luma([255]));
        for y in 0..modules {
            for x in 0..modules {
                if colors[(y * modules + x) as usize] == qrcode::Color::Dark {
                    for dy in 0..scale {
                        for dx in 0..scale {
                            let px = quiet + x * scale + dx;
                            let py = quiet + y * scale + dy;
                            img.put_pixel(px, py, Luma([0]));
                        }
                    }
                }
            }
        }
        if invert {
            for p in img.pixels_mut() {
                p.0[0] = 255 - p.0[0];
            }
        }
        img
    }

    #[test]
    fn frames_roundtrip_in_any_order_and_with_duplicates() {
        let data = bytes(701);
        let frames = encode_frames(&data).unwrap();
        assert_eq!(frames.len(), 4);

        let mut shuffled = frames.clone();
        shuffled.reverse();
        shuffled.push(frames[1].clone());
        assert_eq!(reassemble(&shuffled).unwrap(), data);
    }

    #[test]
    fn rejects_missing_corrupt_and_malformed_frames() {
        let data = bytes(701);
        let frames = encode_frames(&data).unwrap();

        assert!(reassemble(&frames[1..]).unwrap_err().contains("missing"));
        assert!(reassemble(&[]).is_err());
        assert!(reassemble(&["NOPE".into()]).is_err());

        let mut corrupt = frames.clone();
        let last = corrupt[0].pop().unwrap();
        corrupt[0].push(if last == '0' { '1' } else { '0' });
        assert!(reassemble(&corrupt).unwrap_err().contains("corrupt"));

        let mut mixed = frames.clone();
        let other = encode_frames(&bytes(702)).unwrap();
        mixed[0] = other[0].clone();
        assert!(reassemble(&mixed).is_err());
    }

    #[test]
    fn renders_and_decodes_qr_images() {
        let data = bytes(701);
        let frames = encode_frames(&data).unwrap();
        for frame in &frames {
            let width = QrCode::new(frame.as_bytes()).unwrap().width();
            assert!(
                width <= 69,
                "QR frame is too wide for an 80-column terminal: {width} modules"
            );
            assert_eq!(
                decode_image(&payload_image(frame, false)),
                vec![frame.clone()]
            );
            assert_eq!(
                decode_image(&payload_image(frame, true)),
                vec![frame.clone()]
            );
        }
    }

    #[test]
    fn frames_shrink_to_fit_a_short_terminal() {
        let data = bytes(701);
        let chunk = chunk_for_terminal(&data, 80, 24).unwrap();
        assert!(chunk < CHUNK_BYTES);
        let frames = encode_frames_with(&data, chunk).unwrap();
        for frame in &frames {
            let (width, height) = art_dimensions(&render(frame).unwrap());
            assert!(width <= 78, "QR art is {width} columns wide");
            assert!(height <= 21, "QR art is {height} rows tall");
        }
        assert_eq!(reassemble(&frames).unwrap(), data);
        assert!(chunk_for_terminal(&data, 80, 10).is_err());
    }

    #[test]
    fn scans_png_files() {
        let frame = encode_frames(b"cairn").unwrap().remove(0);
        let dir = std::env::temp_dir().join(format!("cairn-qr-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        // The extension is deliberately wrong: format should come from the bytes.
        let path = dir.join("frame.dat");
        payload_image(&frame, false)
            .save_with_format(&path, image::ImageFormat::Png)
            .unwrap();

        let found = scan_images(&[path.to_string_lossy().into_owned()]).unwrap();
        assert_eq!(found, vec![frame]);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
