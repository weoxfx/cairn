#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let frames: Vec<String> = text.lines().map(str::to_owned).collect();
    if let Ok(bytes) = cairn::qr::reassemble(&frames) {
        let encoded = cairn::qr::encode_frames(&bytes)
            .expect("reassembled data must fit the QR frame limits");
        let decoded = cairn::qr::reassemble(&encoded).expect("cairn's own frames must reassemble");
        assert_eq!(decoded, bytes);
    }
});
