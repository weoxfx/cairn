//! The shipped binary.
//!
//! Everything the wallet does lives in the library (`cairn::cli` and the modules
//! it drives), so the binary is only an entry point. Building it compiles the
//! same modules once; the fuzz targets and `tests/` see the same code.

fn main() {
    cairn::cli::main();
}
