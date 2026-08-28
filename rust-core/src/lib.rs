//! Performance-critical primitives for the AegorX antivirus engine.
//!
//! The hashing core is dependency-light and testable without Python; the
//! pyo3 bindings are opt-in via the `extension-module` feature so that
//! plain `cargo test` links without libpython.

use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::Read;

/// Stream a file through SHA-256 without loading it fully into memory.
// Dead from the linker's view when built as a bare lib (no feature, no
// tests); reachable via the pyo3 wrapper or the test module.
#[cfg_attr(not(any(test, feature = "extension-module")), allow(dead_code))]
fn stream_sha256_inner(path: &str) -> Result<String, String> {
    let mut file = File::open(path).map_err(|e| e.to_string())?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 1024 * 1024];
    loop {
        let n = file.read(&mut buf).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

#[cfg(feature = "extension-module")]
mod python_bindings {
    use super::stream_sha256_inner;
    use pyo3::exceptions::PyIOError;
    use pyo3::prelude::*;

    /// Stream a file through SHA-256 without loading it fully into memory.
    #[pyfunction]
    pub fn stream_sha256(path: &str) -> PyResult<String> {
        stream_sha256_inner(path).map_err(PyIOError::new_err)
    }

    #[pymodule]
    fn _aegorx_core(m: &Bound<'_, PyModule>) -> PyResult<()> {
        m.add_function(wrap_pyfunction!(stream_sha256, m)?)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::stream_sha256_inner as stream_sha256;
    use std::fs::File;
    use std::io::Write;
    use std::path::PathBuf;

    const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    // NIST vector: sha256 of 1,000,000 'a' bytes (forces multi-chunk reads)
    const MILLION_A_SHA256: &str =
        "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0";

    fn temp_file(name: &str, size: usize, byte: u8) -> PathBuf {
        let path = std::env::temp_dir().join(name);
        let mut f = File::create(&path).expect("create temp file");
        let block = vec![byte; 8192];
        let mut written = 0;
        while written < size {
            let n = std::cmp::min(block.len(), size - written);
            f.write_all(&block[..n]).expect("write temp file");
            written += n;
        }
        path
    }

    #[test]
    fn empty_file_hashes_to_known_vector() {
        let path = temp_file("aegorx_core_empty", 0, b'a');
        assert_eq!(
            stream_sha256(path.to_str().unwrap()),
            Ok(EMPTY_SHA256.to_string())
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn million_a_hashes_to_known_vector() {
        let path = temp_file("aegorx_core_million_a", 1_000_000, b'a');
        assert_eq!(
            stream_sha256(path.to_str().unwrap()),
            Ok(MILLION_A_SHA256.to_string())
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn missing_file_is_an_error() {
        assert!(stream_sha256("/definitely/not/here").is_err());
    }
}
