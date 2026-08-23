use pyo3::exceptions::PyIOError;
use pyo3::prelude::*;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::Read;

/// Stream a file through SHA-256 without loading it fully into memory.
#[pyfunction]
fn stream_sha256(path: &str) -> PyResult<String> {
    let mut file = File::open(path).map_err(|e| PyIOError::new_err(e.to_string()))?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 1024 * 1024];
    loop {
        let n = file
            .read(&mut buf)
            .map_err(|e| PyIOError::new_err(e.to_string()))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

#[pymodule]
fn _defentra_core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(stream_sha256, m)?)?;
    Ok(())
}
