from __future__ import annotations

import hashlib
import os

from aegorx.scanner.hashes import file_hashes

EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


def test_eicar_known_hashes(eicar_file):
    h = file_hashes(eicar_file)
    assert h["md5"] == "44d88612fea8a8f36de82e1278abb02f"
    assert h["sha1"] == "3395856ce81f2b7382dee72602f798b642f14140"
    assert (
        h["sha256"]
        == "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
    )


def test_large_file_streaming(tmp_path):
    p = tmp_path / "big.bin"
    data = os.urandom(3 * 1024 * 1024 + 17)
    p.write_bytes(data)
    h = file_hashes(str(p))
    assert h["sha256"] == hashlib.sha256(data).hexdigest()
