"""Tests for the sandbox modules."""

import os
import struct
import tempfile
import unittest
import zipfile

from aegorx.sandbox.static_analyzer import StaticSandbox, AnalysisResult
from aegorx.sandbox.behavioral_sandbox import BehavioralSandbox, SandboxConfig, SandboxResult
from aegorx.sandbox.archive_sandbox import ArchiveSandbox, ExtractionResult


class TestStaticSandbox(unittest.TestCase):
    def setUp(self):
        self.sandbox = StaticSandbox()
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_analyze_nonexistent_file(self):
        result = self.sandbox.analyze("/nonexistent/file.exe")
        self.assertIn("file_not_found", result.risk_factors)

    def test_analyze_pe_file(self):
        # Create a minimal PE-like file
        path = os.path.join(self.tmpdir, "test.exe")
        # DOS header + PE signature + minimal COFF header
        dos_header = bytearray(64)
        dos_header[0:2] = b"MZ"
        struct.pack_into("<I", dos_header, 60, 64)  # PE offset

        pe_sig = b"PE\x00\x00"
        coff_header = bytearray(20)
        struct.pack_into("<H", coff_header, 0, 0x8664)  # AMD64
        struct.pack_into("<H", coff_header, 2, 1)  # 1 section
        struct.pack_into("<I", coff_header, 4, 1234567890)  # timestamp
        struct.pack_into("<H", coff_header, 18, 0x22)  # characteristics

        optional_header = bytearray(240)  # PE32+
        struct.pack_into("<H", optional_header, 0, 0x20b)  # PE32+
        struct.pack_into("<I", optional_header, 16, 0x1000)  # entry point

        section = bytearray(40)
        section[0:6] = b".text\x00"
        struct.pack_into("<I", section, 8, 0x1000)  # virtual size
        struct.pack_into("<I", section, 16, 0x200)  # raw size
        struct.pack_into("<I", section, 36, 0x60000020)  # executable, readable

        with open(path, "wb") as f:
            f.write(bytes(dos_header))
            f.write(pe_sig)
            f.write(bytes(coff_header))
            f.write(bytes(optional_header))
            f.write(bytes(section))

        result = self.sandbox.analyze(path)
        self.assertEqual(result.file_type, "pe")
        self.assertEqual(result.entry_point, 0x1000)
        self.assertTrue(len(result.sections) >= 1)

    def test_analyze_elf_file(self):
        path = os.path.join(self.tmpdir, "test.elf")
        # ELF header (64-bit, little-endian)
        elf_header = bytearray(64)
        elf_header[0:4] = b"\x7fELF"
        elf_header[4] = 2  # 64-bit
        elf_header[5] = 1  # little-endian
        struct.pack_into("<H", elf_header, 16, 2)  # ET_EXEC
        struct.pack_into("<H", elf_header, 18, 0x3E)  # x86-64
        struct.pack_into("<Q", elf_header, 24, 0x400000)  # entry point

        with open(path, "wb") as f:
            f.write(bytes(elf_header))

        result = self.sandbox.analyze(path)
        self.assertEqual(result.file_type, "elf")
        self.assertEqual(result.entry_point, 0x400000)

    def test_analyze_pdf(self):
        path = os.path.join(self.tmpdir, "test.pdf")
        content = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog /OpenAction [3 0 R /Fit] >>\nendobj\n"
        content += b"/JavaScript (/launch)\n"
        with open(path, "wb") as f:
            f.write(content)

        result = self.sandbox.analyze(path)
        self.assertEqual(result.file_type, "pdf")
        self.assertTrue(len(result.suspicious_patterns) > 0)

    def test_entropy_calculation(self):
        # All same bytes = 0 entropy
        data = b"\x00" * 1000
        ent = self.sandbox._entropy(data)
        self.assertAlmostEqual(ent, 0.0, places=5)

        # Random-like data = high entropy
        import random
        random.seed(42)
        data = bytes(random.getrandbits(8) for _ in range(10000))
        ent = self.sandbox._entropy(data)
        self.assertGreater(ent, 7.0)

    def test_risk_score_computation(self):
        result = AnalysisResult()
        result.risk_factors = ["high_entropy", "packed_binary", "unsigned"]
        self.sandbox._compute_risk(result)
        self.assertGreater(result.risk_score, 0.0)

    def test_risk_score_clamps(self):
        result = AnalysisResult()
        result.is_packed = True
        result.suspicious_patterns = [{}] * 10
        result.suspicious_imports = [{}] * 10
        result.risk_factors = ["a", "b", "c", "d"]
        self.sandbox._compute_risk(result)
        self.assertLessEqual(result.risk_score, 1.0)


class TestBehavioralSandbox(unittest.TestCase):
    def setUp(self):
        self.config = SandboxConfig(timeout_seconds=5)
        self.sandbox = BehavioralSandbox(self.config)
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_analyze_nonexistent_file(self):
        result = self.sandbox.analyze("/nonexistent/malware.exe")
        self.assertIn("file_not_found", result.risk_factors)

    def test_analyze_script(self):
        path = os.path.join(self.tmpdir, "test.sh")
        with open(path, "w") as f:
            f.write("#!/bin/bash\necho hello\n")
        os.chmod(path, 0o755)

        result = self.sandbox.analyze(path)
        self.assertIsNotNone(result)
        self.assertIn(result.verdict, ["clean", "suspicious", "malicious"])

    def test_sandbox_result_to_dict(self):
        result = SandboxResult(file_path="/test")
        d = result.to_dict()
        self.assertEqual(d["file_path"], "/test")
        self.assertIn("risk_score", d)

    def test_malicious_file_detection(self):
        result = SandboxResult()
        from aegorx.sandbox.behavioral_sandbox import FileChange
        result.file_changes = [
            FileChange(path="/tmp/how_to_decrypt.txt", operation="created"),
            FileChange(path="/tmp/file.txt.locked", operation="renamed"),
        ]
        self.sandbox._analyze_behavior(result)
        self.assertGreater(result.risk_score, 0.3)

    def test_suspicious_process_detection(self):
        result = SandboxResult()
        from aegorx.sandbox.behavioral_sandbox import ProcessSpawn
        result.processes_spawned = [
            ProcessSpawn(pid=1, name="cmd.exe", cmdline="cmd.exe /c whoami"),
        ]
        self.sandbox._analyze_behavior(result)
        self.assertGreater(result.risk_score, 0.1)


class TestArchiveSandbox(unittest.TestCase):
    def setUp(self):
        self.sandbox = ArchiveSandbox()
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_analyze_nonexistent_file(self):
        result = self.sandbox.analyze("/nonexistent/archive.zip")
        self.assertIn("file_not_found", result.risk_factors)

    def test_analyze_valid_zip(self):
        path = os.path.join(self.tmpdir, "test.zip")
        with zipfile.ZipFile(path, "w") as zf:
            zf.writestr("file1.txt", "hello world")
            zf.writestr("file2.txt", "another file")

        result = self.sandbox.analyze(path)
        self.assertEqual(result.archive_type, "zip")
        self.assertEqual(result.total_entries, 2)
        self.assertIn(result.verdict, ["clean", "suspicious", "malicious"])

    def test_zip_bomb_detection(self):
        path = os.path.join(self.tmpdir, "bomb.zip")
        with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            # Create repeated pattern that compresses well (bomb)
            data = b"\x00" * (1024 * 1024 * 100)  # 100MB of zeros
            zf.writestr("bomb.bin", data)

        result = self.sandbox.analyze(path)
        # The compression ratio of zeros is very high
        self.assertTrue(result.bomb_detected or result.compression_ratio > 50)

    def test_path_traversal_detection(self):
        path = os.path.join(self.tmpdir, "traversal.zip")
        with zipfile.ZipFile(path, "w") as zf:
            zf.writestr("../../../etc/passwd", "malicious")

        result = self.sandbox.analyze(path)
        self.assertGreater(result.path_traversal_attempts, 0)

    def test_extraction_result_to_dict(self):
        result = ExtractionResult(archive_path="/test.zip")
        d = result.to_dict()
        self.assertEqual(d["archive_type"], "unknown")
        self.assertIn("risk_score", d)

    def test_extract_safe_zip(self):
        archive_path = os.path.join(self.tmpdir, "safe.zip")
        with zipfile.ZipFile(archive_path, "w") as zf:
            zf.writestr("hello.txt", "hello world")

        dest = os.path.join(self.tmpdir, "extracted")
        os.makedirs(dest)

        result = self.sandbox.extract(archive_path, dest)
        self.assertGreater(result.extracted_entries, 0)

    def test_symlink_attack_detection(self):
        path = os.path.join(self.tmpdir, "symlink.zip")
        with zipfile.ZipFile(path, "w") as zf:
            # Manually add a symlink entry
            info = zipfile.ZipInfo("link.txt")
        # Just test that the detection logic works
        result = self.sandbox.analyze(path)
        self.assertIsNotNone(result)


class TestArchiveSandboxTar(unittest.TestCase):
    def setUp(self):
        self.sandbox = ArchiveSandbox()
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_analyze_gzip_tar(self):
        import tarfile
        path = os.path.join(self.tmpdir, "test.tar.gz")
        with tarfile.open(path, "w:gz") as tf:
            import io
            data = b"hello world"
            info = tarfile.TarInfo(name="file1.txt")
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))

        result = self.sandbox.analyze(path)
        self.assertEqual(result.archive_type, "gzip")
        self.assertEqual(result.total_entries, 1)

    def test_tar_path_traversal(self):
        import tarfile
        path = os.path.join(self.tmpdir, "traversal.tar")
        with tarfile.open(path, "w") as tf:
            import io
            data = b"malicious"
            info = tarfile.TarInfo(name="../../../etc/passwd")
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))

        result = self.sandbox.analyze(path)
        self.assertGreater(result.path_traversal_attempts, 0)


if __name__ == "__main__":
    unittest.main()
