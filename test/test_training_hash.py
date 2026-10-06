import hashlib
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import training_artifacts as artifacts


class TrainingHashTests(unittest.TestCase):
    def test_linux_advises_only_consumed_chunks_without_changing_hash(self):
        content = bytes(range(256)) * 9000
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "weights.bin"
            path.write_bytes(content)
            calls = []
            with patch.object(artifacts.sys, "platform", "linux"), patch.object(artifacts.os, "POSIX_FADV_DONTNEED", 4, create=True), patch.object(artifacts.os, "posix_fadvise", side_effect=lambda *args: calls.append(args), create=True):
                self.assertEqual(artifacts.sha256_file(path), hashlib.sha256(content).hexdigest())
            self.assertEqual([(offset, length, advice) for _, offset, length, advice in calls], [(0, 1048576, 4), (1048576, 1048576, 4), (2097152, len(content) - 2097152, 4)])
            self.assertEqual(path.read_bytes(), content)

    def test_windows_hash_does_not_attempt_linux_advice(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "weights.bin"
            path.write_bytes(b"model bytes")
            with patch.object(artifacts.sys, "platform", "win32"), patch.object(artifacts.os, "posix_fadvise", create=True) as advise:
                self.assertEqual(artifacts.sha256_file(path), hashlib.sha256(b"model bytes").hexdigest())
                advise.assert_not_called()

    def test_unsupported_filesystem_keeps_hash_mandatory(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "weights.bin"
            path.write_bytes(b"first content")
            with patch.object(artifacts.sys, "platform", "linux"), patch.object(artifacts.os, "POSIX_FADV_DONTNEED", 4, create=True), patch.object(artifacts.os, "posix_fadvise", side_effect=OSError("unsupported"), create=True):
                before = artifacts.sha256_file(path)
                path.write_bytes(b"tampered content")
                after = artifacts.sha256_file(path)
            self.assertNotEqual(before, after)
            self.assertEqual(after, hashlib.sha256(b"tampered content").hexdigest())


if __name__ == "__main__":
    unittest.main()
