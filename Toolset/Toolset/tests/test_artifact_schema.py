from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from toolset_core.artifacts import ArtifactStore


class ArtifactStoreTests(unittest.TestCase):
    def test_write_text_returns_ref_and_hash(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT / "tests") as tmp:
            store = ArtifactStore(Path(tmp) / "artifacts")
            record = store.write_text("logs/out.txt", "hello")
            self.assertEqual(record.ref, "artifact://logs/out.txt")
            self.assertTrue(record.sha256.startswith("sha256:"))
            self.assertEqual(store.ref_to_path(record.ref), record.path)

    def test_path_escape_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT / "tests") as tmp:
            store = ArtifactStore(Path(tmp) / "artifacts")
            with self.assertRaises(ValueError):
                store.write_text("../escape.txt", "no")


if __name__ == "__main__":
    unittest.main()
