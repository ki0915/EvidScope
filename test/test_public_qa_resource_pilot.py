import importlib.util
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
spec = importlib.util.spec_from_file_location("pilot", ROOT / "scripts/public-qa-resource-pilot.py")
pilot = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pilot)


def item(index, length):
    return ({"input_ids": list(range(length)), "attention_mask": [1] * length, "labels": [-100] * length}, {"id": f"row-{index}", "tokens": length})


class PilotSelectionTests(unittest.TestCase):
    def test_deterministic_sample_includes_longest_without_duplicates(self):
        rows = [item(index, 100 + index) for index in range(40)]
        selected = pilot.select_pilot_features(rows, count=32)
        self.assertEqual(selected, pilot.select_pilot_features(rows, count=32))
        self.assertEqual(len(selected), 32)
        self.assertIs(selected[0], rows[-1])
        self.assertEqual(len({row[1]["id"] for row in selected}), 32)

    def test_invalid_or_misaligned_features_fail_closed(self):
        with self.assertRaisesRegex(ValueError, "count_invalid"):
            pilot.select_pilot_features([], count=1)
        with self.assertRaisesRegex(ValueError, "feature_invalid"):
            pilot.select_pilot_features([({"input_ids": [1], "attention_mask": [], "labels": [1]}, {"tokens": 1})], count=1)
        with self.assertRaisesRegex(ValueError, "feature_invalid"):
            pilot.select_pilot_features([item(0, 1025)], count=1)


if __name__ == "__main__":
    unittest.main()
