"""Unit tests. Run from the project root:  python -m unittest discover -s tests -v"""

import hashlib
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from collision_detector import CollisionDetector, scan_inputs  # noqa: E402
from hash_generator import (  # noqa: E402
    SUPPORTED_ALGORITHMS,
    UnsupportedAlgorithmError,
    generate_hash,
    normalize_algorithm,
)
from utils import parse_input_line, read_inputs_from_file  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class HashGeneratorTests(unittest.TestCase):
    def test_known_vectors(self):
        self.assertEqual(generate_hash("abc", "md5"), "900150983cd24fb0d6963f7d28e17f72")
        self.assertEqual(generate_hash("abc", "sha1"),
                         "a9993e364706816aba3e25717850c26c9cd0d89d")
        self.assertEqual(
            generate_hash("abc", "sha256"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        self.assertTrue(generate_hash("abc", "sha512").startswith("ddaf35a193617aba"))

    def test_matches_hashlib_for_all_algorithms(self):
        for alg in SUPPORTED_ALGORITHMS:
            self.assertEqual(generate_hash("data", alg), hashlib.new(alg, b"data").hexdigest())

    def test_name_normalisation(self):
        self.assertEqual(normalize_algorithm("SHA-256"), "sha256")
        self.assertEqual(normalize_algorithm(" sha_1 "), "sha1")

    def test_unsupported_algorithm(self):
        with self.assertRaises(UnsupportedAlgorithmError):
            generate_hash("x", "crc32")
        with self.assertRaises(UnsupportedAlgorithmError):
            normalize_algorithm("")

    def test_truncation(self):
        full = generate_hash("abc", "md5")
        self.assertEqual(generate_hash("abc", "md5", 16), full[:4])
        self.assertEqual(generate_hash("abc", "md5", 12), full[:3])
        for bad in (0, -1, 129):
            with self.assertRaises(ValueError):
                generate_hash("abc", "md5", bad)

    def test_bad_data_type(self):
        with self.assertRaises(TypeError):
            generate_hash(123, "md5")


class DetectorTests(unittest.TestCase):
    def test_no_collision_for_distinct_inputs(self):
        det = CollisionDetector("sha256")
        det.add_many(["a", "b", "c"])
        r = det.result()
        self.assertFalse(r.has_collisions)
        self.assertEqual((r.total_inputs, r.unique_hashes), (3, 3))

    def test_duplicates_are_not_collisions(self):
        det = CollisionDetector("md5")
        det.add_many(["same", "same", "other"])
        r = det.result()
        self.assertEqual(r.duplicates_skipped, 1)
        self.assertEqual(r.collision_count, 0)
        self.assertEqual(r.unique_hashes, 2)

    def test_truncated_collision_detected(self):
        det = CollisionDetector("md5", truncate_bits=8)  # only 256 values
        det.add_many(f"item-{i}" for i in range(1000))
        r = det.result()
        self.assertTrue(r.has_collisions)
        hit = r.collisions[0]
        self.assertNotEqual(hit.first_input, hit.second_input)
        self.assertEqual(generate_hash(hit.first_input, "md5", 8),
                         generate_hash(hit.second_input, "md5", 8))

    def test_real_md5_collision_vectors(self):
        inputs = read_inputs_from_file(os.path.join(ROOT, "samples", "md5_collision_pair.txt"))
        self.assertEqual(len(inputs), 2)
        md5 = scan_inputs(inputs, ["md5"])[0]
        self.assertEqual(md5.collision_count, 1)
        self.assertEqual(md5.collisions[0].digest, "79054025255fb1a26e4bc422aef54eb4")
        sha = scan_inputs(inputs, ["sha256"])[0]
        self.assertFalse(sha.has_collisions)

    def test_invalid_truncation_rejected(self):
        with self.assertRaises(ValueError):
            CollisionDetector("md5", truncate_bits=500)


class UtilsTests(unittest.TestCase):
    def test_hex_prefix(self):
        self.assertEqual(parse_input_line("hex:00 ff"), b"\x00\xff")
        self.assertEqual(parse_input_line("plain"), b"plain")
        with self.assertRaises(ValueError):
            parse_input_line("hex:zz")
        with self.assertRaises(ValueError):
            parse_input_line("hex:")

    def test_file_reading(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "in.txt")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("# comment\nalpha\n\nbeta \r\n")
            self.assertEqual(read_inputs_from_file(path), [b"alpha", b"beta "])

    def test_file_errors(self):
        with self.assertRaises(FileNotFoundError):
            read_inputs_from_file("/no/such/file.txt")
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(IsADirectoryError):
                read_inputs_from_file(tmp)
            bad = os.path.join(tmp, "bin.txt")
            with open(bad, "wb") as fh:
                fh.write(b"\xff\xfe\xfa")
            with self.assertRaises(ValueError):
                read_inputs_from_file(bad)


if __name__ == "__main__":
    unittest.main()
