"""Uji otomatis dasar: jalankan dengan `python -m unittest -v`."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from rsa_core import generate_keypair, encrypt_bytes, METHODS
from file_vault import encrypt_file, read_ciphertext_file, decrypt_file
from key_manager import save_keys, load_keys
from benchmark import benchmark_methods
from main import normalize_output_path, normalize_decrypted_output_path

class RSACoreTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.public_key, cls.private_key = generate_keypair(256)
        cls.plaintext = "Uji RSA CRT dan Blinding: 123 ✓".encode("utf-8")
        cls.ciphertext = encrypt_bytes(cls.plaintext, cls.public_key)

    def test_all_methods_recover_plaintext(self):
        for key, (_, decrypt_fn) in METHODS.items():
            with self.subTest(method=key):
                self.assertEqual(decrypt_fn(self.ciphertext, self.private_key), self.plaintext)

    def test_crt_parameters(self):
        self.assertEqual(self.private_key["p"] * self.private_key["q"], self.private_key["n"])

    def test_benchmark_returns_samples_and_median(self):
        result = benchmark_methods(self.ciphertext[:5], self.private_key, 3)
        self.assertEqual(len(result), 4)
        self.assertTrue(all(len(item["samples_ms"]) == 3 for item in result))
        self.assertTrue(all(item["correct"] for item in result))

    def test_file_roundtrip_and_name_without_extension(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            original = root / "lorem.txt"
            original.write_bytes(self.plaintext)
            encrypt_file(str(root / "lorem"), str(root / "lorem.enc.json"), self.public_key)
            ciphertext, _ = read_ciphertext_file(str(root / "lorem"))
            self.assertEqual(ciphertext, self.ciphertext)
            out = root / "restored.txt"
            decrypt_file(str(root / "lorem.enc.json"), str(out), self.private_key, "d")
            self.assertEqual(out.read_bytes(), self.plaintext)

    def test_decryption_rejects_wrong_key_for_new_ciphertext(self):
        wrong_public, wrong_private = generate_keypair(256)
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            original = root / "lorem.txt"
            original.write_bytes(self.plaintext)
            encrypted = root / "lorem.enc.json"
            encrypt_file(str(original), str(encrypted), self.public_key)
            with self.assertRaisesRegex(ValueError, "Kunci aktif tidak cocok"):
                decrypt_file(str(encrypted), str(root / "wrong.txt"), wrong_private, "d")

    def test_output_names_get_expected_extensions(self):
        self.assertTrue(normalize_output_path("lorem", ".enc.json").endswith("lorem.enc.json"))
        self.assertTrue(normalize_output_path("lorem.enc.json", ".enc.json").endswith("lorem.enc.json"))
        self.assertTrue(normalize_decrypted_output_path("lorem").endswith("lorem_pulih.txt"))
        self.assertTrue(normalize_decrypted_output_path("lorem.pulih").endswith("lorem_pulih.txt"))

    def test_key_default_name(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "rsa_key.json"
            saved = save_keys(self.public_key, self.private_key, str(path))
            loaded_public, loaded_private, _ = load_keys(saved)
            self.assertEqual(loaded_public, self.public_key)
            self.assertEqual(loaded_private, self.private_key)

if __name__ == "__main__":
    unittest.main()