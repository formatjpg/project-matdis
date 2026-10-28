"""Operasi file untuk prototipe RSA edukasional."""
from __future__ import annotations

import json
from pathlib import Path
from rsa_core import encrypt_bytes, METHODS

FORMAT_NAME = "RSA-EDUCATIONAL-DEMO-1"

def resolve_input_path(input_path: str, expected_suffix: str) -> Path:
    """Terima nama file tanpa ekstensi atau ekstensi yang memang diharapkan."""
    raw = input_path.strip().strip('"').strip()
    if not raw:
        raise ValueError("Path file tidak boleh kosong.")
    path = Path(raw).expanduser()
    if expected_suffix == ".enc.json":
        lower_name = path.name.lower()
        if lower_name.endswith(".enc.json"):
            pass
        elif path.suffix == "":
            path = Path(str(path) + ".enc.json")
        else:
            raise ValueError("Gunakan nama file tanpa ekstensi atau dengan ekstensi .enc.json.")
    else:
        if path.suffix == "":
            path = path.with_suffix(expected_suffix)
        elif path.suffix.lower() != expected_suffix.lower():
            raise ValueError(f"File input harus berekstensi {expected_suffix}.")
    if not path.is_file():
        raise FileNotFoundError(f"File '{path}' tidak ditemukan.")
    return path

def default_ciphertext_path(source: Path) -> Path:
    """Contoh lorem.txt menjadi lorem.enc.json."""
    if source.suffix.lower() == ".txt":
        return source.with_suffix(".enc.json")
    return Path(str(source) + ".enc.json")

def default_plaintext_output(cipher_path: Path) -> Path:
    """Contoh lorem.enc.json menjadi lorem_pulih.txt."""
    name = cipher_path.name
    if name.lower().endswith(".enc.json"):
        name = name[:-len(".enc.json")]
    else:
        name = cipher_path.stem
    return cipher_path.with_name(name + "_pulih.txt")

def encrypt_file(input_path: str, output_path: str, public_key: dict) -> int:
    """Enkripsi textbook RSA per byte; hanya untuk demonstrasi akademik."""
    source = resolve_input_path(input_path, ".txt")
    data = source.read_bytes()
    ciphertext = encrypt_bytes(data, public_key)
    payload = {
        "format": FORMAT_NAME,
        # Textbook RSA tanpa padding hanya untuk eksperimen akademik.
        "original_name": source.name,
        "original_size_bytes": len(data),
        "ciphertext": ciphertext,
    }
    destination = Path(output_path).expanduser()
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(payload), encoding="utf-8")
    return len(data)

def read_ciphertext_file(input_path: str) -> tuple[list[int], dict]:
    path = resolve_input_path(input_path, ".enc.json")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        if payload.get("format") != FORMAT_NAME:
            raise ValueError("Format file tidak dikenali sebagai ciphertext demo ini.")
        ciphertext = [int(x) for x in payload["ciphertext"]]
        if any(x < 0 for x in ciphertext):
            raise ValueError("Ciphertext berisi nilai negatif.")
    except (json.JSONDecodeError, KeyError, TypeError) as exc:
        raise ValueError("File ciphertext rusak atau formatnya tidak valid.") from exc
    return ciphertext, payload

def decrypt_file(input_path: str, output_path: str, private_key: dict, method_key: str) -> int:
    if method_key not in METHODS:
        raise ValueError("Metode dekripsi tidak dikenal.")
    ciphertext, _ = read_ciphertext_file(input_path)
    _, decrypt_function = METHODS[method_key]
    plaintext = decrypt_function(ciphertext, private_key)
    destination = Path(output_path).expanduser()
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(plaintext)
    return len(plaintext)