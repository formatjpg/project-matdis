"""Penyimpanan dan pemuatan parameter RSA dalam JSON."""
from __future__ import annotations
import json
import os
from pathlib import Path

KEY_FORMAT_VERSION = 1

def save_keys(public_key: dict, private_key: dict, filename: str = "rsa_key.json") -> str:
    """Simpan kunci eksperimen ke JSON. Kunci privat disimpan TANPA enkripsi."""
    path = Path(filename).expanduser()
    if path.suffix.lower() != ".json":
        path = path.with_suffix(".json")

    payload = {
        "format_version": KEY_FORMAT_VERSION,
        "purpose": "EDUCATIONAL_DEMO_ONLY",
        # Parameter privat disimpan apa adanya untuk eksperimen lokal.
        "public_key": public_key,
        "private_key": private_key,
    }
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return str(path)

def load_keys(filename: str = "rsa_key.json"):
    """Muat dan validasi struktur dasar kunci dari JSON."""
    path = Path(filename).expanduser()
    if path.suffix.lower() != ".json":
        path = path.with_suffix(".json")
    if not path.is_file():
        raise FileNotFoundError(f"File kunci '{path}' tidak ditemukan.")

    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        public_key = payload["public_key"]
        private_key = payload["private_key"]
        n, e = int(public_key["n"]), int(public_key["e"])
        required = ("n", "d", "p", "q", "dP", "dQ", "q_inv", "e")
        private_key = {k: int(private_key[k]) for k in required}
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise ValueError("Struktur file JSON kunci tidak valid.") from exc

    if n != private_key["n"] or e != private_key["e"]:
        raise ValueError("Kunci publik dan privat tidak cocok.")
    if private_key["p"] * private_key["q"] != n:
        raise ValueError("Validasi kunci gagal: p*q tidak sama dengan n.")
    if not (1 < e < n and 1 < private_key["d"] < n):
        raise ValueError("Nilai eksponen kunci tidak valid.")
    if private_key["dP"] != private_key["d"] % (private_key["p"] - 1):
        raise ValueError("Parameter dP tidak konsisten.")
    if private_key["dQ"] != private_key["d"] % (private_key["q"] - 1):
        raise ValueError("Parameter dQ tidak konsisten.")

    return public_key, private_key, str(path.resolve())

def key_file_exists(filename: str = "rsa_key.json") -> bool:
    return os.path.isfile(filename)