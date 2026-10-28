"""Antarmuka CLI berwarna untuk RSA File Vault (prototipe edukasional)."""
from __future__ import annotations

import os
import sys
import time
from pathlib import Path

from rsa_core import generate_keypair, METHODS
from key_manager import save_keys, load_keys
from file_vault import (
    encrypt_file,
    decrypt_file,
    read_ciphertext_file,
    resolve_input_path,
    default_ciphertext_path,
    default_plaintext_output,
)
from benchmark import benchmark_methods

DEFAULT_KEY_FILE = str(Path(__file__).resolve().parent / "rsa_key.json")

class UI:
    """Warna ANSI sederhana; otomatis nonaktif bila terminal tidak mendukungnya."""
    ENABLED = (
        hasattr(sys.stdout, "isatty")
        and sys.stdout.isatty()
        and "NO_COLOR" not in os.environ
    )
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    CYAN = "\033[36m"
    WHITE = "\033[97m"

    @classmethod
    def paint(cls, text: str, *styles: str) -> str:
        if not cls.ENABLED:
            return str(text)
        return "".join(styles) + str(text) + cls.RESET

def line(char: str = "─", width: int = 68) -> str:
    return char * width

def section(title: str) -> None:
    print("\n" + UI.paint("┌─ " + title + " " + "─" * max(2, 62 - len(title)), UI.CYAN, UI.BOLD))

def success(message: str) -> None:
    print("\n" + UI.paint("  ✓  ", UI.GREEN, UI.BOLD) + UI.paint(message, UI.GREEN))

def info(message: str) -> None:
    print(UI.paint("  •  ", UI.BLUE, UI.BOLD) + message)

def warning(message: str) -> None:
    print(UI.paint("  !  ", UI.YELLOW, UI.BOLD) + UI.paint(message, UI.YELLOW))

def error(message: str) -> None:
    print("\n" + UI.paint("  ✗  ERROR: ", UI.RED, UI.BOLD) + UI.paint(message, UI.RED))

def prompt_path(prompt: str, default: str = "") -> str:
    hint = UI.paint(" [" + default + "]", UI.DIM) if default else ""
    value = input(UI.paint("  › ", UI.CYAN, UI.BOLD) + prompt + hint + ": ").strip()
    return value or default

def normalize_output_path(value: str, suffix: str) -> str:
    """Pastikan output enkripsi berakhiran .enc.json."""
    value = value.strip().strip('"')
    path = Path(value).expanduser()
    if path.name.lower().endswith(suffix.lower()):
        return str(path)
    if suffix == ".enc.json":
        if path.suffix.lower() == ".txt":
            path = path.with_suffix(suffix)
        else:
            path = Path(str(path) + suffix)
    return str(path)

def normalize_decrypted_output_path(value: str) -> str:
    """Nama output tanpa ekstensi mendapat akhiran _pulih.txt."""
    value = value.strip().strip('"')
    path = Path(value).expanduser()
    lower = path.name.lower()
    if lower.endswith(".txt"):
        return str(path)
    if lower.endswith("_pulih"):
        return str(path) + ".txt"
    if lower.endswith(".pulih"):
        return str(path.with_name(path.name[:-len(".pulih")] + "_pulih.txt"))
    if path.suffix == "":
        return str(path) + "_pulih.txt"
    return str(path) + ".txt"

def print_key_summary(public_key: dict, key_path: str) -> None:
    width = 68
    print(UI.paint("┌" + "─" * width + "┐", UI.BLUE))
    title = " RSA FILE VAULT "
    print(UI.paint("│", UI.BLUE) + UI.paint(title.center(width), UI.BOLD, UI.WHITE) + UI.paint("│", UI.BLUE))
    print(UI.paint("├" + "─" * width + "┤", UI.BLUE))
    key_label = "Kunci aktif : "
    size_label = "Ukuran kunci: "
    visible_path = str(key_path)
    max_path_len = width - len(key_label) - 3
    if len(visible_path) > max_path_len:
        visible_path = "…" + visible_path[-(max_path_len - 1):]
    key_text = key_label + visible_path
    print(UI.paint("│ ", UI.BLUE) + UI.paint(key_label, UI.DIM) + visible_path + " " * max(0, width - len(key_text) - 1) + UI.paint("│", UI.BLUE))
    size_text = size_label + str(public_key["n"].bit_length()) + " bit"
    print(UI.paint("│ ", UI.BLUE) + UI.paint(size_label, UI.DIM) + UI.paint(str(public_key["n"].bit_length()) + " bit", UI.CYAN, UI.BOLD) + " " * max(0, width - len(size_text) - 1) + UI.paint("│", UI.BLUE))
    print(UI.paint("└" + "─" * width + "┘", UI.BLUE))

def ensure_keys():
    path = Path(DEFAULT_KEY_FILE)
    if path.exists():
        try:
            public_key, private_key, loaded_path = load_keys(str(path))
            info("Kunci dimuat dari " + str(loaded_path))
            return public_key, private_key, loaded_path
        except ValueError as exc:
            warning("File kunci default tidak valid: " + str(exc))
            answer = input("  Buat pasangan kunci baru dan timpa file tersebut? (y/N): ").strip().lower()
            if answer != "y":
                raise RuntimeError("Kunci tidak valid. Perbaiki file atau pilih file kunci lain melalui menu 5.")

    info("File rsa_key.json belum ada atau perlu dibuat ulang; membuat kunci demo 512-bit.")
    public_key, private_key = generate_keypair(512)
    saved_path = save_keys(public_key, private_key, DEFAULT_KEY_FILE)
    success("Kunci disimpan ke " + str(saved_path))
    return public_key, private_key, str(Path(saved_path).resolve())

def menu() -> None:
    width = 68
    print("\n" + UI.paint("╭" + "─" * width + "╮", UI.CYAN))
    title = "MENU UTAMA"
    print(UI.paint("│", UI.CYAN) + UI.paint(title.center(width), UI.BOLD, UI.WHITE) + UI.paint("│", UI.CYAN))
    print(UI.paint("├" + "─" * width + "┤", UI.CYAN))
    items = [
        ("1", "Enkripsi file teks", "TXT  →  ENC.JSON"),
        ("2", "Dekripsi file", "ENC.JSON  →  TXT"),
        ("3", "Benchmark empat metode", "UJI PERFORMA"),
        ("4", "Buat pasangan kunci baru", "RSA KEYGEN"),
        ("5", "Muat file kunci JSON lain", "GANTI KUNCI"),
        ("6", "Keluar", "EXIT"),
    ]
    for number, label, detail in items:
        left = "  [" + number + "]  " + label
        # Panjang dihitung dari teks biasa, bukan string ANSI berwarna.
        gap = max(2, width - len(left) - len(detail))
        row = (UI.paint("│", UI.CYAN) + UI.paint("  [" + number + "]", UI.CYAN, UI.BOLD)
               + "  " + label + " " * gap + UI.paint(detail, UI.DIM)
               + UI.paint("│", UI.CYAN))
        print(row)
    print(UI.paint("╰" + "─" * width + "╯", UI.CYAN))
    print(UI.paint("Pilih menu (1–6)", UI.BOLD) + "  " + UI.paint("atau Ctrl+C untuk membatalkan operasi", UI.DIM))

def prompt_resolved_input(prompt: str, suffix: str):
    while True:
        entered = prompt_path(prompt)
        try:
            return resolve_input_path(entered, suffix)
        except (OSError, ValueError) as exc:
            error(str(exc))
            info("Masukkan path file yang benar, atau nama file tanpa ekstensi.")

def prompt_positive_integer(prompt: str, default: int) -> int:
    while True:
        raw = prompt_path(prompt, str(default))
        try:
            value = int(raw)
            if value <= 0:
                raise ValueError
            return value
        except ValueError:
            error("Masukkan bilangan bulat positif.")

def prompt_choice(prompt: str, allowed: tuple, default: str = "") -> str:
    while True:
        value = input(UI.paint("  › ", UI.CYAN, UI.BOLD) + prompt).strip().lower() or default
        if value in allowed:
            return value
        error("Pilihan tidak valid. Pilih: " + ", ".join(allowed) + ".")

def print_benchmark_results(results, show_iterations: bool) -> None:
    section("HASIL BENCHMARK")
    if show_iterations:
        print(UI.paint("Mode: seluruh iterasi dan median", UI.DIM))
        for item in results:
            print("\n" + UI.paint("▸ " + item["method"], UI.CYAN, UI.BOLD))
            for i, sample in enumerate(item["samples_ms"], start=1):
                print("    Iterasi {:>2}  {:>12.3f} ms".format(i, sample))
            print("    Median      {:>12.3f} ms".format(item["median_ms"]))
            print("    Peak Python {:>12.2f} KB".format(item["peak_kb"]))
            result_label = UI.paint("LULUS", UI.GREEN, UI.BOLD) if item["correct"] else UI.paint("GAGAL", UI.RED, UI.BOLD)
            print("    Validasi    " + result_label)
    else:
        print(UI.paint("Mode: median saja (waktu dekripsi tanpa I/O file)", UI.DIM))
        print(line("─", 78))
        print("{:<28} {:>16} {:>16} {:>10}".format("Metode", "Median (ms)", "Peak (KB)", "Validasi"))
        print(line("─", 78))
        for item in results:
            result_label = UI.paint("LULUS", UI.GREEN, UI.BOLD) if item["correct"] else UI.paint("GAGAL", UI.RED, UI.BOLD)
            print("{:<28} {:>16.3f} {:>16.2f} {:>10}".format(
                item["method"], item["median_ms"], item["peak_kb"], result_label
            ))
    print(line("─", 78))
    fastest = min(results, key=lambda row: row["median_ms"])
    success("Metode tercepat pada percobaan ini: " + fastest["method"])

def main() -> None:
    print("\n" + UI.paint("RSA FILE VAULT", UI.CYAN, UI.BOLD) + UI.paint("  /  Prototipe eksperimen akademik", UI.DIM))
    print(UI.paint(line("─", 68), UI.CYAN))
    try:
        public_key, private_key, key_path = ensure_keys()
    except (OSError, ValueError, RuntimeError) as exc:
        error(str(exc))
        return

    while True:
        print_key_summary(public_key, key_path)
        menu()
        choice = input(UI.paint("\n  › ", UI.CYAN, UI.BOLD)).strip()
        try:
            if choice == "1":
                section("ENKRIPSI FILE")
                source = prompt_resolved_input("Path file .txt: ", ".txt")
                default_out = str(default_ciphertext_path(source))
                while True:
                    output = normalize_output_path(prompt_path("Simpan sebagai .enc.json", default_out), ".enc.json")
                    try:
                        start = time.perf_counter()
                        size = encrypt_file(str(source), output, public_key)
                        elapsed = (time.perf_counter() - start) * 1000
                        success("Enkripsi selesai")
                        print("    File sumber : " + str(source))
                        print("    File output : " + output)
                        print("    Ukuran      : {} byte".format(size))
                        print("    Durasi      : {:.3f} ms (termasuk I/O)".format(elapsed))
                        break
                    except OSError as exc:
                        error("Tidak dapat menyimpan file output: " + str(exc))
                        info("Periksa folder tujuan, lalu masukkan path output lain.")

            elif choice == "2":
                section("DEKRIPSI FILE")
                source = prompt_resolved_input("Path file .enc.json: ", ".enc.json")
                default_out = str(default_plaintext_output(source))
                while True:
                    output = normalize_decrypted_output_path(prompt_path("Simpan hasil sebagai .txt", default_out))
                    print("\n" + UI.paint("Metode dekripsi", UI.BOLD))
                    for key, (label, _) in METHODS.items():
                        print("    " + UI.paint("[{}]".format(key), UI.CYAN, UI.BOLD) + "  " + label)
                    method = prompt_choice("Pilih metode (a/b/c/d): ", tuple(METHODS.keys()))
                    try:
                        size = decrypt_file(str(source), output, private_key, method)
                        success("Dekripsi selesai")
                        print("    File sumber : " + str(source))
                        print("    File output : " + output)
                        print("    Ukuran pulih: {} byte".format(size))
                        break
                    except OSError as exc:
                        error("Tidak dapat membaca/menyimpan file: " + str(exc))
                        retry = prompt_choice("Coba lagi? (y/n): ", ("y", "n"))
                        if retry == "n":
                            break
                    except ValueError as exc:
                        error(str(exc))
                        retry = prompt_choice("Coba metode/path lain? (y/n): ", ("y", "n"))
                        if retry == "n":
                            break

            elif choice == "3":
                section("BENCHMARK METODE DEKRIPSI")
                source = prompt_resolved_input("Path file .enc.json: ", ".enc.json")
                ciphertext, payload = read_ciphertext_file(str(source))
                if not ciphertext:
                    warning("File kosong; tidak ada operasi dekripsi untuk diukur.")
                    continue
                repeats = prompt_positive_integer("Jumlah pengulangan per metode", 5)
                print("\n" + UI.paint("Mode tampilan", UI.BOLD))
                print("    [1] Semua iterasi + median\n    [2] Median saja")
                display_mode = prompt_choice("Pilih tampilan (1/2) [2]: ", ("1", "2"), "2")
                info("Benchmark berjalan; progres ditampilkan per metode.")

                def show_progress(method_label, iteration, total):
                    if iteration == 0:
                        print("\n" + UI.paint("▸ Mengukur " + method_label, UI.CYAN, UI.BOLD), flush=True)
                    else:
                        print("    Iterasi {}/{} selesai".format(iteration, total), flush=True)

                results = benchmark_methods(ciphertext, private_key, repeats, progress_callback=show_progress)
                print("\nFile            : " + str(source))
                print("Ukuran asli     : {} byte".format(payload.get("original_size_bytes", "tidak diketahui")))
                print("Jumlah pengujian: {} ({} metode × {} pengulangan)".format(len(METHODS) * repeats, len(METHODS), repeats))
                print_benchmark_results(results, display_mode == "1")

            elif choice == "4":
                section("PEMBUATAN KUNCI BARU")
                warning("Kunci baru dapat membuat file lama tidak bisa didekripsi.")
                answer = prompt_choice("Lanjutkan? (y/n) [n]: ", ("y", "n"), "n")
                if answer != "y":
                    info("Pembuatan kunci dibatalkan.")
                    continue
                while True:
                    bits = prompt_positive_integer("Ukuran modulus dalam bit", 512)
                    if bits >= 128 and bits % 2 == 0:
                        break
                    error("Ukuran modulus harus genap dan minimal 128 bit.")
                start = time.perf_counter()
                new_public, new_private = generate_keypair(bits)
                elapsed = (time.perf_counter() - start) * 1000
                saved_path = save_keys(new_public, new_private, DEFAULT_KEY_FILE)
                public_key, private_key = new_public, new_private
                key_path = str(Path(saved_path).resolve())
                success("Pasangan kunci baru berhasil dibuat")
                print("    File kunci : " + key_path)
                print("    Ukuran     : {} bit".format(public_key["n"].bit_length()))
                print("    Durasi     : {:.3f} ms".format(elapsed))
                warning("Kunci demo ini tidak ditujukan untuk melindungi data sungguhan.")

            elif choice == "5":
                section("MUAT FILE KUNCI")
                while True:
                    source = prompt_path("Path file kunci JSON")
                    try:
                        new_public, new_private, new_key_path = load_keys(source)
                        public_key, private_key, key_path = new_public, new_private, new_key_path
                        success("Kunci aktif berhasil diganti")
                        print("    File kunci : " + str(key_path))
                        print("    Ukuran     : {} bit".format(public_key["n"].bit_length()))
                        break
                    except (OSError, ValueError, RuntimeError) as exc:
                        error(str(exc))
                        retry = prompt_choice("Masukkan path lain? (y/n): ", ("y", "n"))
                        if retry == "n":
                            break

            elif choice == "6":
                print("\n" + UI.paint(line("─", 68), UI.CYAN))
                success("Program RSA File Vault selesai. Terima kasih!")
                break
            else:
                error("Pilihan menu tidak valid. Masukkan angka 1 sampai 6.")
        except (OSError, ValueError, RuntimeError) as exc:
            error(str(exc))
        except KeyboardInterrupt:
            print("\n")
            warning("Operasi dibatalkan oleh pengguna.")
        except EOFError:
            print("\n")
            info("Input berakhir; program ditutup.")
            break

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n  Operasi dibatalkan oleh pengguna.")
        print("  RSA File Vault ditutup.")