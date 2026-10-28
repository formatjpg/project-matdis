"""Benchmark terkontrol untuk empat metode dekripsi."""
from __future__ import annotations

import statistics
import time
import tracemalloc
from rsa_core import METHODS

def _measure_peak_memory(fn):
    """Peak alokasi Python terlacak; bukan total RAM proses."""
    tracemalloc.start()
    try:
        # clear_traces tersedia di Python 3.8; reset_peak tidak tersedia di beberapa versi.
        tracemalloc.clear_traces()
        fn()
        _, peak = tracemalloc.get_traced_memory()
        return peak / 1024
    finally:
        tracemalloc.stop()

def benchmark_methods(ciphertext: list[int], private_key: dict, repeats: int = 5, progress_callback=None):
    """Mengukur empat metode pada ciphertext yang sama, tanpa I/O file."""
    if repeats < 1:
        raise ValueError("Jumlah pengulangan minimal 1.")

    # Hasil referensi untuk validasi. Operasi ini tetap membutuhkan waktu untuk file besar.
    reference = METHODS["a"][1](ciphertext, private_key)

    # Warm-up singkat; tidak masuk sampel yang dilaporkan.
    sample = ciphertext[:min(8, len(ciphertext))]
    for _, fn in METHODS.values():
        fn(sample, private_key)

    results = []
    for key, (label, fn) in METHODS.items():
        samples_ms = []
        if progress_callback is not None:
            progress_callback(label, 0, repeats)
        for iteration in range(1, repeats + 1):
            start = time.perf_counter()
            output = fn(ciphertext, private_key)
            elapsed = (time.perf_counter() - start) * 1000
            if output != reference:
                raise RuntimeError(f"Validasi gagal pada iterasi metode {label}.")
            samples_ms.append(elapsed)
            if progress_callback is not None:
                progress_callback(label, iteration, repeats)

        peak_kb = _measure_peak_memory(lambda: fn(ciphertext, private_key))
        results.append({
            "key": key,
            "method": label,
            "median_ms": statistics.median(samples_ms),
            "samples_ms": samples_ms,
            "peak_kb": peak_kb,
            "correct": True,
        })
    return results