# RSA File Vault

Proyek CLI akademik untuk membandingkan empat metode dekripsi:
1. RSA standar
2. RSA + CRT
3. RSA + Blinding
4. RSA + CRT + Blinding

## Isi proyek
- `main.py`: menu CLI, otomatis membuat/memuat kunci, input nama file dan submenu benchmark.
- `rsa_core.py`: pembangkitan kunci, enkripsi/dekripsi, empat metode.
- `key_manager.py`: penyimpanan/pemuatan kunci JSON; nama default `rsa_key.json`.
- `file_vault.py`: operasi file ciphertext JSON.
- `benchmark.py`: pengukuran median waktu, iterasi individual, dan peak alokasi Python.
- `test_rsa_core.py`: pengujian otomatis.

```bash
python main.py
```

Uji otomatis:

```bash
python -m unittest -v
```

## File input
- Enkripsi mencari file `.txt`; masukkan `lorem` atau `lorem.txt`.
- Dekripsi dan benchmark mencari file `.enc.json`; masukkan `lorem` atau `lorem.enc.json`.
- Default hasil enkripsi: `lorem.enc.json`.
- Default hasil dekripsi: `lorem.pulih`.
- Kunci default: `rsa_key.json`, dibuat otomatis saat program mulai jika belum ada.

## Benchmark
Menu 3 meminta jumlah pengulangan per metode (default 5), lalu mode tampilan:
1. semua iterasi dan median;
2. median saja.

Empat metode x lima pengulangan = 20 pengukuran waktu. I/O file tidak masuk pengukuran waktu. `Peak Python (KB)` adalah peak alokasi Python yang dilacak `tracemalloc`, bukan seluruh RAM proses.

## Batasan keamanan — wajib dibaca
Implementasi ini **hanya prototipe edukasional**, bukan untuk data sensitif.
- Enkripsi memakai textbook RSA per byte tanpa padding, tidak aman dan tidak memberikan autentikasi/integritas.
- Ukuran kunci default 512-bit hanya untuk demonstrasi, bukan ukuran aman.
- JSON menyimpan parameter privat tanpa enkripsi; jaga `rsa_key.json` agar tidak dibagikan.
- Blinding mengurangi risiko kanal samping tertentu, tetapi tidak menjadikan implementasi Python tahan semua timing attack.
- CRT dapat memiliki risiko fault attack jika tidak ada pemeriksaan hasil dekripsi.
- Hasil benchmark waktu/memori tidak membuktikan keamanan kriptografis.

Untuk penggunaan nyata, gunakan pustaka kriptografi teruji dan skema hibrida: AES-GCM untuk isi file serta RSA-OAEP untuk melindungi kunci AES.
