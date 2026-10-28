"""
Modul algoritma RSA untuk eksperimen akademik.

PERINGATAN:
- Implementasi textbook RSA ini sengaja tidak menggunakan padding.
- Tidak aman untuk melindungi data sungguhan.
- Ukuran kunci default hanya untuk demonstrasi dan benchmark kelas.
- Gunakan pustaka kriptografi teruji (mis. RSA-OAEP + AES-GCM) untuk data nyata.
"""
from __future__ import annotations
import secrets
from math import gcd

def extended_gcd(a: int, b: int):
    """Mengembalikan (gcd(a,b), x, y) sehingga a*x + b*y = gcd(a,b)."""
    if b == 0:
        return a, 1, 0
    g, x1, y1 = extended_gcd(b, a % b)
    return g, y1, x1 - (a // b) * y1

def invers_modulo(a: int, m: int) -> int:
    """Menghitung invers a modulo m, jika gcd(a,m)=1."""
    g, x, _ = extended_gcd(a, m)
    if g != 1:
        raise ValueError("Invers modular tidak ada karena gcd(a, m) != 1.")
    return x % m

def is_probable_prime(n: int, rounds: int = 32) -> bool:
    """Uji Miller-Rabin probabilistik; cukup untuk demonstrasi pembangkitan kunci."""
    if n < 2:
        return False
    small_primes = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)
    for p in small_primes:
        if n == p:
            return True
        if n % p == 0:
            return False

    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1

    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def generate_prime(bits: int) -> int:
    """Membangkitkan bilangan prima probable-prime dengan ukuran bit tertentu."""
    if bits < 16:
        raise ValueError("Ukuran prima minimal 16 bit untuk demonstrasi ini.")
    while True:
        candidate = secrets.randbits(bits)
        candidate |= (1 << (bits - 1)) | 1
        if is_probable_prime(candidate):
            return candidate

def generate_keypair(modulus_bits: int = 512):
    """
    Membuat RSA key pair eksperimen.
    modulus_bits adalah target perkiraan ukuran n; gunakan bilangan genap.
    Default 512-bit TIDAK aman untuk penggunaan nyata.
    """
    if modulus_bits < 128 or modulus_bits % 2:
        raise ValueError("Gunakan modulus_bits genap dan minimal 128 untuk eksperimen.")
    prime_bits = modulus_bits // 2
    e = 65537

    while True:
        p = generate_prime(prime_bits)
        q = generate_prime(prime_bits)
        if p == q:
            continue
        n = p * q
        phi = (p - 1) * (q - 1)
        if gcd(e, phi) == 1:
            break

    d = invers_modulo(e, phi)
    d_p = d % (p - 1)
    d_q = d % (q - 1)
    q_inv = invers_modulo(q, p)

    public_key = {"n": n, "e": e}
    private_key = {
        "n": n, "d": d, "p": p, "q": q,
        "dP": d_p, "dQ": d_q, "q_inv": q_inv,
        "e": e,
    }
    return public_key, private_key

def encrypt_bytes(plaintext: bytes, public_key: dict) -> list[int]:
    """
    Enkripsi textbook RSA per byte untuk demonstrasi matematika saja.
    Tidak memiliki padding/randomisasi, sehingga tidak aman untuk file nyata.
    """
    n, e = public_key["n"], public_key["e"]
    if n <= 255:
        raise ValueError("Modulus n harus lebih besar dari 255.")
    return [pow(byte, e, n) for byte in plaintext]

def _validate_ciphertext(ciphertext: list[int], n: int):
    for c in ciphertext:
        if not isinstance(c, int) or c < 0 or c >= n:
            raise ValueError("Ciphertext berisi nilai di luar rentang RSA yang valid.")

def decrypt_standard(ciphertext: list[int], private_key: dict) -> bytes:
    """Metode 1: RSA standar, m = c^d mod n."""
    n, d = private_key["n"], private_key["d"]
    _validate_ciphertext(ciphertext, n)
    return bytes(pow(c, d, n) for c in ciphertext)

def decrypt_crt(ciphertext: list[int], private_key: dict) -> bytes:
    """Metode 2: RSA-CRT untuk mempercepat operasi privat."""
    p, q = private_key["p"], private_key["q"]
    d_p, d_q, q_inv = private_key["dP"], private_key["dQ"], private_key["q_inv"]
    n = private_key["n"]
    _validate_ciphertext(ciphertext, n)

    output = []
    for c in ciphertext:
        m1 = pow(c, d_p, p)
        m2 = pow(c, d_q, q)
        h = (q_inv * (m1 - m2)) % p
        m = m2 + h * q
        output.append(m)
    return bytes(output)

def _random_blinding_factor(n: int) -> int:
    """Menghasilkan r dalam rentang yang valid dengan gcd(r,n)=1."""
    while True:
        r = secrets.randbelow(n - 3) + 2
        if gcd(r, n) == 1:
            return r

def decrypt_blinding(ciphertext: list[int], private_key: dict) -> bytes:
    """Metode 3: RSA blinding untuk mengurangi kebocoran kanal samping tertentu."""
    n, d, e = private_key["n"], private_key["d"], private_key["e"]
    _validate_ciphertext(ciphertext, n)
    output = []
    for c in ciphertext:
        r = _random_blinding_factor(n)
        c_blind = (c * pow(r, e, n)) % n
        m_blind = pow(c_blind, d, n)
        m = (m_blind * invers_modulo(r, n)) % n
        output.append(m)
    return bytes(output)

def decrypt_crt_blinding(ciphertext: list[int], private_key: dict) -> bytes:
    """Metode 4: RSA-CRT + blinding."""
    n, e = private_key["n"], private_key["e"]
    p, q = private_key["p"], private_key["q"]
    d_p, d_q, q_inv = private_key["dP"], private_key["dQ"], private_key["q_inv"]
    _validate_ciphertext(ciphertext, n)

    output = []
    for c in ciphertext:
        r = _random_blinding_factor(n)
        c_blind = (c * pow(r, e, n)) % n

        m1 = pow(c_blind, d_p, p)
        m2 = pow(c_blind, d_q, q)
        h = (q_inv * (m1 - m2)) % p
        m_blind = m2 + h * q

        m = (m_blind * invers_modulo(r, n)) % n
        output.append(m)
    return bytes(output)

METHODS = {
    "a": ("RSA Standar", decrypt_standard),
    "b": ("RSA + CRT", decrypt_crt),
    "c": ("RSA + Blinding", decrypt_blinding),
    "d": ("RSA + CRT + Blinding", decrypt_crt_blinding),
}