from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.backends import default_backend
import os
from .util import now_ns, ns_to_ms

# Returns (ct, key, nonce, ad, tag, elapsed_ms, algo_name, variant)

def enc_aes_gcm(msg: bytes, key_bits: int, ad: bytes=b"CN-Py") -> tuple:
    key = os.urandom(key_bits // 8)
    aes = AESGCM(key)
    nonce = os.urandom(12)
    t0 = now_ns()
    ct = aes.encrypt(nonce, msg, ad)
    _ = aes.decrypt(nonce, ct, ad)
    ms = ns_to_ms(now_ns() - t0)
    return (ct, key, nonce, ad, None, ms, "AES-GCM", str(key_bits))

def enc_chacha_poly(msg: bytes, ad: bytes=b"CN-Py") -> tuple:
    key = os.urandom(32)
    cc = ChaCha20Poly1305(key)
    nonce = os.urandom(12)
    t0 = now_ns()
    ct = cc.encrypt(nonce, msg, ad)
    _ = cc.decrypt(nonce, ct, ad)
    ms = ns_to_ms(now_ns() - t0)
    return (ct, key, nonce, ad, None, ms, "ChaCha20-Poly1305", "256")

def enc_aes_ctr_hmac(msg: bytes) -> tuple:
    key = os.urandom(16)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=default_backend())
    enc = cipher.encryptor()
    t0 = now_ns()
    ct = enc.update(msg) + enc.finalize()
    hkey = os.urandom(32)
    h = hmac.HMAC(hkey, hashes.SHA256())
    h.update(ct); tag = h.finalize()
    hv = hmac.HMAC(hkey, hashes.SHA256())
    hv.update(ct); hv.verify(tag)
    ms = ns_to_ms(now_ns() - t0)
    return (ct, key, iv, None, tag, ms, "AES-CTR+HMAC", "128")
