"""
GREENWIRE RSA Implementation
============================
RSA key generation, signing, verification, encryption, and decryption.
Uses built-in Python libraries where possible.
"""

import math, random
from typing import Optional, Tuple
from .primitives import GreenwireCryptoError, InvalidSignatureError, secure_random  # noqa: F401
from .hashes import hash_sha1, hash_sha256


class RSAKey:
    """GREENWIRE RSA Key class."""
    
    def __init__(self, n: int, e: int, d: Optional[int] = None, p: Optional[int] = None, q: Optional[int] = None):
        """Initialize RSA key with components."""
        self.n = n  # Modulus
        self.e = e  # Public exponent
        self.d = d  # Private exponent
        self.p = p  # First prime
        self.q = q  # Second prime
        
        if d is not None:
            self.is_private = True
        else:
            self.is_private = False
    
    def public_key(self):
        """Get the public key component."""
        return RSAKey(self.n, self.e)
    
    def key_size(self) -> int:
        """Get key size in bits."""
        return self.n.bit_length()
    
    def to_pem_public(self) -> str:
        """Convert to PEM format (simplified)."""
        return f"-----BEGIN GREENWIRE RSA PUBLIC KEY-----\nn={hex(self.n)}\ne={hex(self.e)}\n-----END GREENWIRE RSA PUBLIC KEY-----"
    
    def to_pem_private(self) -> str:
        """Convert to PEM format (simplified)."""
        if not self.is_private:
            raise ValueError("Cannot export private key from public key")
        return f"-----BEGIN GREENWIRE RSA PRIVATE KEY-----\nn={hex(self.n)}\ne={hex(self.e)}\nd={hex(self.d)}\n-----END GREENWIRE RSA PRIVATE KEY-----"


def _miller_rabin(n: int, k: int = 5) -> bool:
    """Miller-Rabin primality test."""
    if n < 2:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False
    
    # Write n-1 as d * 2^r
    r = 0
    d = n - 1
    while d % 2 == 0:
        d //= 2
        r += 1
    
    # Perform k rounds of testing
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        
        if x == 1 or x == n - 1:
            continue
        
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    
    return True


def _generate_prime(bits: int) -> int:
    """Generate a prime number with specified bit length."""
    while True:
        # Generate random odd number
        candidate = random.getrandbits(bits)
        candidate |= (1 << bits - 1) | 1  # Set MSB and LSB
        
        # Simple trial division for small primes
        small_primes = [3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47]
        is_composite = False
        for prime in small_primes:
            if candidate % prime == 0 and candidate != prime:
                is_composite = True
                break
        
        if not is_composite and _miller_rabin(candidate):
            return candidate


def _extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
    """Extended Euclidean algorithm."""
    if a == 0:
        return b, 0, 1
    gcd, x1, y1 = _extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd, x, y


def _mod_inverse(a: int, m: int) -> int:
    """Compute modular inverse of a mod m."""
    gcd, x, _ = _extended_gcd(a % m, m)
    if gcd != 1:
        raise ValueError("Modular inverse does not exist")
    return x % m


def generate_rsa_keypair(key_size: int = 2048) -> RSAKey:
    """Generate an RSA key pair."""
    if key_size < 512:
        raise ValueError("RSA key size must be at least 512 bits")
    
    # Generate two distinct primes
    p_bits = key_size // 2
    q_bits = key_size - p_bits
    
    while True:
        p = _generate_prime(p_bits)
        q = _generate_prime(q_bits)
        
        if p != q and abs(p - q) > (1 << (key_size // 2 - 100)):
            break
    
    n = p * q
    phi = (p - 1) * (q - 1)
    
    # Choose public exponent
    e = 65537
    if math.gcd(e, phi) != 1:
        e = 3
        while math.gcd(e, phi) != 1:
            e += 2
    
    # Compute private exponent
    d = _mod_inverse(e, phi)
    
    return RSAKey(n, e, d, p, q)


def _pkcs1_pad(message: bytes, key_size: int, block_type: int = 2) -> bytes:
    """PKCS#1 v1.5 padding."""
    if len(message) > key_size - 11:
        raise ValueError("Message too long for key size")
    
    pad_length = key_size - 3 - len(message)
    
    if block_type == 1:
        # Signing
        padding = b'\xff' * pad_length
    else:
        # Encryption
        padding = secure_random(pad_length)
        # Ensure no zero bytes in padding
        padding = bytes(b if b != 0 else 1 for b in padding)
    
    return b'\x00' + bytes([block_type]) + padding + b'\x00' + message


def _pkcs1_unpad(padded_message: bytes, block_type: int = 2) -> bytes:
    """Remove PKCS#1 v1.5 padding."""
    if len(padded_message) < 11:
        raise ValueError("Invalid padded message")
    
    if padded_message[0] != 0:
        raise ValueError("Invalid padding: first byte must be 0")
    
    if padded_message[1] != block_type:
        raise ValueError(f"Invalid padding: expected block type {block_type}")
    
    # Find the separator (0x00)
    try:
        separator_idx = padded_message.index(0, 2)
    except ValueError:
        raise ValueError("Invalid padding: no separator found")
    
    return padded_message[separator_idx + 1:]


def rsa_encrypt(public_key: RSAKey, plaintext: bytes) -> bytes:
    """Encrypt data with RSA public key."""
    key_bytes = (public_key.n.bit_length() + 7) // 8
    
    if len(plaintext) > key_bytes - 11:
        raise ValueError("Plaintext too long for key size")
    
    padded = _pkcs1_pad(plaintext, key_bytes, 2)
    m = int.from_bytes(padded, 'big')
    c = pow(m, public_key.e, public_key.n)
    
    return c.to_bytes(key_bytes, 'big')


def rsa_decrypt(private_key: RSAKey, ciphertext: bytes) -> bytes:
    """Decrypt data with RSA private key."""
    if not private_key.is_private:
        raise ValueError("Private key required for decryption")
    
    key_bytes = (private_key.n.bit_length() + 7) // 8
    
    if len(ciphertext) != key_bytes:
        raise ValueError("Invalid ciphertext length")
    
    c = int.from_bytes(ciphertext, 'big')
    m = pow(c, private_key.d, private_key.n)
    padded = m.to_bytes(key_bytes, 'big')
    
    return _pkcs1_unpad(padded, 2)


def rsa_sign(private_key: RSAKey, message: bytes, hash_func='sha256') -> bytes:
    """Sign message with RSA private key."""
    if not private_key.is_private:
        raise ValueError("Private key required for signing")
    
    # Hash the message
    if hash_func == 'sha256':
        digest = hash_sha256(message)
        # DigestInfo for SHA-256
        digest_info = b'\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20' + digest
    elif hash_func == 'sha1':
        digest = hash_sha1(message)
        # DigestInfo for SHA-1
        digest_info = b'\x30\x21\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00\x04\x14' + digest
    else:
        raise ValueError(f"Unsupported hash function: {hash_func}")
    
    key_bytes = (private_key.n.bit_length() + 7) // 8
    padded = _pkcs1_pad(digest_info, key_bytes, 1)
    m = int.from_bytes(padded, 'big')
    s = pow(m, private_key.d, private_key.n)
    
    return s.to_bytes(key_bytes, 'big')


def rsa_verify(public_key: RSAKey, signature: bytes, message: bytes, hash_func='sha256') -> bool:
    """Verify RSA signature."""
    try:
        key_bytes = (public_key.n.bit_length() + 7) // 8
        
        if len(signature) != key_bytes:
            return False
        
        s = int.from_bytes(signature, 'big')
        m = pow(s, public_key.e, public_key.n)
        padded = m.to_bytes(key_bytes, 'big')
        
        digest_info = _pkcs1_unpad(padded, 1)
        
        # Verify digest
        if hash_func == 'sha256':
            expected_digest = hash_sha256(message)
            expected_prefix = b'\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20'
        elif hash_func == 'sha1':
            expected_digest = hash_sha1(message)
            expected_prefix = b'\x30\x21\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00\x04\x14'
        else:
            return False
        
        if not digest_info.startswith(expected_prefix):
            return False
        
        actual_digest = digest_info[len(expected_prefix):]
        return actual_digest == expected_digest
        
    except Exception:
        return False