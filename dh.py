import time
import random
import secrets
import hashlib

# Try to import getPrime from PyCryptodome; if unavailable, provide a local implementation.
try:
    from Crypto.Util.number import getPrime
except Exception:
    # Miller-Rabin primality test
    def is_probable_prime(n, k=8):
        if n < 2:
            return False
        small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29]
        for p in small_primes:
            if n % p == 0:
                return n == p
        d = n - 1
        s = 0
        while d % 2 == 0:
            d //= 2
            s += 1
        import random as _random
        for _ in range(k):
            a = _random.randrange(2, n - 1)
            x = pow(a, d, n)
            if x == 1 or x == n - 1:
                continue
            for __ in range(s - 1):
                x = (x * x) % n
                if x == n - 1:
                    break
            else:
                return False
        return True

    def getPrime(bits):
        if bits < 2:
            raise ValueError("bits must be >= 2")
        while True:
            # ensure top bit and odd
            candidate = secrets.randbits(bits) | (1 << (bits - 1)) | 1
            if is_probable_prime(candidate):
                return candidate
class diffie_hellman:
    def __init__(self, p: int, g: int):
        self.p = p
        self.g = g
        self.private_key = None
        self.public_key = None
        # random.seed(42) 
    def generate_prime_number(self,key_size):
        if key_size not in [128, 192, 256]:
            raise ValueError("Key size must be exactly 128, 192, or 256 bits.")

        prime = getPrime(key_size)
        return prime
    def generate_generator(self):
        
        while True:
            g = random.randint(2, self.p - 1)
            if pow(g, (self.p - 1) // 2, self.p) != 1: 
                return g
    def generate_private_key(self, key_size):
        while True:
            private = secrets.randbits(key_size)
            if private.bit_length() >= key_size:
                self.private_key = private
                return
    def generate_public_key(self):
        if self.private_key is None:
            raise ValueError("Private key not generated yet.")
        self.public_key = pow(self.g, self.private_key, self.p)

    def compute_shared_secret(self, other_public_key):
        if self.private_key is None:
            raise ValueError("Private key not generated yet.")
        return pow(other_public_key, self.private_key)%self.p
def getkey_from_shared_secret(shared_secret):
    shared_secret_bytes = shared_secret.to_bytes((shared_secret.bit_length() + 7) // 8, byteorder='big')
    key = hashlib.sha256(shared_secret_bytes).digest()[:16]
    return key

