import time
import random
import secrets
import hashlib
class diffie_hellman:
    def __init__(self, p: int, g: int):
        self.p = p
        self.g = g
        self.private_key = None
        self.public_key = None
        random.seed(42) 
    def is_prime(self, n, k=40):
        if n <= 1:
            return False
        if n <= 3:
            return True
        if n % 2 == 0:
            return False
        r, d = 0, n - 1
        while d % 2 == 0:
            d //= 2
            r += 1
        for _ in range(k):
            a = random.randint(2, n - 2)
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
    def generate_prime_number(self,key_size):

        if key_size not in [128, 192, 256]:
            raise ValueError("Key size must be exactly 128, 192, or 256 bits.")
        while True:
            candidate = secrets.randbits(key_size) | (1 << (key_size - 1)) | 1
            if self.is_prime(candidate):
                return candidate
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
        return pow(other_public_key, self.private_key, self.p)
def getkey_from_shared_secret(shared_secret):
    shared_secret_bytes = shared_secret.to_bytes((shared_secret.bit_length() + 7) // 8, byteorder='big')
    key = hashlib.sha256(shared_secret_bytes).digest()[:16]
    return key

