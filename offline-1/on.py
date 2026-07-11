import os
import time

from aes_helpers import Sbox, InvSbox, Rcon, Mixer, InvMixer, gf_mult


class aes:
    """
    AES implementation supporting 128-, 192-, and 256-bit keys (AES-128/192/256).

    Key size determines:
        Nk (key length in 32-bit words): 4, 6, or 8
        Nr (number of rounds):           10, 12, or 14
    Nb (block size in words) is always 4 for AES.
    """

    def __init__(self, key):
        encryption_time = 0
        decryption_time = 0
        if isinstance(key, str):
            key = key.encode('utf-8')

        # --- Generalized key-size handling ---
        # Snap the given key to the nearest valid AES key size (16/24/32 bytes),
        # padding with zero bytes if it's shorter, truncating if longer.
        if len(key) <= 16:
            key = key + b'\x00' * (16 - len(key))
            self.Nk, self.Nr = 4, 10
        elif len(key) <= 24:
            key = key + b'\x00' * (24 - len(key))
            self.Nk, self.Nr = 6, 12
        elif len(key) <= 32:
            key = key + b'\x00' * (32 - len(key))
            self.Nk, self.Nr = 8, 14
        else:
            key = key[:32]
            self.Nk, self.Nr = 8, 14

        self.Nb = 4
        self.key_bytes_len = 4 * self.Nk

        self.key = self.key_to_words(key, self.Nk)
        key_time = time.perf_counter()
        self.round_keys = self.key_expansion(self.key, self.Nk, self.Nr)
        kend = time.perf_counter()
        self.key_schedule_time = kend - key_time

    # ---------- state / word conversions ----------

    def bytes_to_state(self, block):
        return [[block[r + 4 * c] for c in range(4)] for r in range(4)]

    def state_to_bytes(self, state):
        out = bytearray(16)
        for r in range(4):
            for c in range(4):
                out[r + 4 * c] = state[r][c]
        return bytes(out)

    def key_to_words(self, key_bytes, Nk):
        """Split key bytes into Nk 'words', each a column of 4 bytes (row-major)."""
        return [[key_bytes[r + 4 * c] for r in range(4)] for c in range(Nk)]

    # ---------- key schedule (generalized for Nk / Nr) ----------

    def key_expansion(self, key_words, Nk, Nr):
        Nb = self.Nb
        w = [list(word) for word in key_words]  # first Nk words come straight from the key

        total_words = Nb * (Nr + 1)
        for i in range(Nk, total_words):
            temp = list(w[i - 1])

            if i % Nk == 0:
                # RotWord + SubWord + Rcon
                temp = temp[1:] + temp[:1]
                for b in range(4):
                    temp[b] = Sbox[temp[b]]
                temp[0] ^= Rcon[i // Nk]
            elif Nk > 6 and i % Nk == 4:
                # Extra SubWord step, only needed for AES-256 (Nk == 8)
                for b in range(4):
                    temp[b] = Sbox[temp[b]]

            w.append([w[i - Nk][j] ^ temp[j] for j in range(4)])

        round_keys = []
        for rnd in range(Nr + 1):
            words = w[rnd * Nb:(rnd + 1) * Nb]
            round_key = [[words[c][row] for c in range(Nb)] for row in range(4)]
            round_keys.append(round_key)
        return round_keys

    # ---------- round transformations (unchanged, block size is always 16 bytes) ----------

    def substitute_bytes(self, state):
        for i in range(4):
            for j in range(4):
                state[i][j] = Sbox[state[i][j]]
        return state

    def inv_substitute_bytes(self, state):
        for i in range(4):
            for j in range(4):
                state[i][j] = InvSbox[state[i][j]]
        return state

    def shift_rows(self, state):
        state[1][0], state[1][1], state[1][2], state[1][3] = state[1][1], state[1][2], state[1][3], state[1][0]
        state[2][0], state[2][1], state[2][2], state[2][3] = state[2][2], state[2][3], state[2][0], state[2][1]
        state[3][0], state[3][1], state[3][2], state[3][3] = state[3][3], state[3][0], state[3][1], state[3][2]
        return state

    def inv_shift_rows(self, state):
        state[1][0], state[1][1], state[1][2], state[1][3] = state[1][3], state[1][0], state[1][1], state[1][2]
        state[2][0], state[2][1], state[2][2], state[2][3] = state[2][2], state[2][3], state[2][0], state[2][1]
        state[3][0], state[3][1], state[3][2], state[3][3] = state[3][1], state[3][2], state[3][3], state[3][0]
        return state

    def mix_columns(self, state):
        for c in range(4):
            col = [state[r][c] for r in range(4)]
            for r in range(4):
                state[r][c] = (
                    gf_mult(Mixer[r][0], col[0]) ^ gf_mult(Mixer[r][1], col[1]) ^
                    gf_mult(Mixer[r][2], col[2]) ^ gf_mult(Mixer[r][3], col[3])
                )
        return state

    def inv_mix_columns(self, state):
        for c in range(4):
            col = [state[r][c] for r in range(4)]
            for r in range(4):
                state[r][c] = (
                    gf_mult(InvMixer[r][0], col[0]) ^ gf_mult(InvMixer[r][1], col[1]) ^
                    gf_mult(InvMixer[r][2], col[2]) ^ gf_mult(InvMixer[r][3], col[3])
                )
        return state

    def add_round_key(self, state, round_key):
        for i in range(4):
            for j in range(4):
                state[i][j] ^= round_key[i][j]
        return state

    # ---------- block encrypt/decrypt (now driven by self.Nr) ----------

    def encrypt_block(self, block):
        state = self.bytes_to_state(block)
        state = self.add_round_key(state, self.round_keys[0])
        for rnd in range(1, self.Nr):
            state = self.substitute_bytes(state)
            state = self.shift_rows(state)
            state = self.mix_columns(state)
            state = self.add_round_key(state, self.round_keys[rnd])
        state = self.substitute_bytes(state)
        state = self.shift_rows(state)
        state = self.add_round_key(state, self.round_keys[self.Nr])
        return self.state_to_bytes(state)

    def decrypt_block(self, block):
        state = self.bytes_to_state(block)
        state = self.add_round_key(state, self.round_keys[self.Nr])
        for rnd in range(self.Nr - 1, 0, -1):
            state = self.inv_shift_rows(state)
            state = self.inv_substitute_bytes(state)
            state = self.add_round_key(state, self.round_keys[rnd])
            state = self.inv_mix_columns(state)
        state = self.inv_shift_rows(state)
        state = self.inv_substitute_bytes(state)
        state = self.add_round_key(state, self.round_keys[0])
        return self.state_to_bytes(state)

    # ---------- padding ----------

    @staticmethod
    def pkcs7_pad(data):
        pad_len = 16 - (len(data) % 16)
        padding = [pad_len] * pad_len
        return data + bytes(padding)

    @staticmethod
    def pkcs7_unpad(data):
        if not data or len(data) % 16 != 0:
            raise ValueError("Invalid padded data length")
        pad_len = data[-1]
        if pad_len < 1 or pad_len > 16:
            raise ValueError("Invalid PKCS#7 padding")
        if data[-pad_len:] != bytes([pad_len] * pad_len):
            raise ValueError("Invalid PKCS#7 padding bytes")
        return data[:-pad_len]

    # ---------- modes ----------

    def encrypt_ecb(self, plaintext):
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
        data = self.pkcs7_pad(plaintext)
        ciphertext = b''
        for i in range(0, len(data), 16):
            ciphertext += self.encrypt_block(data[i:i + 16])
        return ciphertext

    def decrypt_ecb(self, ciphertext):
        plaintext = b''
        for i in range(0, len(ciphertext), 16):
            plaintext += self.decrypt_block(ciphertext[i:i + 16])
        return self.pkcs7_unpad(plaintext)

    def encrypt_cbc(self, plaintext, iv=None):
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
        if iv is None:
            iv = os.urandom(16)
        data = self.pkcs7_pad(plaintext)
        ciphertext = iv
        prev = iv
        for i in range(0, len(data), 16):
            block = bytes(a ^ b for a, b in zip(data[i:i + 16], prev))
            enc = self.encrypt_block(block)
            ciphertext += enc
            prev = enc
        return ciphertext

    def decrypt_cbc(self, ciphertext):
        iv = ciphertext[:16]
        ciphertext = ciphertext[16:]
        plaintext = b''
        prev = iv
        for i in range(0, len(ciphertext), 16):
            block = ciphertext[i:i + 16]
            dec = self.decrypt_block(block)
            plaintext += bytes(a ^ b for a, b in zip(dec, prev))
            prev = block
        return self.pkcs7_unpad(plaintext)

    def get_key_expansion_time(self):
        return self.key_schedule_time

    def encrypt(self, plaintext, mode='ECB'):
        if mode.upper() == 'ECB':
            return self.encrypt_ecb(plaintext)
        elif mode.upper() == 'CBC':
            return self.encrypt_cbc(plaintext)
        else:
            raise ValueError("Unsupported mode: " + str(mode))

    def decrypt(self, ciphertext, mode='ECB'):
        if mode.upper() == 'ECB':
            return self.decrypt_ecb(ciphertext)
        elif mode.upper() == 'CBC':
            return self.decrypt_cbc(ciphertext)
        else:
            raise ValueError("Unsupported mode: " + str(mode))


if __name__ == "__main__":
    # Quick sanity check across all three key sizes
    for keylen, label in [(16, "AES-128"), (24, "AES-192"), (32, "AES-256")]:
        key = os.urandom(keylen)
        cipher = aes(key)
        msg = b"Testing variable-length AES key schedules!"
        for mode in ("ECB", "CBC"):
            ct = cipher.encrypt(msg, mode=mode)
            pt = cipher.decrypt(ct, mode=mode)
            assert pt == msg, f"{label} {mode} round-trip failed"
        print(f"{label}: Nk={cipher.Nk}, Nr={cipher.Nr} -> OK")