import random

from aes_helpers import Sbox, InvSbox, Rcon, Mixer, InvMixer, gf_mult
import os
import time
# from Crypto.Util.number import getPrime
import secrets
import hashlib

class aes:
    def __init__(self, key):
        random.seed(42)  # For reproducibility in testing
        if isinstance(key, str):
            key = key.encode('utf-8')
        if len(key) < 16:
            key = key + b'\x00' * (16 - len(key))
        elif len(key) > 16:
            key = key[:16]
        self.key = [[key[r + 4 * c] for c in range(4)] for r in range(4)]
        self.round_keys = self.key_expansion(self.key)
    def bytes_to_state(self, block):
        return [[block[r + 4 * c] for c in range(4)] for r in range(4)]
    def state_to_bytes(self, state):
        out = bytearray(16)
        for r in range(4):
            for c in range(4):
                out[r + 4 * c] = state[r][c]
        return bytes(out)

    def key_expansion(self, key):
        w=[]
        for c in range(4):
         w.append([key[r][c] for r in range(4)])
          
        for i in range(4, 44):
            temp = list(w[i - 1])
            if i % 4 == 0:
                temp = temp[1:] + temp[:1]
                for b in range(4):
                    temp[b] = Sbox[temp[b]]
    
                temp[0] ^= Rcon[i // 4]
            w.append([w[i - 4][j] ^ temp[j] for j in range(4)])

        round_keys = []
        for r in range(11):
            words=w[r * 4:(r + 1) * 4]
            round=[[words[c][r] for c in range(4)] for r in range(4)]
            round_keys.append(round)
        return round_keys

    
   
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
                    gf_mult(Mixer[r][0], col[0])^ gf_mult(Mixer[r][1], col[1])^ gf_mult(Mixer[r][2], col[2]) ^ gf_mult(Mixer[r][3], col[3])
                )
        return state

    def inv_mix_columns(self, state):
        for c in range(4):
            col = [state[r][c] for r in range(4)]
            for r in range(4):
                state[r][c] = (
                    gf_mult(InvMixer[r][0], col[0]) ^ gf_mult(InvMixer[r][1], col[1])^ gf_mult(InvMixer[r][2], col[2])^ gf_mult(InvMixer[r][3], col[3])
                )
        return state

    def add_round_key(self, state, round_key):
        for i in range(4):
            for j in range(4):
                state[i][j] ^= round_key[i][j]
        return state

    def encrypt_block(self, block):
        state = self.bytes_to_state(block)
        state = self.add_round_key(state, self.round_keys[0])
        for rnd in range(1, 10):
            state = self.substitute_bytes(state)
            state = self.shift_rows(state)
            state = self.mix_columns(state)
            state = self.add_round_key(state, self.round_keys[rnd])
        state = self.substitute_bytes(state)
        state = self.shift_rows(state)
        state = self.add_round_key(state, self.round_keys[10])
        return self.state_to_bytes(state)
    
    def decrypt_block(self, block):
        state = self.bytes_to_state(block)
        state = self.add_round_key(state, self.round_keys[10])
        for rnd in range(9, 0, -1):
            state = self.inv_shift_rows(state)
            state = self.inv_substitute_bytes(state)
            state = self.add_round_key(state, self.round_keys[rnd])
            state = self.inv_mix_columns(state)
        state = self.inv_shift_rows(state)
        state = self.inv_substitute_bytes(state)
        state = self.add_round_key(state, self.round_keys[0])
        return self.state_to_bytes(state)
    @staticmethod
    def pkcs7_pad(data):
        pad_len = 16 - (len(data) % 16)
        padding=[pad_len] * pad_len
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



