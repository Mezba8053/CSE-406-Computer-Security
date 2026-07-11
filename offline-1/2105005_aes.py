import random

from aes_helpers import Sbox, InvSbox, Rcon, Mixer, InvMixer, gf_mult
import os
import time
import secrets
import hashlib

class aes:
    def __init__(self, key):
        random.seed(42)  
        encryption_time=0
        decryption_time=0
        if isinstance(key, str):
            key = key.encode('utf-8')
        
        if len(key)<=16:
            key=key+ b'\x00'*(16-len(key))
            self.number_of_key,self.number_of_round=4,10
        
        elif len(key)<=24:
            key=key+ b'\x00'*(24-len(key))
            self.number_of_key,self.number_of_round=6,12
        elif len(key)<=32:
            key=key+ b'\x00'*(32-len(key))
            self.number_of_key,self.number_of_round=8,14
        else:
            key=key[:32]
            self.number_of_key,self.number_of_round=8,14
        self.key_bytes_length=4*self.number_of_key
        self.key_in_words=self.key_to_words(key,self.number_of_key)
        # self.key=self.bytes_to_state(key)
        key_time=time.perf_counter()
        self.round_keys = self.key_expansion(self.key_in_words,self.number_of_key,self.number_of_round)
        kend=time.perf_counter()
        self.key_schedule_time=kend-key_time
    def key_to_words(self,key_bytes,nk):
        words=[]
        for c in range(nk):
            words.append([key_bytes[4*c + r] for r in range(4)])
        return words
    def bytes_to_state(self, block):
        return [[block[r + 4 * c] for c in range(4)] for r in range(4)]
    def state_to_bytes(self, state):
        out = bytearray(16)
        for r in range(4):
            for c in range(4):
                out[r + 4 * c] = state[r][c]
        return bytes(out)

    def key_expansion(self, key, nk, nr):
        w=[]
        for c in range(nk):
         w.append(list(key[c]))
          
        for i in range(nk, 4 * (nr + 1)):
            temp = list(w[i - 1])
            if i % nk == 0:
                temp = temp[1:] + temp[:1]
                for b in range(4):
                    temp[b] = Sbox[temp[b]]
    
                temp[0] ^= Rcon[i // nk]
            w.append([w[i - nk][j] ^ temp[j] for j in range(4)])

        round_keys = []
        for r in range(nr + 1):
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
        padding_len = 16 - (len(data) % 16)
        padding=[padding_len] * padding_len
        return data + bytes(padding)

    @staticmethod
    def pkcs7_unpad(data):
        if not data or len(data) % 16 != 0:
            raise ValueError("Invalid padded data")
        padding_length = data[-1]
        if padding_length < 1 or padding_length > 16:
            raise ValueError("Invalid PKCS#7 padding")
        if data[-padding_length:] != bytes([padding_length] * padding_length):
            raise ValueError("Invalid PKCS#7 padding ")
        return data[:-padding_length]

    def encrypt_ecb(self, plaintext):
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
        data = self.pkcs7_pad(plaintext)
        ciphertext = b''
        for i in range(0, len(data), 16):
            ciphertext += self.encrypt_block(data[i:i + 16])
        print(f"")
        return ciphertext

    def decrypt_ecb(self,ciphertext):
        plaintext = b''
        
        for i in range(0,len(ciphertext), 16):
            plaintext += self.decrypt_block(ciphertext[i:i + 16])
        print("Before Unpadding:")
        print(f"In Hex: {plaintext.hex()}")
        print(f"In ASCII: {plaintext.decode(errors='ignore')}")

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
        print("Before Unpadding:")
        print(f"In Hex: {plaintext.hex()}")
        print(f"In ASCII: {plaintext.decode(errors='ignore')}")

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



