import socket
import pickle
from dh import diffie_hellman, getkey_from_shared_secret
from aes import aes
from runner import runner
sock = socket.socket()
sock.connect(("localhost",5001))

p = diffie_hellman(0, 0).generate_prime_number(128)
dh = diffie_hellman(p, 2)

dh.p = p
dh.g = dh.generate_generator()

dh.generate_private_key(128)
dh.generate_public_key()

sock.sendall(
    pickle.dumps({
        "p":p,
        "g":dh.g,
        "A":dh.public_key
    })
)

reply = pickle.loads(sock.recv(4096))
print("Enter Message to send to Bob:")
message = input()

B = reply["B"]

shared = dh.compute_shared_secret(B)

aes_key = getkey_from_shared_secret(shared)

cipher = aes(aes_key)

ciphertext = cipher.encrypt_cbc(message)

sock.sendall(ciphertext)