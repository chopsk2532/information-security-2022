from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64

def decode_base64(b64):
    return base64.b64decode(b64)

def encode_base64(p):
    return base64.b64encode(p).decode('ascii')

def read_from_base64():
    return [ decode_base64(input()), decode_base64(input()) ]

def encrypt_secret(secret, pubkey):
    priKey_rsa = RSA.import_key(pubkey)
    enc_sec = PKCS1_OAEP.new(priKey_rsa).encrypt(secret)
    result = encode_base64(enc_sec)
    return result
    # PKCS#1 OAEP를 이용한 RSA 암호화 구현

[secret, pubkey] = read_from_base64()
cipher_str = encrypt_secret(secret, pubkey)

print(cipher_str)