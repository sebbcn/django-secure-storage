
from Crypto.Cipher import AES
from Crypto.Random.random import StrongRandom
import hashlib


def generate_random(nbytes):
    ''' return nbytes-long random string '''
    return ''.join(chr(StrongRandom().randint(0, 0xFF)) for i in range(nbytes))


def new_cbc(passphrase, iv=None):
    ''' cipher block chaining. '''
    if not iv:
        iv = generate_random(16)

    cipher = AES.new(passphrase, AES.MODE_CBC, iv)
    return cipher, iv


def get_key(passphrase):

    h = hashlib.new('sha512')
    h.update(passphrase)
    return h.hexdigest()[32:64]


def get_cipher_and_iv(passphrase, iv=None):

    return new_cbc(get_key(passphrase), iv)


PAD = '\x00'

def padding(buff):
    ''' padding routine to make buffers size compatible with AES (16 bytes) '''
    if len(buff) % 16 != 0:
        buff += PAD * (16 - len(buff) % 16)
    return buff


def encrypt_string(buff, passphrase, iv):

    cipher = get_cipher_and_iv(passphrase, iv)[0]
    return cipher.encrypt(padding(buff))


def decrypt_string(buff, passphrase, iv):

    cipher = get_cipher_and_iv(passphrase, iv)[0]
    return cipher.decrypt(buff).strip()
