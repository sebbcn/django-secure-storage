
from Crypto.Cipher import AES
from Crypto.Random.random import StrongRandom
import hashlib


def generate_random(nbytes):
    ''' returns nbytes-long random string '''
    return ''.join(chr(StrongRandom().randint(0, 0xFF)) for i in range(nbytes))


def new_cbc(key, salt=None):
    ''' initializes a AES cipher block chaining. '''
    if not salt:
        salt = generate_random(16)
    cipher = AES.new(key, AES.MODE_CBC, salt)
    return cipher, salt


def get_key(passphrase):
    ''' returns a 256-bits key based on passphrase '''
    h = hashlib.new('sha256')
    h.update(passphrase)
    return h.hexdigest()[:32]


def get_cipher_and_iv(passphrase, salt=None):
    ''' get cipher for a given passphrase and salt.  '''
    return new_cbc(get_key(passphrase), salt)


def padding(buff):
    ''' padding routine to make buffers size compatible with AES (16 bytes) '''
    PAD = '\x00'
    if len(buff) % 16 != 0:
        buff += PAD * (16 - len(buff) % 16)
    return buff


def encrypt_string(buff, passphrase, iv):
    ''' function for quick and dirty string encryption '''
    cipher = get_cipher_and_iv(passphrase, iv)[0]
    return cipher.encrypt(padding(buff))


def decrypt_string(buff, passphrase, iv):
    ''' function for quick and dirty string decryption '''
    cipher = get_cipher_and_iv(passphrase, iv)[0]
    return cipher.decrypt(buff).strip()
