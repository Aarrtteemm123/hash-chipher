from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

class DESCipher:

    def encrypt(self, plain_bytes):
        key = get_random_bytes(8)
        cipher = DES.new(key, DES.MODE_CBC)
        iv = cipher.iv
        cipher_text = cipher.encrypt(pad(plain_bytes, DES.block_size))
        return iv + cipher_text, key

    def decrypt(self, cipher_text, key):
        iv = cipher_text[:DES.block_size]
        cipher = DES.new(key, DES.MODE_CBC, iv)
        decrypted_bytes = unpad(cipher.decrypt(cipher_text[DES.block_size:]), DES.block_size)
        return decrypted_bytes
