from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

class AESCipher:
    def encrypt(self, plain_bytes):
        key = get_random_bytes(32)
        cipher = AES.new(key, AES.MODE_CBC)
        iv = cipher.iv
        cipher_text = cipher.encrypt(pad(plain_bytes, AES.block_size))
        return iv + cipher_text, key

    def decrypt(self, cipher_text, key):
        iv = cipher_text[:AES.block_size]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_bytes = unpad(cipher.decrypt(cipher_text[AES.block_size:]), AES.block_size)
        return decrypted_bytes
