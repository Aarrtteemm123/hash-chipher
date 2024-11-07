import time
from aes import AESCipher
from des import DESCipher
from hash_cipher_v1 import HashCipherV1


def read_file(path: str) -> bytes:
    with open(path, 'rb') as file:
        data = file.read()
    return data

def save_file(path: str, data) -> bytes:
    with open(path, 'wb') as file:
        file.write(data)


def benchmark(func, data, info_msg, *args, **kwargs):
    len_data = len(data)
    start_time = time.time()
    res = func(*args, **kwargs)
    end_time = time.time()
    total_time = end_time - start_time
    data_size_MB = len_data / (1024 * 1024)  # Convert bytes to Megabytes
    throughput = data_size_MB / total_time if total_time else float('inf')
    print(f'---------------{info_msg}---------------')
    print(f"Total time taken: {total_time} seconds")
    print(f"Throughput: {throughput} MB/s")
    print(f"File size: {data_size_MB} MB\n")
    return res


#data = read_file('data')
data = b'Hello World' * 500_000

hash_cipher = HashCipherV1()
secret_key, public_key = benchmark(hash_cipher.encrypt, data, 'HashCipher code (compress=False)', data)
hash_cipher.save_keys(secret_key, public_key)
secret_key, public_key = hash_cipher.load_keys('secret_key_v1.key', 'public_key_v1.key').values()
msg = benchmark(hash_cipher.decrypt, secret_key, 'HashCipher decode (compress=False)', secret_key, public_key)

secret_key, public_key = benchmark(hash_cipher.encrypt, data, 'HashCipher code (compress=True)', data, True)
hash_cipher.save_keys(secret_key, public_key, True)
secret_key, public_key = hash_cipher.load_keys('secret_key_v1.key', 'public_key_v1.key').values()
msg = benchmark(hash_cipher.decrypt, secret_key, 'HashCipher decode (compress=True)', secret_key, public_key)

aes_cipher = AESCipher()
cipher_text, key = benchmark(aes_cipher.encrypt, data, 'AES code', data)
msg = benchmark(aes_cipher.decrypt, cipher_text, 'AES decode', cipher_text, key)

des_cipher = DESCipher()
cipher_text, key = benchmark(des_cipher.encrypt, data, 'DES code', data)
msg = benchmark(des_cipher.decrypt, cipher_text, 'DES decode', cipher_text, key)
