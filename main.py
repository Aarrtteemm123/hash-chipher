import time

from hash_cipher_v1 import HashCipherV1


def read_file(path: str) -> bytes:
    with open(path, 'rb') as file:
        data = file.read()
    return data


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


data = read_file('data/dummy-500-kb-example-png-file.png')
hash_cipher = HashCipherV1()
# data = b'Hello World!'
secret_key, public_key = benchmark(hash_cipher.code, data, 'code v1', data)
hash_cipher.save_keys(secret_key, public_key)
secret_key, public_key = hash_cipher.load_keys('secret_key_v1.key', 'public_key_v1.key').values()
msg = benchmark(hash_cipher.decode, secret_key, 'decode v1', secret_key, public_key)
