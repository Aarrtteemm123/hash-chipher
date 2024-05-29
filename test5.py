import os
import random
import time
from typing import List

import lz4framed
import xxhash


def read_file(path: str):
    with open(path, 'rb') as file:
        data = file.read()
    return data


def write_file(data: bytes, path: str):
    with open(path, 'wb') as file:
        file.write(data)


def save_keys(secret_keys: List[str], public_key: str, compressed: bool):
    with open('secret_key.key', 'wb') as file:
        write_data = ('\n'.join(secret_keys) + f'\n{int(compressed)}').encode()
        file.write(write_data)
    with open('public_key.key', 'wb') as file:
        file.write(public_key.encode())


def decode(secret_keys: List[bytes], public_key: bytes):
    compressed = secret_keys[-1] == b'1'
    secret_keys.pop(-1)
    public_key_str = public_key.decode()

    hash_parts = [
        xxhash.xxh3_64_hexdigest(secret_key + public_key_str[index].encode())[0] for index, secret_key in
        enumerate(secret_keys)
    ]

    decode_msg = ''.join(hash_parts)

    if compressed:
        decode_msg = lz4framed.decompress(decode_msg)

    decode_msg = bytes.fromhex(decode_msg)
    return decode_msg


def code(data: bytes, compress=False):
    hex_list = ('0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f')
    hash_table = [None] * 256
    counter = 0

    for hex_ in hex_list:
        for hex_2 in hex_list:
            while True:
                hash_ = os.urandom(8).hex()    # get 8*2=16 str size
                hash_2 = xxhash.xxh3_64_hexdigest(hash_ + hex_2)
                if hash_2[0] == hex_:
                    hash_table[counter] = hash_
                    counter += 1
                    break

    if compress:
        data = lz4framed.compress(data)

    data = data.hex()
    len_data = len(data)
    max_hight_val = int(len_data * 2)
    min_hight_val = 1000
    max_min_len = int(len_data * 0.2)
    min_min_len = 100
    tail_max_len = max_hight_val if max_hight_val > min_hight_val else min_hight_val
    tail_min_len = max_min_len if max_min_len > min_min_len else min_min_len
    tail = random.randint(tail_min_len, tail_max_len)
    random_bytes = os.urandom(len_data + tail).hex()
    secret_list = [hash_table[int(data[i] + random_bytes[i], 16)] for i in range(len_data)]
    return secret_list, random_bytes


data = read_file('data/data.txt')
#data = b'Hello World!'
len_data = len(data)
start_total_time = time.time()
secret_key, public_key = code(data)
end_total_time = time.time()
total_time = end_total_time - start_total_time
data_size_MB = len_data / (1024 * 1024)  # Convert bytes to Megabytes
throughput = data_size_MB / total_time
# save_keys(secret_key, public_key, False)
# secret_key = read_file('secret_key.key').splitlines()
# public_key = read_file('public_key.key')
# st_decode = time.time()
# msg = decode(secret_key, public_key)
# end_decode = time.time()
# total_time_decode = end_decode - st_decode
# throughput_decode = data_size_MB / (total_time_decode + 0.0000000000000000000000001)
# write_file(msg, 'xx_2_decode.jpg')
# print('msg', msg)
print(f"Total time code taken: {total_time} seconds")
print(f"Throughput code: {throughput} MB/s")
# print(f"Total time decode taken: {total_time_decode} seconds")
# print(f"Throughput decode: {throughput_decode} MB/s")
print(f"File size: {data_size_MB} MB")