import os
import random
import time
import xxhash
from multiprocessing import Pool, cpu_count

def read_file(path: str):
    with open(path, 'rb') as file:
        data = file.read()
    return data

def generate_bytes(num: int):
    random_bytes = os.urandom(num)
    return random_bytes

def create_hash_table(size: int):
    return {index: xxhash.xxh3_128_hexdigest(os.urandom(10)) for index in range(size)}

def find_hashes_parallel(args):
    i, random_bytes, data, hash_table = args
    chunk = random_bytes[i]
    counter = 0
    while True:
        hash_ = hash_table[counter]
        hash_2 = xxhash.xxh3_128_hexdigest(hash_ + chunk)
        if data[i] in hash_2:
            return (i, (hash_2.index(data[i]), hash_))
        counter += 1

def find_hashes(random_bytes: bytes, data: bytes):
    hash_table = create_hash_table(10)
    data = data.hex()
    random_bytes = random_bytes.hex()
    len_data = len(data)
    secret_list = [None] * len_data
    pool = Pool(2)
    results = pool.map(find_hashes_parallel, [(i, random_bytes, data, hash_table) for i in range(len_data)])
    pool.close()
    pool.join()
    for result in results:
        if result:
            i, value = result
            secret_list[i] = value
    if None in secret_list:
        print('Missing bytes!')

if __name__ == "__main__":
    data = read_file('data/10mb.pdf')
    len_data = len(data)
    start_total_time = time.time()
    random_bytes = generate_bytes(len_data)
    find_hashes(random_bytes, data)
    end_total_time = time.time()
    total_time = end_total_time - start_total_time
    data_size_MB = len_data / (1024 * 1024)  # Convert bytes to Megabytes
    throughput = data_size_MB / total_time
    print(f"Total time taken: {total_time} seconds")
    print(f"Throughput: {throughput} MB/s")
    print(f"File size: {data_size_MB} MB")
