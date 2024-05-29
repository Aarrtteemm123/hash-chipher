import os
import time
import xxhash
import threading

def read_file(path: str):
    with open(path, 'rb') as file:
        data = file.read()
    return data

def generate_bytes(num: int):
    random_bytes = os.urandom(num)
    return random_bytes

def create_hash_table(size: int):
    return {index: xxhash.xxh3_64_hexdigest(str(index)) for index in range(size)}

def find_hashes_chunk(chunk_start, chunk_end, random_bytes, data, hash_table, results):
    data_hex = data.hex()
    random_bytes_hex = random_bytes.hex()
    for i in range(chunk_start, chunk_end):
        chunk = random_bytes_hex[i]
        for counter in range(len(hash_table)):
            hash_ = hash_table[counter]
            hash_2 = xxhash.xxh3_64_hexdigest(hash_ + chunk)
            if data_hex[i] in hash_2:
                results[i] = (hash_2.index(data_hex[i]), hash_)
                break

def main():
    data = read_file('data/10mb.pdf')
    random_bytes = generate_bytes(len(data))
    hash_table = create_hash_table(10)
    num_threads = 2  # Adjust the number of threads as needed

    chunk_size = len(data) // num_threads
    threads = []
    results = [None] * len(data)

    start_total_time = time.time()

    for i in range(num_threads):
        chunk_start = i * chunk_size
        chunk_end = (i + 1) * chunk_size if i < num_threads - 1 else len(data)
        thread = threading.Thread(target=find_hashes_chunk, args=(chunk_start, chunk_end, random_bytes, data, hash_table, results))
        thread.start()
        threads.append(thread)

    for thread in threads:
        thread.join()

    end_total_time = time.time()
    if None in results:
        print('Missing bytes!')

    print(f"Total time taken: {end_total_time - start_total_time} seconds")

if __name__ == "__main__":
    main()
