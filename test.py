import base64
import hashlib

import xxhash

import time

def find_k(target_prefix):
    k = 0  # Start with k = 0
    while True:
        xxhash_hash = xxhash.xxh64_digest(str(k))
        base85_hash = base64.b85encode(xxhash_hash).decode('utf-8')
        print(base85_hash)
        if base85_hash.startswith(target_prefix):
            return k, base85_hash
        k += 1


if __name__ == "__main__":
    target_prefix = "t"  # Desired hash prefix

    start_time = time.time()  # Record the start time
    k, base85_hash = find_k(target_prefix)
    end_time = time.time()  # Record the end time

    execution_time = end_time - start_time
    print(f"Found k: {k}, Hash of the string: {base85_hash}")
    print(f"Execution time: {execution_time} seconds")
    # Size of k: sys.getsizeof(k) is no longer necessary as it's not a relevant metric in this context
