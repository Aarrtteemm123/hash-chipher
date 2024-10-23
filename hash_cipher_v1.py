import os
import random
from typing import List, Dict, Tuple
import lz4framed
import xxhash


class HashCipherV1:
    def encrypt(self, data: bytes, compress: bool = True, random_bytes: bytes = None) -> Tuple[List[str], str]:
        hex_list = ('0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f')
        hash_table = [None] * 256
        counter = 0

        for hex_ in hex_list:
            for hex_2 in hex_list:
                while True:
                    hash_ = os.urandom(8).hex()  # get 8*2=16 str size
                    hash_2 = xxhash.xxh3_64_hexdigest(hash_ + hex_2)
                    if hash_2[0] == hex_:
                        hash_table[counter] = hash_
                        counter += 1
                        break

        if compress:
            data = lz4framed.compress(data)

        data = data.hex()
        len_data = len(data)
        random_bytes = random_bytes.hex() if random_bytes else None
        if random_bytes and len(random_bytes) < len_data:
            raise Exception('Array of random bytes is shorter than the original data')

        if not random_bytes:
            max_hight_val = int(len_data * 2)
            min_hight_val = 1000
            max_min_len = int(len_data * 0.1)
            min_min_len = 100
            tail_max_len = max_hight_val if max_hight_val > min_hight_val else min_hight_val
            tail_min_len = max_min_len if max_min_len > min_min_len else min_min_len
            tail = random.randint(tail_min_len, tail_max_len)
            random_bytes = os.urandom(len_data + tail).hex()
        hex_decimal_dict = {'0' + hex(i)[2:] if i < 16 else hex(i)[2:]: i for i in range(256)}
        secret_list = [hash_table[hex_decimal_dict[data[i] + random_bytes[i]]] for i in range(len_data)]
        return secret_list, random_bytes

    def decrypt(self, secret_keys: List[bytes], public_key: bytes) -> bytes:
        compressed = secret_keys[-1] == b'1'
        secret_keys.pop(-1)
        public_key_str = public_key.decode()

        hash_parts = [
            xxhash.xxh3_64_hexdigest(secret_key + public_key_str[index].encode())[0] for index, secret_key in
            enumerate(secret_keys)
        ]

        decode_msg = ''.join(hash_parts)
        decode_msg = bytes.fromhex(decode_msg)

        if compressed:
            decode_msg = lz4framed.decompress(decode_msg)

        return decode_msg

    def save_keys(self, secret_keys: List[str] = None, public_key: str = None, compressed: bool = False,
                  filename_secret_key: str = 'secret_key_v1.key',
                  filename_public_key: str = 'public_key_v1.key'):

        if secret_keys:
            write_data = ('\n'.join(secret_keys) + f'\n{int(compressed)}').encode()
            self._save_file(write_data, filename_secret_key)
        if public_key:
            self._save_file(public_key.encode(), filename_public_key)

    def load_keys(self, filename_secret_key: str = None, filename_public_key: str = None) -> Dict[str, bytes]:
        keys = {}
        if filename_secret_key:
            secret_key = self._read_file(filename_secret_key).splitlines()
            keys['secret_key'] = secret_key
        if filename_public_key:
            public_key = self._read_file(filename_public_key)
            keys['public_key'] = public_key

        return keys

    def _read_file(self, path: str) -> bytes:
        with open(path, 'rb') as file:
            data = file.read()
        return data

    def _save_file(self, data: bytes, path: str):
        with open(path, 'wb') as file:
            file.write(data)
