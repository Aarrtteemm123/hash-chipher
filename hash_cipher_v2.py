import hashlib
from typing import List, Dict


class HashCipherV2:
    def __init__(self, secret_seed: bytes):
        self.initial_key = hashlib.sha256(secret_seed).digest()

    def encrypt(self, data: bytes) -> List[int]:
        encrypted_salts = []
        current_key = self.initial_key

        for single_byte in data:
            salt, current_key = self._encrypt_byte(single_byte, current_key)
            encrypted_salts.append(salt)

        return encrypted_salts

    def decrypt(self, salts: List[int]) -> bytes:
        decrypted_bytes = bytearray()
        current_key = self.initial_key

        for salt in salts:
            single_byte, current_key = self._decrypt_byte(salt, current_key)
            decrypted_bytes.append(single_byte)

        return bytes(decrypted_bytes)

    def save_keys(
        self,
        salts: List[int] = None,
        filename_secret_key: str = "secret_key_v2.key",
    ):
        if salts is not None:
            payload = "\n".join(map(str, salts)).encode()
            self._save_file(payload, filename_secret_key)

    def load_keys(self, filename_secret_key: str = None) -> Dict[str, List[int]]:
        keys = {}
        if filename_secret_key:
            salts_raw = self._read_file(filename_secret_key).decode().splitlines()
            keys["secret_key"] = [int(salt) for salt in salts_raw if salt]

        return keys

    def _get_next_key(self, current_key: bytes) -> bytes:
        return hashlib.sha256(current_key).digest()

    def _encrypt_byte(self, single_byte: int, current_key: bytes) -> tuple[int, bytes]:
        mask = hashlib.sha256(current_key).digest()
        mask_byte = mask[0]
        xor_target = single_byte ^ mask_byte

        salt = 0
        while True:
            salt_bytes = salt.to_bytes(4, byteorder="big")
            attempt_hash = hashlib.sha256(current_key + salt_bytes).digest()
            if attempt_hash[0] == xor_target:
                break
            salt += 1

        next_key = self._get_next_key(current_key)
        return salt, next_key

    def _decrypt_byte(self, salt: int, current_key: bytes) -> tuple[int, bytes]:
        mask = hashlib.sha256(current_key).digest()
        mask_byte = mask[0]

        salt_bytes = salt.to_bytes(4, byteorder="big")
        attempt_hash = hashlib.sha256(current_key + salt_bytes).digest()
        xor_target = attempt_hash[0]

        single_byte = xor_target ^ mask_byte
        next_key = self._get_next_key(current_key)
        return single_byte, next_key

    def _read_file(self, path: str) -> bytes:
        with open(path, "rb") as file:
            data = file.read()
        return data

    def _save_file(self, data: bytes, path: str):
        with open(path, "wb") as file:
            file.write(data)


if __name__ == "__main__":
    secret_seed = b"super_secret_master_key_256_bits"
    cipher = HashCipherV2(secret_seed)

    message = "Secret data"
    message_bytes = message.encode("utf-8")

    print(f"Source message: {message}")
    print(f"String length: {len(message)} chars. UTF-8 size: {len(message_bytes)} bytes.\n")

    print("Encryption (salt search)...")
    encrypted_salts = cipher.encrypt(message_bytes)
    for source_byte, salt in zip(message_bytes, encrypted_salts):
        print(f"  Byte {source_byte} encrypted with salt: {salt}")

    print(f"\nTransmitted ciphertext (salt array): {encrypted_salts}")
    print(f"Metadata size: {len(encrypted_salts) * 4} bytes.\n")

    print("Decryption (instant hashing)...")
    decrypted_message = cipher.decrypt(encrypted_salts).decode("utf-8")
    print(f"\nSuccessfully decrypted: {decrypted_message}")