import hashlib
from blake3 import blake3
from typing import List, Dict


class HashCipherV2:
    HASH_SIZE_BYTES = 64

    def __init__(self, secret_seed: bytes):
        self.initial_key = hashlib.sha256(secret_seed).digest()

    def encrypt(self, data: bytes) -> List[int]:
        encrypted_salts = []
        data_hash = blake3(data).digest(length=self.HASH_SIZE_BYTES)
        hash_int = int.from_bytes(data_hash, byteorder="big")
        current_key = self._mix_initial_key(data_hash)

        for single_byte in data:
            salt, current_key = self._encrypt_byte(single_byte, current_key, data_hash)
            encrypted_salts.append(salt)

        encrypted_salts.append(hash_int)
        return encrypted_salts

    def decrypt(self, salts: List[int]) -> bytes:
        if not salts:
            raise ValueError("Ciphertext is empty")

        hash_int = salts[-1]
        if hash_int < 0:
            raise ValueError("Invalid ciphertext hash value")

        salts_payload = salts[:-1]
        data_hash = hash_int.to_bytes(self.HASH_SIZE_BYTES, byteorder="big")
        decrypted_bytes = bytearray()
        current_key = self._mix_initial_key(data_hash)

        for salt in salts_payload:
            single_byte, current_key = self._decrypt_byte(salt, current_key, data_hash)
            decrypted_bytes.append(single_byte)

        decrypted_data = bytes(decrypted_bytes)
        expected_hash = blake3(decrypted_data).digest(length=self.HASH_SIZE_BYTES)
        if expected_hash != data_hash:
            raise ValueError("Integrity check failed: message hash mismatch")

        return decrypted_data

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

    def _mix_initial_key(self, data_hash: bytes) -> bytes:
        return hashlib.sha256(self.initial_key + data_hash + b"|init-key|").digest()

    def _get_next_key(self, current_key: bytes, data_hash: bytes) -> bytes:
        return hashlib.sha256(current_key + data_hash + b"|next-key|").digest()

    def _encrypt_byte(self, single_byte: int, current_key: bytes, data_hash: bytes) -> tuple[int, bytes]:
        mask = hashlib.sha256(current_key + data_hash + b"|mask|").digest()
        mask_byte = mask[0]
        xor_target = single_byte ^ mask_byte

        salt = 0
        while True:
            salt_bytes = salt.to_bytes(4, byteorder="big")
            attempt_hash = hashlib.sha256(current_key + data_hash + salt_bytes + b"|salt|").digest()
            if attempt_hash[0] == xor_target:
                break
            salt += 1

        next_key = self._get_next_key(current_key, data_hash)
        return salt, next_key

    def _decrypt_byte(self, salt: int, current_key: bytes, data_hash: bytes) -> tuple[int, bytes]:
        mask = hashlib.sha256(current_key + data_hash + b"|mask|").digest()
        mask_byte = mask[0]

        salt_bytes = salt.to_bytes(4, byteorder="big")
        attempt_hash = hashlib.sha256(current_key + data_hash + salt_bytes + b"|salt|").digest()
        xor_target = attempt_hash[0]

        single_byte = xor_target ^ mask_byte
        next_key = self._get_next_key(current_key, data_hash)
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
    payload_salts = encrypted_salts[:-1]
    message_hash = encrypted_salts[-1]

    for source_byte, salt in zip(message_bytes, payload_salts):
        print(f"  Byte {source_byte} encrypted with salt: {salt}")
    print(f"  BLAKE3-64 integrity hash (as int): {message_hash}")

    print(f"\nTransmitted ciphertext (salt array): {encrypted_salts}")
    metadata_size = sum(max(1, (salt.bit_length() + 7) // 8) for salt in encrypted_salts)
    print(f"Metadata size: {metadata_size} bytes.\n")

    print("Decryption (instant hashing)...")
    decrypted_message = cipher.decrypt(encrypted_salts).decode("utf-8")
    print(f"\nSuccessfully decrypted: {decrypted_message}")