from hash_cipher_v2 import HashCipherV2
from pathlib import Path
from blake3 import blake3


def run_demo() -> None:
    secret_seed = b"super_secret_master_key_256_bits"
    cipher = HashCipherV2(secret_seed)

    message = "Hello!"
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

    assert decrypted_message == message, "Decrypted message does not match source message"


def test_hash_cipher_v2_round_trip() -> None:
    secret_seed = b"super_secret_master_key_256_bits"
    cipher = HashCipherV2(secret_seed)
    message = "Hello!"
    message_bytes = message.encode("utf-8")

    salts = cipher.encrypt(message_bytes)
    decrypted_message = cipher.decrypt(salts).decode("utf-8")

    assert decrypted_message == message


def test_hash_cipher_v2_appends_blake3_64_hash() -> None:
    secret_seed = b"super_secret_master_key_256_bits"
    cipher = HashCipherV2(secret_seed)
    message_bytes = b"Hello!"

    salts = cipher.encrypt(message_bytes)
    expected_hash = blake3(message_bytes).digest(length=cipher.HASH_SIZE_BYTES)
    expected_hash_int = int.from_bytes(expected_hash, byteorder="big")

    assert len(salts) == len(message_bytes) + 1
    assert salts[-1] == expected_hash_int


def test_hash_cipher_v2_save_and_load_key(tmp_path: Path) -> None:
    secret_seed = b"super_secret_master_key_256_bits"
    cipher = HashCipherV2(secret_seed)
    message = b"Test key persistence"

    salts = cipher.encrypt(message)
    key_file = tmp_path / "secret_key_v2.key"

    cipher.save_keys(salts=salts, filename_secret_key=str(key_file))
    loaded = cipher.load_keys(filename_secret_key=str(key_file))

    assert "secret_key" in loaded
    assert loaded["secret_key"] == salts


def test_hash_cipher_v2_encrypt_test_file(tmp_path: Path) -> None:
    secret_seed = b"super_secret_master_key_256_bits"
    cipher = HashCipherV2(secret_seed)

    source_file = tmp_path / "test_input.bin"
    source_data = b"Binary\x00data\x01for\x02encryption\xfftest"
    source_file.write_bytes(source_data)

    encrypted_salts = cipher.encrypt(source_file.read_bytes())
    decrypted_data = cipher.decrypt(encrypted_salts)

    assert decrypted_data == source_data


def test_hash_cipher_v2_integrity_check_on_tampered_ciphertext() -> None:
    secret_seed = b"super_secret_master_key_256_bits"
    cipher = HashCipherV2(secret_seed)
    message = b"Integrity test payload"

    salts = cipher.encrypt(message)
    tampered = salts.copy()
    tampered[0] += 1

    try:
        cipher.decrypt(tampered)
        raise AssertionError("Decryption must fail on tampered ciphertext")
    except ValueError as error:
        assert "Integrity check failed" in str(error)


if __name__ == "__main__":
    run_demo()
    test_hash_cipher_v2_round_trip()
    test_hash_cipher_v2_appends_blake3_64_hash()
    project_dir = Path(__file__).resolve().parent
    test_hash_cipher_v2_save_and_load_key(project_dir)
    test_hash_cipher_v2_encrypt_test_file(project_dir)
    test_hash_cipher_v2_integrity_check_on_tampered_ciphertext()
    print("\nAll tests passed.")
