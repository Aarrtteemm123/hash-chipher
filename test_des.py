from Crypto.Cipher import DES
from Crypto.Random import get_random_bytes
import time
def read_file(path: str):
    with open(path, 'rb') as file:
        data = file.read()
    return data

# Data to be encrypted (must be a multiple of 8 bytes)
data = read_file('data/data2.txt')

# Начинаем отсчет времени
start_time = time.time()

# Key for DES encryption (must be 8 bytes long)
key = get_random_bytes(8)

# Initialize the DES cipher object with the key
cipher = DES.new(key, DES.MODE_ECB)

# Pad the data to make it a multiple of 8 bytes if necessary
if len(data) % 8 != 0:
    data += b'\0' * (8 - len(data) % 8)

# Encrypt the data
encrypted_data = cipher.encrypt(data)

# Decrypt the data
#decrypted_data = cipher.decrypt(encrypted_data)

# Останавливаем отсчет времени
end_time = time.time()
data_size_MB = len(data) / (1024 * 1024)  # Convert bytes to Megabytes
throughput = data_size_MB / (end_time - start_time)
# Выводим зашифрованный текст и время, затраченное на шифрование
print("Время шифрования:", end_time - start_time, "секунд")
print(f"Throughput: {throughput} MB/s")
print(f"File size: {data_size_MB} MB")

