from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import time


def read_file(path: str):
    with open(path, 'rb') as file:
        data = file.read()
    return data

# Данные, которые мы будем шифровать (предположим, это строка)
data = read_file('data/10mb.pdf')

# Начинаем отсчет времени
start_time = time.time()

# Генерируем случайный ключ AES длиной 256 бит (32 байта)
key = get_random_bytes(32)

# Создаем объект AES с использованием ключа
cipher = AES.new(key, AES.MODE_EAX)

# Шифруем данные
ciphertext, tag = cipher.encrypt_and_digest(data)

# Останавливаем отсчет времени
end_time = time.time()
data_size_MB = len(data) / (1024 * 1024)  # Convert bytes to Megabytes
throughput = data_size_MB / (end_time - start_time)
# Выводим зашифрованный текст и время, затраченное на шифрование
print("Время шифрования:", end_time - start_time, "секунд")
print(f"Throughput: {throughput} MB/s")
print(f"File size: {data_size_MB} MB")
