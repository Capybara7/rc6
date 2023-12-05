﻿from utils import *
import math
import base64

# w = int(input("Введите размер слова в битах  (16, 32, 64): "))  # Размер слова в битах  (16, 32, 64)
w = 16
# r = int(input("Введите кол-во раундов: "))   # Кол-во раундов
r = 20
# Key = input("Введите секретный ключ: ")  # Секретный ключ
Key = "test"

Key_bit = base64.b64encode(bytes(Key, 'utf-8'))
Key_bit = bytesToBin(Key_bit)  # Преобразование ключа в биты

while len(Key_bit) % w != 0:  # Дополнение ключа до кратности w
    Key_bit = "0" + Key_bit

l = int(len(Key_bit) / 8)  # Размер ключа в байтах

Pw = {16: 0xb7e1, 32: 0xb7e15163, 64: 0xb7e151628aed2a6b}
Qw = {16: 0x9e37, 32: 0x9e3779b9, 64: 0x9e3779b97f4a7c15}

# Формирование раундового ключа
W = [Pw[w], ]  # Раундовый ключ длиной в 2r+4

c = int(8 * l / w)  # число слов в ключе

# Преобразование ключа в массив из с слов
L = []
for i in range(c):
    L.append(int("0b" + Key_bit[i:i + w], 2))

for i in range(2 * r + 4 - 1):  # Инициализация массива раундовых ключей
    W.append(mod((W[-1] + Qw[w]), (2 ** w)))

i, j, a, b = 0, 0, 0, 0

for count in range(3 * c):  # Формирование раундового ключа
    W[i] = circular_shift(mod((W[i] + a + b), (2 ** w)), w, 3, 'left')
    a = W[i]
    L[j] = circular_shift(mod((L[j] + a + b), (2 ** w)), w, mod((a + b), (2 ** w)), 'left')
    b = L[j]
    i = mod((i + 1), (2 * r + 4))
    j = mod((j + 1), c)

# message = input("Введите сообщение: ")  # Сообщение
message = "message_ еуые"
print("MESSAGE: ", message)
print("KEY: ", Key)

message_bit = base64.b64encode(bytes(message, 'utf-8'))
message_bit = bytesToBin(message_bit)  # Сообщение в битах

while len(message_bit) % (4 * w) != 0:
    message_bit = "0" + message_bit  # Дополнение нулями до кратности в 4w

print("BIN MESSAGE: ", message_bit)

# Шифрование
encoded_message_bit = ""  # Инициализация зашифрованного сообщения

init = "b"  # Инициализирующий вектор
print("INIT: ", init)

init = base64.b64encode(bytes(init, 'utf-8'))
init = bytesToBin(init)[:4 * w]  # Преобразование инициализирующего вектора в биты

while len(init) % (4 * w) != 0:
    init = "0" + init  # Дополнение нулями до кратности в 4w

synchro_package = init  # Синхропосылка для закодирования

for i in range(0, len(message_bit), 4 * w):  # Цикл по блокам в 4 слова
    temp = message_bit[i: i + 4 * w]
    temp = bin_expansion(bin(XOR(int("0b" + temp, 2), int("0b" + synchro_package, 2))), 4 * w)[
           2:]  # Сложение по модулю 2 с кодируемым блоком

    A = int('0b' + temp[:w], 2)
    B = int('0b' + temp[w:2 * w], 2)
    C = int('0b' + temp[2 * w:3 * w], 2)
    D = int('0b' + temp[3 * w:4 * w], 2)

    B = mod(B + W[0], 2 ** w)
    D = mod(D + W[1], 2 ** w)

    for i in range(1, r + 1):
        t = circular_shift(f(B, w), w, int(math.log(w)), "left")
        u = circular_shift(f(D, w), w, int(math.log(w)), "left")
        A = mod((circular_shift(XOR(A, t), w, u, 'left') + W[2 * i]), (2 ** w))
        C = mod((circular_shift(XOR(C, u), w, t, 'left') + W[2 * i + 1]), (2 ** w))

        aa, bb, cc, dd = B, C, D, A
        A, B, C, D = aa, bb, cc, dd

    A = mod(A + W[2 * r + 2], 2 ** w)
    C = mod(C + W[2 * r + 3], 2 ** w)

    synchro_package = bin_expansion(bin(A), w)[2:] + bin_expansion(bin(B), w)[2:] + \
                      bin_expansion(bin(C), w)[2:] + bin_expansion(bin(D), w)[2:]  # Переопределение синхропосылки

    encoded_message_bit += synchro_package

print("ENCODED BIN MESSAGE: ", encoded_message_bit)

# Дешифрование
synchro_package = init  # Синхропосылка для декодирования
decoded_message_bit = ""  # Инициализация расшифрованного сообщения

for i in range(0, len(encoded_message_bit), 4 * w):
    temp = encoded_message_bit[i: i + 4 * w]  # Запоминание декодируемого блока

    A = int('0b' + temp[:w], 2)
    B = int('0b' + temp[w:2 * w], 2)
    C = int('0b' + temp[2 * w:3 * w], 2)
    D = int('0b' + temp[3 * w:4 * w], 2)

    A = mod(A - W[2 * r + 2], 2 ** w)
    C = mod(C - W[2 * r + 3], 2 ** w)

    for j in range(1, r + 1):
        i = r - j + 1

        aa, bb, cc, dd = D, A, B, C
        A, B, C, D = aa, bb, cc, dd

        t = circular_shift(f(B, w), w, int(math.log(w)), "left")
        u = circular_shift(f(D, w), w, int(math.log(w)), "left")
        A = XOR(circular_shift(mod((A - W[2 * i]), 2 ** w), w, u, 'right'), t)
        C = XOR(circular_shift(mod((C - W[2 * i + 1]), (2 ** w)), w, t, 'right'), u)

    B = mod(B - W[0], 2 ** w)
    D = mod(D - W[1], 2 ** w)

    output = bin_expansion(bin(A), w)[2:] + bin_expansion(bin(B), w)[2:] + \
             bin_expansion(bin(C), w)[2:] + bin_expansion(bin(D), w)[2:]  # Раскодированый блок

    decoded_message_bit += bin_expansion(bin(XOR(int("0b" + synchro_package, 2), int("0b" + output, 2))), 4 * w)[2:]

    synchro_package = temp  # Переопределение синхропосылки

#print("DECODED BIN MESSAGE: ", decoded_message_bit)
#print("DECODED MESSAGE: ", base64.b64decode(binToBytes(decoded_message_bit)).decode('utf-8'))
