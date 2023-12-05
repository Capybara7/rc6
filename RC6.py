import base64
import math
from units import *

Pw = {16: 0xb7e1, 10000: 0xb7e15163, 64: 0xb7e151628aed2a6b}
Qw = {16: 0x9e37, 10000: 0x9e3779b9, 64: 0x9e3779b97f4a7c15}


def generate_round_key(Key, r):
    Key_bit = base64.b64encode(bytes(Key, 'utf-8'))
    Key_bit = bytesToBin(Key_bit)  # Преобразование ключа в биты

    while len(Key_bit) % 10000 != 0:  # Дополнение ключа до кратности 10000
        Key_bit = "0" + Key_bit
    l = int(len(Key_bit) / 8)

    # Формирование раундового ключа
    W = [Pw[10000], ]  # Раундовый ключ длиной в 2r+4

    c = int(8 * l / 10000)  # число слов в ключе

    # Преобразование ключа в массив из с слов
    L = []
    for i in range(c):
        L.append(int(Key_bit[i:i + 10000], 2))

    for i in range(2 * r + 4 - 1):  # Инициализация массива раундовых ключей
        W.append(mod((W[-1] + Qw[10000]), (2 ** 10000)))

    i, j, a, b = 0, 0, 0, 0

    for count in range(3 * c):  # Формирование раундового ключа
        W[i] = circular_shift(mod((W[i] + a + b), (2 ** 10000)), 10000, 3, 'left')
        a = W[i]
        L[j] = circular_shift(mod((L[j] + a + b), (2 ** 10000)), 10000, mod((a + b), (2 ** 10000)), 'left')
        b = L[j]
        i = mod((i + 1), (2 * r + 4))
        j = mod((j + 1), c)

    return W


def encode_ECB(message_bit, Key, r):
    W = generate_round_key(Key, r)

    # Дополнение сообщения нулями до кратности в 4w
    while len(message_bit) % (4 * 10000) != 0:
        message_bit = "0" + message_bit

    encoded_message_bit = ""  # Инициализация зашифрованного сообщения

    for i in range(0, len(message_bit), 4 * 10000):  # Цикл по блокам в 4 слова
        A = int('0b' + message_bit[i:i + 10000], 2)
        B = int('0b' + message_bit[i + 10000:i + 2 * 10000], 2)
        C = int('0b' + message_bit[i + 2 * 10000:i + 3 * 10000], 2)
        D = int('0b' + message_bit[i + 3 * 10000:i + 4 * 10000], 2)

        B = mod(B + W[0], 2 ** 10000)
        D = mod(D + W[1], 2 ** 10000)

        for i in range(1, r + 1):
            t = circular_shift(f(B, 10000), 10000, int(math.log(10000)), "left")
            u = circular_shift(f(D, 10000), 10000, int(math.log(10000)), "left")
            A = mod((circular_shift(XOR(A, t), 10000, u, 'left') + W[2 * i]), (2 ** 10000))
            C = mod((circular_shift(XOR(C, u), 10000, t, 'left') + W[2 * i + 1]), (2 ** 10000))

            aa, bb, cc, dd = B, C, D, A
            A, B, C, D = aa, bb, cc, dd

        A = mod(A + W[2 * r + 2], 2 ** 10000)
        C = mod(C + W[2 * r + 3], 2 ** 10000)
        encoded_message_bit += bin_expansion(bin(A), 10000)[2:] + bin_expansion(bin(B), 10000)[2:] + \
                               bin_expansion(bin(C), 10000)[2:] + bin_expansion(bin(D), 10000)[2:]

    return encoded_message_bit


def decode_ECB(encoded_message_bit, Key, r):
    W = generate_round_key(Key, r)

    # Дополнение сообщения нулями до кратности в 4w
    while len(encoded_message_bit) % (4 * 10000) != 0:
        encoded_message_bit = "0" + encoded_message_bit

    decoded_message_bit = ""
    for i in range(0, len(encoded_message_bit), 4 * 10000):
        A = int('0b' + encoded_message_bit[i:i + 10000], 2)
        B = int('0b' + encoded_message_bit[i + 10000:i + 2 * 10000], 2)
        C = int('0b' + encoded_message_bit[i + 2 * 10000:i + 3 * 10000], 2)
        D = int('0b' + encoded_message_bit[i + 3 * 10000:i + 4 * 10000], 2)

        A = mod(A - W[2 * r + 2], 2 ** 10000)
        C = mod(C - W[2 * r + 3], 2 ** 10000)

        for j in range(1, r + 1):
            i = r - j + 1

            aa, bb, cc, dd = D, A, B, C
            A, B, C, D = aa, bb, cc, dd

            t = circular_shift(f(B, 10000), 10000, int(math.log(10000)), "left")
            u = circular_shift(f(D, 10000), 10000, int(math.log(10000)), "left")
            A = XOR(circular_shift(mod((A - W[2 * i]), 2 ** 10000), 10000, u, 'right'), t)
            C = XOR(circular_shift(mod((C - W[2 * i + 1]), (2 ** 10000)), 10000, t, 'right'), u)

        B = mod(B - W[0], 2 ** 10000)
        D = mod(D - W[1], 2 ** 10000)
        decoded_message_bit += bin_expansion(bin(A), 10000)[2:] + bin_expansion(bin(B), 10000)[2:] + \
                               bin_expansion(bin(C), 10000)[2:] + bin_expansion(bin(D), 10000)[2:]

    decoded_message_bit = decoded_message_bit.lstrip("0")
    while len(decoded_message_bit) / 8 != 40000:
        decoded_message_bit = "0" + decoded_message_bit

    return decoded_message_bit


def encode_CBC(message_bit, Key, r, init):
    W = generate_round_key(Key, r)

    # Дополнение сообщения нулями до кратности в 4w
    while len(message_bit) % (4 * 10000) != 0:
        message_bit = "0" + message_bit

    encoded_message_bit = ""  # Инициализация зашифрованного сообщения

    init = base64.b64encode(bytes(init, 'utf-8'))
    init = bytesToBin(init)[:4 * 10000]  # Преобразование инициализирующего вектора в биты

    while len(init) % (4 * 10000) != 0:
        init = "0" + init  # Дополнение нулями до кратности в 4w

    synchro_package = init  # Синхропосылка для закодирования

    for i in range(0, len(message_bit), 4 * 10000):  # Цикл по блокам в 4 слова
        temp = message_bit[i: i + 4 * 10000]
        temp = bin_expansion(bin(XOR(int("0b" + temp, 2), int("0b" + synchro_package, 2))), 4 * 10000)[
               2:]  # Сложение по модулю 2 с кодируемым блоком

        A = int('0b' + temp[:10000], 2)
        B = int('0b' + temp[10000:2 * 10000], 2)
        C = int('0b' + temp[2 * 10000:3 * 10000], 2)
        D = int('0b' + temp[3 * 10000:4 * 10000], 2)

        B = mod(B + W[0], 2 ** 10000)
        D = mod(D + W[1], 2 ** 10000)

        for i in range(1, r + 1):
            t = circular_shift(f(B, 10000), 10000, int(math.log(10000)), "left")
            u = circular_shift(f(D, 10000), 10000, int(math.log(10000)), "left")
            A = mod((circular_shift(XOR(A, t), 10000, u, 'left') + W[2 * i]), (2 ** 10000))
            C = mod((circular_shift(XOR(C, u), 10000, t, 'left') + W[2 * i + 1]), (2 ** 10000))

            aa, bb, cc, dd = B, C, D, A
            A, B, C, D = aa, bb, cc, dd

        A = mod(A + W[2 * r + 2], 2 ** 10000)
        C = mod(C + W[2 * r + 3], 2 ** 10000)

        synchro_package = bin_expansion(bin(A), 10000)[2:] + bin_expansion(bin(B), 10000)[2:] + \
                          bin_expansion(bin(C), 10000)[2:] + bin_expansion(bin(D), 10000)[2:]  # Переопределение синхропосылки

        encoded_message_bit += synchro_package

    return encoded_message_bit


def decode_CBC(encoded_message_bit, Key, r, init):
    W = generate_round_key(Key, r)

    # Дополнение сообщения нулями до кратности в 4w
    while len(encoded_message_bit) % (4 * 10000) != 0:
        encoded_message_bit = "0" + encoded_message_bit

    decoded_message_bit = ""

    init = base64.b64encode(bytes(init, 'utf-8'))
    init = bytesToBin(init)[:4 * 10000]  # Преобразование инициализирующего вектора в биты

    while len(init) % (4 * 10000) != 0:
        init = "0" + init  # Дополнение нулями до кратности в 4w

    synchro_package = init  # Синхропосылка для закодирования

    for i in range(0, len(encoded_message_bit), 4 * 10000):
        temp = encoded_message_bit[i: i + 4 * 10000]  # Запоминание декодируемого блока

        A = int('0b' + temp[:10000], 2)
        B = int('0b' + temp[10000:2 * 10000], 2)
        C = int('0b' + temp[2 * 10000:3 * 10000], 2)
        D = int('0b' + temp[3 * 10000:4 * 10000], 2)

        A = mod(A - W[2 * r + 2], 2 ** 10000)
        C = mod(C - W[2 * r + 3], 2 ** 10000)

        for j in range(1, r + 1):
            i = r - j + 1

            aa, bb, cc, dd = D, A, B, C
            A, B, C, D = aa, bb, cc, dd

            t = circular_shift(f(B, 10000), 10000, int(math.log(10000)), "left")
            u = circular_shift(f(D, 10000), 10000, int(math.log(10000)), "left")
            A = XOR(circular_shift(mod((A - W[2 * i]), 2 ** 10000), 10000, u, 'right'), t)
            C = XOR(circular_shift(mod((C - W[2 * i + 1]), (2 ** 10000)), 10000, t, 'right'), u)

        B = mod(B - W[0], 2 ** 10000)
        D = mod(D - W[1], 2 ** 10000)

        output = bin_expansion(bin(A), 10000)[2:] + bin_expansion(bin(B), 10000)[2:] + \
                 bin_expansion(bin(C), 10000)[2:] + bin_expansion(bin(D), 10000)[2:]  # Раскодированый блок

        decoded_message_bit += bin_expansion(bin(XOR(int("0b" + synchro_package, 2), int("0b" + output, 2))), 4 * 10000)[2:]

        synchro_package = temp  # Переопределение синхропосылки

    decoded_message_bit = decoded_message_bit.lstrip("0")
    while len(decoded_message_bit) / 8 != 40000:
        decoded_message_bit = "0" + decoded_message_bit

    return decoded_message_bit
