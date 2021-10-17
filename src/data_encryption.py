import os.path
import struct
from random import randint
from typing import List, Tuple

import diffie_hellman

BORDER = 10 ** 9


def inter_prime(p: int) -> int:
    result = randint(2, p)
    while diffie_hellman.NOD(p, result) != 1:
        result = randint(2, p)
    return result


def prime() -> int:
    while True:
        result = randint(2, BORDER)
        if diffie_hellman.Ferma(result):
            break
    return result


def shamir_cipher_encode(msg_in_bytes: bytearray) -> Tuple[int, int, List[int]]:
    p = prime()
    Ca = inter_prime(p - 1)
    Da = diffie_hellman.EuclidAlgorithm(p - 1, Ca)[-1]
    if Da < 0:
        Da += (p - 1)
    Cb = inter_prime(p - 1)
    Db = diffie_hellman.EuclidAlgorithm(p - 1, Cb)[-1]
    if Db < 0:
        Db += (p - 1)

    encoded_msg_in_byte = list()
    for byte in msg_in_bytes:
        # print("o ", byte)
        x1 = diffie_hellman.Exponentiation(byte, Ca, p)
        x2 = diffie_hellman.Exponentiation(x1, Cb, p)
        x3 = diffie_hellman.Exponentiation(x2, Da, p)
        encoded_msg_in_byte.append(x3)
        # print("e ", x3)

    return p, Db, encoded_msg_in_byte


def shamir_cipher_decode(p: int, db: int, encoded_int_list: List[int]) -> List[int]:
    decoded_msg = list()
    for byte in encoded_int_list:
        x4 = diffie_hellman.Exponentiation(byte, db, p)
        decoded_msg.append(x4)
        # print("d ", x4)
    return decoded_msg


def el_gamal_cipher_encode(msg):
    while True:  # генерируем q
        q = randint(0, BORDER)
        p = 2 * q + 1  # считаем P
        if diffie_hellman.Ferma(q) and diffie_hellman.Ferma(p):  # проверяем P и q на простоту
            break

    while True:  # генерируем первообразный корень g
        g = randint(0, BORDER)
        if 1 < g < p - 1 and diffie_hellman.Exponentiation(g, q, p) != 1:
            break

    x = randint(1, p)
    y = diffie_hellman.Exponentiation(g, x, p)

    k = randint(1, p - 1)
    a = diffie_hellman.Exponentiation(g, k, p)
    encoded_msg = list()
    for byte in msg:
        b = (byte * diffie_hellman.Exponentiation(y, k, p)) % p
        encoded_msg.append(b)
        # print("e ", b)

    return a, p, x, encoded_msg


def el_gamal_decode(a, p, x, encoded_msg):
    decoded_msg = list()
    for byte in encoded_msg:
        m = (byte * diffie_hellman.Exponentiation(a, p - 1 - x, p)) % p
        decoded_msg.append(m)
        # print("d ", m)
    return decoded_msg


def vernam_cipher_encode(msg):
    encoded_msg = list()
    k = randint(0, 255)
    for byte in msg:
        e = byte ^ k
        encoded_msg.append(e)
        # print("e ", e)
    return k, encoded_msg


def vernam_cipher_decode(k, encoded_msg):
    decoded_msg = list()
    for byte in encoded_msg:
        m = byte ^ k
        decoded_msg.append(m)
        # print("m ", m)
    return decoded_msg


def rsa_cipher_encode(msg):
    encoded_msg = list()
    P = prime()
    Q = prime()
    N = P * Q
    phi = (P - 1) * (Q - 1)

    while True:
        d = inter_prime(phi)
        if d < phi:
            break

    c = diffie_hellman.EuclidAlgorithm(phi, d)[-1]
    if c < 0:
        c += phi
    for byte in msg:
        e = diffie_hellman.Exponentiation(byte, d, N)
        encoded_msg.append(e)
        # print("e ", e)
    return c, N, encoded_msg


def rsa_cipher_decode(c, N, encoded_msg):
    decoded_msg = list()
    for byte in encoded_msg:
        m = diffie_hellman.Exponentiation(byte, c, N)
        decoded_msg.append(m)
        # print("m ", m)
    return decoded_msg


def read_file_bytes(filepath: str) -> bytearray:
    with open(filepath, 'rb') as file:
        return bytearray(file.read())


def write_file_bytes_as_str(_bytes: List[int], filepath: str):
    with open(filepath, 'w') as file:
        string = ''.join([chr(_byte) for _byte in _bytes])
        file.write(string)


def write_encoded_as_int_list(encoded_int_list: List[int], filepath: str):
    with open(filepath, 'wb') as file:
        encoded_bytes = struct.pack(f'{len(encoded_int_list)}Q', *encoded_int_list)
        file.write(encoded_bytes)


def read_bytes_as_int_list(filepath: str) -> List[int]:
    with open(filepath, 'rb') as file:
        _bytes = file.read()
        list_size = len(_bytes) // 8
        unpacked_ints = struct.unpack(f'{list_size}Q', _bytes)
        return list(unpacked_ints)


def main():
    script_path = os.path.abspath(__file__)
    script_dir = os.path.dirname(script_path)
    res_dir = os.path.join(script_dir, '..', 'res')
    main_filepath = os.path.join(res_dir, 'harry_potter.txt')

    # read file bytes
    text_in_bytes = read_file_bytes(main_filepath)

    # shamir payload
    p, Db, encoded_int_list = shamir_cipher_encode(text_in_bytes)
    write_encoded_as_int_list(encoded_int_list, os.path.join(res_dir, 'shamir_encode.txt'))
    encoded_int_list = read_bytes_as_int_list(os.path.join(res_dir, 'shamir_encode.txt'))

    shamir_decoded = shamir_cipher_decode(p, Db, encoded_int_list)
    write_file_bytes_as_str(shamir_decoded, os.path.join(res_dir, 'shamir_decode.txt'))

    # el-gamal payload
    a, p, x, encoded_int_list = el_gamal_cipher_encode(text_in_bytes)
    write_encoded_as_int_list(encoded_int_list, os.path.join(res_dir, 'el_gamal_encode.txt'))
    encoded_int_list = read_bytes_as_int_list(os.path.join(res_dir, 'el_gamal_encode.txt'))

    el_gamal_decoded = el_gamal_decode(a, p, x, encoded_int_list)
    write_file_bytes_as_str(el_gamal_decoded, os.path.join(res_dir, 'el_gamal_decode.txt'))

    # vernam-cipher payload
    k, encoded_int_list = vernam_cipher_encode(text_in_bytes)
    write_encoded_as_int_list(encoded_int_list, os.path.join(res_dir, 'vernam_encode.txt'))
    encoded_int_list = read_bytes_as_int_list(os.path.join(res_dir, 'vernam_encode.txt'))

    vernam_decoded = vernam_cipher_decode(k, encoded_int_list)
    write_file_bytes_as_str(el_gamal_decoded, os.path.join(res_dir, 'vernam_decode.txt'))

    # rsa payload
    c, N, encoded_int_list = rsa_cipher_encode(text_in_bytes)
    write_encoded_as_int_list(encoded_int_list, os.path.join(res_dir, 'rsa_encode.txt'))
    encoded_int_list = read_bytes_as_int_list(os.path.join(res_dir, 'rsa_encode.txt'))

    rsa_decoded = rsa_cipher_decode(c, N, encoded_int_list)
    write_file_bytes_as_str(rsa_decoded, os.path.join(res_dir, 'rsa_decode.txt'))


if __name__ == '__main__':
    main()
