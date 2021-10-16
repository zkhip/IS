from random import randint
import diffie_hellman

BORDER = 10 ** 9


def inter_prime(p):
    result = randint(2, p)
    while diffie_hellman.NOD(p, result) != 1:
        result = randint(2, p)
    return result


def prime():
    while True:
        result = randint(2, BORDER)
        if diffie_hellman.Ferma(result):
            break
    return result


def shamir_cipher_encode(msg_in_bytes):
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


def shamir_cipher_decode(p, db, encoded_msg):
    decoded_msg = list()
    for byte in encoded_msg:
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
    phi = (P - 1)*(Q - 1)

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


def main():
    with open('../res/harry_potter.txt', 'rb') as main_file:
        text_in_bytes = bytearray(main_file.read())

    p, Db, encoded_text = shamir_cipher_encode(text_in_bytes)
    with open('../res/shamir_encode.txt', 'w') as file_shamir_encode:
        file_shamir_encode.write(str(encoded_text))
    shamir_decoded = shamir_cipher_decode(p, Db, encoded_text)
    with open('../res/shamir_decode.txt', 'wb') as shamir_decode:
        shamir_decode.write(bytearray(shamir_decoded))

    a, p, x, encoded_text = el_gamal_cipher_encode(text_in_bytes)
    with open('../res/el_gamal_encode.txt', 'w') as file_el_gamal_encode:
        file_el_gamal_encode.write(str(encoded_text))
    el_gamal_decoded = el_gamal_decode(a, p, x, encoded_text)
    with open('../res/el_gamal_decode.txt', 'wb') as file_el_gamal_decode:
        file_el_gamal_decode.write(bytearray(el_gamal_decoded))

    k, encoded_text = vernam_cipher_encode(text_in_bytes)
    with open('../res/vernam_encode.txt', 'w') as file_vernam_encode:
        file_vernam_encode.write(str(encoded_text))
    vernam_decoded = vernam_cipher_decode(k, encoded_text)
    with open('../res/vernam_decode.txt', 'wb') as file_vernam_decode:
        file_vernam_decode.write(bytearray(vernam_decoded))

    c, N, encoded_text = rsa_cipher_encode(text_in_bytes)
    with open('../res/rsa_encode.txt', 'w') as file_rsa_encode:
        file_rsa_encode.write(str(encoded_text))
    rsa_decoded = rsa_cipher_decode(c, N, encoded_text)
    with open('../res/rsa_decode.txt', 'wb') as file_rsa_decode:
        file_rsa_decode.write(bytearray(rsa_decoded))


if __name__ == '__main__':
    main()
