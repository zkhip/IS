import math
from random import randint


def Exponentiation(a, x, p):
    y = 1
    while 0 < x:
        if x % 2 == 1:
            y = y * a % p
        a = a * a % p
        x //= 2
    return y


def EuclidAlgorithm(a, b) -> object:
    U = [a, 1, 0]
    V = [b, 0, 1]
    T = [0] * 3
    while V[0] != 0:
        q = U[0] // V[0]
        T[0] = U[0] % V[0]
        T[1] = U[1] - q * V[1]
        T[2] = U[2] - q * V[2]
        for i in range(3):
            U[i] = V[i]
            V[i] = T[i]
    return U


def NOD(x, y):
    if x > y:
        x, y = y, x
    while y != 0:
        r = x % y
        x = y
        y = r
    return x


def Ferma(x):
    if x == 2:
        return True
    if x & 1 == 0:
        return False
    for i in range(100):
        a = randint(0, 10 ** 9)
        if NOD(a, x) != 1 or Exponentiation(a, x - 1, x) != 1:
            return False
    return True


def DiffieHellman():
    while True:  # generation q
        q = randint(0, 10 ** 9)
        p = 2 * q + 1  # calculation P
        if Ferma(q) and Ferma(p):  # check P and q for simplicity
            break

    while True:  # generation g
        g = randint(0, 10 ** 9)
        if 1 < g < p - 1 and Exponentiation(g, q, p) != 1:
            break

    Xa = randint(1, p)
    Xb = randint(1, p)

    Ya = Exponentiation(g, Xa, p)
    Yb = Exponentiation(g, Xb, p)

    Za = Exponentiation(Yb, Xa, p)
    Zb = Exponentiation(Ya, Xb, p)
    print(Za, " == ", Zb)


def BabyStepGiantStep(p, a, y):
    m = k = math.ceil(math.sqrt(p))
    L1 = [0] * m
    L2 = [0] * k
    for i in range(m):
        L1[i] = (Exponentiation(a, i, p) * Exponentiation(y, 1, p)) % p
    for i in range(k):
        L2[i] = Exponentiation(a, (i + 1) * m, p) % p

    dictionary = dict()
    for i in range(m):
        dictionary[L1[i]] = i
    for i in range(k):
        if dictionary.get(L2[i]):
            x = ((i + 1) * m) - (dictionary[L2[i]])
            print("x = {:10d} ==> {:10d} == {:10d}".format(x, y, Exponentiation(a, x, p)))
    return


def main():
    print("1. Exponentiation modulo:")
    print("expect: ", 5 ** 12 % 7, "receive: ", Exponentiation(5, 12, 7))
    print("expect: ", 2 ** 10 % 5, "receive: ", Exponentiation(2, 10, 5))
    print("-" * 20)

    print("2. Generalized Euclidean algorithm:")
    print("expect: [1, -2, 3] receive: ", EuclidAlgorithm(28, 19))
    print("-" * 20)

    print("3. Building a shared key using the Diffie-Hellman scheme:")
    DiffieHellman()
    print("-" * 20)

    print("4. Baby step, giant step:")
    BabyStepGiantStep(28406579, 21698472, 16312338)
    print("-" * 10)
    BabyStepGiantStep(323605307, 229635193, 45162172)


if __name__ == '__main__':
    main()