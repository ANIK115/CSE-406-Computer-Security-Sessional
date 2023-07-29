import random
import time

from util_1805115 import *


#Miller–Rabin primality test
#Utility functiuon for modular exponentiation
def modular_exponent(a, b, p):
    result = 1
    a = a % p

    while b > 0:
        if b % 2 == 1:
            result = (result * a) % p
        b = b >> 1
        a = (a * a) % p
    return result

#Utility function for Miller-Rabin primality test
def miller_rabin_test(d,n):
    rand = 2 + random.randint(1 ,n-4)
    exp = modular_exponent(rand,d,n)
    if exp == 1 or exp == n-1:
        return True

    while d != n-1:
        exp = (exp*exp)%n
        d *= 2
        if exp == 1:
            return False
        if exp == n-1:
            return True
        
    return False

#Main function for Miller-Rabin primality test
def is_prime(n,k):
    if n <= 1 or n == 4:
        return False
    if n <= 3:
        return True
    

    d = n-1
    while d%2 == 0:
        d //= 2

    for i in range(k):
        if not miller_rabin_test(d,n):
            return False
    return True

#generate a prime that is at least k bits long
def generate_prime(k=128):
    while True:
        # print("Generating prime...")
        n = random.randint(2**(k-1), 2**k - 1)
        if n%2 == 0:
            n += 1
        x = (n-1)//2
        if is_prime(x, 100) and is_prime(n, 100):
            return n
        
def gcd(x, y):
    while(y):
        t = x%y
        x = y
        y = t
    return x

def extended_gcd(x, y):
    if x == 0:
        return y, 0, 1
    gcd, x1, y1 = extended_gcd(y%x, x)
    quotient = y//x
    x = y1 - quotient * x1
    y = x1
    return gcd, x, y

def modular_inverse(a, p):
    gcd, x, y = extended_gcd(a, p)
    if gcd != 1:
        return None
    else:
        return x%p
    

def public_private_key(k=128):
    p = generate_prime(k)
    q = generate_prime(k)
    while p == q:
        q = generate_prime(k)
    
    n = p*q
    phi = (p-1)*(q-1)
    exp = random.randint(1, phi-1)
    while gcd(exp, phi) != 1:
        exp = random.randint(1, phi-1)
    d = modular_inverse(exp, phi)
    public_key = (exp, n)
    private_key = (d, n)
    return public_key, private_key

def rsa_encryption(text, public_key):
    exp, n = public_key
    cipher_text = []
    for i in range(len(text)):
        cipher_text.append(modular_exponent(ord(text[i]), exp, n))
    return cipher_text

def rsa_decryption(cipher_text, private_key):
    d, n = private_key
    text = ""
    for i in range(len(cipher_text)):
        text += chr(modular_exponent(cipher_text[i], d, n))
    return text
def read_file(filename):
    file = open(filename, "r")
    text = file.read()
    file.close()
    return text


def rsa_test():
    start_time = time.time()
    public_key, private_key = public_private_key()
    key_generation_time = (time.time() - start_time)*10**3  #in ms

    print("Public Key: ", public_key)
    print("Private Key: ", private_key)
    text = read_file("key.txt")

    print("Plain Text: ")
    print("In ASCII: ", text)
    print("In Hex: ", text_to_hexadecimal_string(text))

    start_time = time.time()
    cipher_text = rsa_encryption(text, public_key)
    encryption_time = (time.time() - start_time)*10**3  #in ms

    start_time = time.time()
    decrypted_text = rsa_decryption(cipher_text, private_key)
    decryption_time = (time.time() - start_time)*10**3  #in ms

    print("Cipher Text: ", cipher_text)
    print("Decrypted Text: ", decrypted_text)

    print("Key Generation Time: ", key_generation_time, " ms")
    print("Encryption Time: ", encryption_time, " ms")
    print("Decryption Time: ", decryption_time, " ms")

rsa_test()

