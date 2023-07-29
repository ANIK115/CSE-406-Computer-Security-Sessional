import random
import time

p_time = 0
g_time = 0
A_time = 0
a_time = 0
shared_key_time = 0

#find number of bits in a number
def num_bits(n):
    count = 0
    while n > 0:
        count += 1
        n //= 2
    return count


#Miller–Rabin primality test

#Utility functiuon for modular exponentiation
def modular_exponent(a, b, p):
    result = 1
    a = a % p

    while b > 0:
        if b % 2 == 1:
            result = (result * a) % p
        b = b >> 1  # b = b/2
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
        
def generate_g(p):
    while True:
        g = random.randint(1, p-2)
        if modular_exponent(g, (p-1)//2, p) != 1 and modular_exponent(g, 2, p) != 1:
            return g
        

def generate_key(p, g, k):
    #generate a random number that is at least k/2 bits long
    global A_time
    global a_time
    start_time = time.time()
    a = generate_prime(k//2)
    a_time = (time.time() - start_time) * 10**3
    start_time = time.time()
    A = modular_exponent(g, a, p)
    A_time = (time.time() - start_time) * 10**3
    return A, a

def generate_shared_key(p, B, a):
    return modular_exponent(B, a, p)

def diffie_hellman(k):
    global p_time
    global g_time
    global shared_key_time

    start_time = time.time()
    p = generate_prime(k)
    p_time = (time.time() - start_time) * 10**3
    start_time = time.time()
    g = generate_g(p)
    g_time = (time.time() - start_time) * 10**3

    # A, a = generate_key(p, g, k)
    # B, b = generate_key(p, g, k)

    # print("p: ", p)
    # print("g: ", g)
    # print("A: ", A)
    # print("B: ", B)
    # print("a: ", a)
    # print("b: ", b)
    # start_time = time.time()
    # shared_key_1 = generate_shared_key(p, B, a)
    # shared_key_time = (time.time() - start_time) * 10**3
    # shared_key_2 = generate_shared_key(p, A, b)
    # print("shared_key_1: ", shared_key_1)
    # print("shared_key_2: ", shared_key_2)
    # if shared_key_1 == shared_key_2:
    #     print("true")
    # else:
    #     print("false")
    return p,g
    
# print("Running diffie_hellman")

def deffie_hellman_test():
    k = 128
    p,g = diffie_hellman(k)
    A, a = generate_key(p, g, k)
    B, b = generate_key(p, g, k)
    shared_key_1 = generate_shared_key(p, B, a)
    shared_key_2 = generate_shared_key(p, A, b)
    print(shared_key_1 == shared_key_2)
    # print("shared_key_1: ", shared_key_1)
    # print("shared_key_2: ", shared_key_2)
    # print("p_time: ", p_time," ms")
    # print("g_time: ", g_time, " ms")
    # print("A_time: ", A_time," ms")
    # print("a_time: ", a_time," ms")
    # print("shared_key_time: ", shared_key_time, " ms")
    return p_time, g_time, A_time, a_time, shared_key_time

def execution_time():
    #take average of 5 values
    p_time = 0
    g_time = 0
    A_time = 0
    a_time = 0
    shared_key_time = 0
    for i in range(5):
        p_time_i, g_time_i, A_time_i, a_time_i, shared_key_time_i = deffie_hellman_test()
        p_time += p_time_i
        g_time += g_time_i
        A_time += A_time_i
        a_time += a_time_i
        shared_key_time += shared_key_time_i
    
    p_time /= 5
    g_time /= 5
    A_time /= 5
    a_time /= 5
    shared_key_time /= 5
    print("p_time: ", p_time," ms")
    print("g_time: ", g_time, " ms")
    print("A_time: ", A_time," ms")
    print("a_time: ", a_time," ms")
    print("shared_key_time: ", shared_key_time, " ms")

# execution_time()

