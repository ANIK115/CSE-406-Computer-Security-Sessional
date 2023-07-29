import time

from BitVector import *
from diffie_hellman_1805115 import *
from util_1805115 import *

sbox = (
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
)

InvSbox = (
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
)


Mixer = [
    [BitVector(hexstring="02"), BitVector(hexstring="03"), BitVector(hexstring="01"), BitVector(hexstring="01")],
    [BitVector(hexstring="01"), BitVector(hexstring="02"), BitVector(hexstring="03"), BitVector(hexstring="01")],
    [BitVector(hexstring="01"), BitVector(hexstring="01"), BitVector(hexstring="02"), BitVector(hexstring="03")],
    [BitVector(hexstring="03"), BitVector(hexstring="01"), BitVector(hexstring="01"), BitVector(hexstring="02")]
]

InvMixer = [
    [BitVector(hexstring="0E"), BitVector(hexstring="0B"), BitVector(hexstring="0D"), BitVector(hexstring="09")],
    [BitVector(hexstring="09"), BitVector(hexstring="0E"), BitVector(hexstring="0B"), BitVector(hexstring="0D")],
    [BitVector(hexstring="0D"), BitVector(hexstring="09"), BitVector(hexstring="0E"), BitVector(hexstring="0B")],
    [BitVector(hexstring="0B"), BitVector(hexstring="0D"), BitVector(hexstring="09"), BitVector(hexstring="0E")]
]


key_scheduling_time = 0
encryption_time = 0
decryption_time = 0



def subbytes(matrix, sbox):
    for i in range(4):
        for j in range(4):
            matrix[i][j]=sbox[matrix[i][j]]
    return matrix


def left_shift(row,n):
    for i in range(n):
        row.append(row.pop(0))
    return row

def right_shift(row,n):
    for i in range(n):
        row.insert(0,row.pop())
    return row

def shift_rows(matrix, direction):
    for i in range(4):
        if direction == "left":
            matrix[i]=left_shift(matrix[i],i)
        elif direction == "right":
            matrix[i]=right_shift(matrix[i],i)
    return matrix

def add_round_key(matrix,key):
    key = text_to_matrix(key)
    for i in range(4):
        for j in range(4):
            matrix[i][j] = int(matrix[i][j]) ^ int(key[i][j])  
    return matrix





def mix_columns(matrix, Mixer):
    AES_modulus = BitVector(bitstring='100011011')
    matrix = decimal_to_hexadecimal_string(matrix)
    matrix = hexadecimal_string_to_bitvector(matrix)

    new_matrix = [[BitVector(intVal=0, size=8) for x in range(4)] for y in range(4)]
    for i in range(4):
        for j in range(4):
            for k in range(4):
                new_matrix[i][j] = new_matrix[i][j] ^ (Mixer[i][k].gf_multiply_modular(matrix[k][j], AES_modulus, 8))
    
    new_matrix = bitvector_to_hexadecimal_string(new_matrix)
    new_matrix = hexadecimal_to_decimal(new_matrix)
    return new_matrix

#AES encryption algorithm
def aes_encryption(state,round_keys, bits=128):
    #AES encryption time

    state = add_round_key(state,round_keys[0])
    # print("After Round 0")
    # print_decimal_as_hexadecimal(state)
    num_of_rounds = 10
    if bits == 192:
        num_of_rounds = 12
    elif bits == 256:
        num_of_rounds = 14

    for i in range(1, num_of_rounds):
        # print("After Round ",i)
        state = subbytes(state, sbox)
        state = shift_rows(state, "left")
        state = mix_columns(state, Mixer)
        state = add_round_key(state, round_keys[i])
        # print_decimal_as_hexadecimal(state)

    state = subbytes(state, sbox)
    state = shift_rows(state, "left")
    state = add_round_key(state, round_keys[num_of_rounds])

    # print("After Round 10")
    # print_decimal_as_hexadecimal(state)
    return state

def aes_decryption(encrypted_text,key, bits=128):
    print("in decryption: bits = ", bits)
    size_in_bytes = bits // 8
    key_length = len(key)
    if key_length < size_in_bytes:
        for i in range(size_in_bytes-key_length):
            key += "}"
    elif key_length > size_in_bytes:
        key = key[:size_in_bytes]

    key = text_to_decimal(key)
    round_keys = key_expansion(key, bits)

    start_time = time.time()
    decrypted_text = [0 for i in range(len(encrypted_text))]

    num_of_rounds = 10
    if bits == 192:
        num_of_rounds = 12
    elif bits == 256:
        num_of_rounds = 14

    print("in decryption: num_of_rounds = ", num_of_rounds)

    for a in range(int(len(encrypted_text)/16)):
        state = text_to_matrix(encrypted_text[a*16:(a+1)*16])
        state = add_round_key(state,round_keys[num_of_rounds])

        for i in range(1, num_of_rounds):
            state = shift_rows(state, "right")
            state = subbytes(state, InvSbox)
            state = add_round_key(state, round_keys[num_of_rounds-i])
            state = mix_columns(state, InvMixer)
    
        state = shift_rows(state, "right")
        state = subbytes(state, InvSbox)
        state = add_round_key(state, round_keys[0])

        for j in range(4):
            for k in range (4):
                decrypted_text[a*16+j*4+k] = state[k][j]  
    end_time = time.time()
    global decryption_time
    decryption_time =( end_time - start_time ) * 10**3

    return decrypted_text

def generate_encrypted_text(text,key, bits=128):
    size_in_bytes = bits // 8
    key_length = len(key)
    if key_length < size_in_bytes:
        for i in range(size_in_bytes-key_length):
            key += "}"
    elif key_length > size_in_bytes:
        key = key[:size_in_bytes]
    
    key = text_to_decimal(key)
    round_keys = key_expansion(key, bits)


    original_length = len(text)
    count = int(original_length/16)
    if original_length%16 != 0:
        count += 1
    for i in range(count*16-original_length):
        text += "\0"

    text_length = len(text)
    text = text_to_decimal(text)    
    # print(text)
    start_time = time.time()
    encrypted_text = [0 for i in range(text_length)]
    for i in range(int(text_length/16)):
        matrix = text_to_matrix(text[i*16:(i+1)*16])
        encrypted_matrix = aes_encryption(matrix,round_keys, bits)
        for j in range(len(encrypted_matrix)):
            for k in range(len(encrypted_matrix[j])):
                encrypted_text[i*16+j*4+k] = encrypted_matrix[k][j] 

    end_time = time.time()
    global encryption_time
    encryption_time = (end_time - start_time)* 10**3     
    return encrypted_text, original_length   #encrypted text in decimal and original text length




def round_key_generator(prev_round_key, round_constant, bits = 128):
    key_matrix = text_to_word(prev_round_key)
    size = int(bits/32)
    g_word = [0 for x in range(4)]
    for i in range(4):
        g_word[i] = key_matrix[size-1][i]
    
    g_word = left_shift(g_word, 1)

    for i in range(len(g_word)):
        g_word[i] = sbox[g_word[i]]
        g_word[i] = g_word[i] ^ round_constant[i]
        
    next_round_key = [[0 for x in range(4)] for y in range(size)] 
    for i in range(4):
        next_round_key[0][i] = key_matrix[0][i] ^ g_word[i]
    
    for i in range(1,size):
        for j in range(4):
            next_round_key[i][j] = next_round_key[i-1][j] ^ key_matrix[i][j]
    
    next_key = [0 for i in range(size*4)]
    k=0
    for i in range(size):
        for j in range(4):
            next_key[k]= next_round_key[i][j]
            k += 1
    
    return next_key

def key_expansion(key, bits=128):
    start_time = time.time()
    values_of_rc = [1, 2, 4, 8, 16, 32, 64, 128, 27, 54, 108, 216, 171, 77, 154]
    round_constant = [1, 0, 0, 0]
    num_of_rounds = 10
    if bits == 192:
        num_of_rounds = 12
    elif bits == 256:
        num_of_rounds = 14
    #taking a (num_of_rounds+1) * size*4 size matrix
    size = int(bits/32)
    round_keys = [[0 for x in range(size*4)] for y in range(num_of_rounds + 1)]
    round_keys[0] = key
    for i in range(1, num_of_rounds + 1):
        key = round_key_generator(key, round_constant, bits)
        if i < num_of_rounds:
            round_constant[0] = values_of_rc[i]
        # print(round_constant[0])
        round_keys[i] = key
        # print("Round Key ", i)
        # print_decimal_as_hexadecimal_1D(key)
    end_time = time.time()
    global key_scheduling_time
    key_scheduling_time = (end_time - start_time)* 10**6
    return round_keys

def read_file(filename):
    file = open(filename, "r")
    text = file.read()
    file.close()
    return text

def aes_for_files():
    start_time = time.time()
    fd = open("bird-min.jpg", "rb")
    file_data = fd.read()
    fd.close()
    text = byte_to_text(file_data)
    key = read_file("key.txt")
    encrypted_data, original_length = generate_encrypted_text(text, key)
    decrypted_data = aes_decryption(encrypted_data, key)

    decrypted_data = decimal_to_byte(decrypted_data)

    fd = open("copy_bird.jpg", "wb")
    fd.write(bytes(decrypted_data))
    fd.flush()
    fd.close()
    print("Done")
    end_time = time.time()
    print("Total Time: ", (end_time - start_time), " seconds")


# aes_for_files()

def aes_test():
    print("AES Encryption")
    text = read_file("sentence.txt")
    key = read_file("key.txt")

    print("Plain Text: ")
    print("In ASCII: ", text)
    print("In Hex: ", text_to_hexadecimal_string(text))


    print("Key: ")
    print("In ASCII: ", key)
    print("In Hex: ", text_to_hexadecimal_string(key))

    bits = 192
    encrypted_text, original_length = generate_encrypted_text(text,key, bits)  #encrypted text in decimal
    cipher_text = decimal_to_text(encrypted_text)
    print("Cipher Text: ")
    print("In Hex: ", text_to_hexadecimal_string(cipher_text))
    print("In ASCII: ", cipher_text)

    decrypted_text = aes_decryption(encrypted_text,key, bits)   #derypted text in decimal
    decrypted_text = decimal_to_text(decrypted_text)
    decrypted_text = remove_padding(decrypted_text, original_length)
    print("Decrypted Text: ")
    print("In Hex: ", text_to_hexadecimal_string(decrypted_text))
    print("In ASCII: ", decrypted_text)

    print("Key Scheduling Time: ", key_scheduling_time, " micro seconds")
    print("Encryption Time: ", encryption_time, " ms")
    print("Decryption Time: ", decryption_time," ms")

# aes_test()