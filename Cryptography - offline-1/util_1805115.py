from BitVector import *

#All conversions functions

def text_to_hexadecimal(text):
    hexa_text = []
    for i in range(len(text)):
        hexa_text.append(hex(ord(text[i])))
    return hexa_text

def text_to_hexadecimal_string(text):
    hexa_text = ""
    for i in range(len(text)):
        hexa_text += (hex(ord(text[i]))[2:])
    return hexa_text

def hexadecimal_to_text(hexa_text):
    text = ""
    for i in range(len(hexa_text)):
        text += chr(int(hexa_text[i], 16))
    return text

def text_to_decimal(text):
    decimal_text = []
    for i in range(len(text)):
        decimal_text.append(ord(text[i]))
    return decimal_text

def decimal_to_text(decimal_text):
    text = ""
    for i in range(len(decimal_text)):
        text += chr(decimal_text[i])
    return text

def decimal_to_hexadecimal(text):
    hexa_text = []
    for i in range(len(text)):
        hexa_text.append(hex(text[i]))
    return hexa_text
    

def hexadecimal_to_decimal(matrix):
    for i in range(4):
        for j in range(4):
            matrix[i][j] = int(matrix[i][j], 16)
    return matrix

def text_to_matrix(text):
    matrix = [[0 for x in range(4)] for y in range(4)]
    k=0
    for i in range(4):
        for j in range(4):
            matrix[j][i]=text[k]
            k += 1
    return matrix

def matrix_to_text(matrix):
    text = ""
    for i in range(4):
        for j in range(4):
            text += matrix[j][i]
    return text

def matrix_to_list(matrix):
    text = []
    for i in range(4):
        for j in range(4):
            text.append(matrix[j][i])
    return text

#All print functions

def print_matrix(matrix):
    for i in range(4):
        for j in range(4):
            print(matrix[i][j], end="")
        print()
    print()


def print_hexa(text):
    hexa_text = text_to_hexadecimal(text)
    for i in range(len(hexa_text)):
        print(hexa_text[i], end=" ")
    print()


def print_decimal_as_hexadecimal(matrix):
    for i in range(4):
        for j in range(4):
            print(hex(matrix[i][j]), end=" ")
        print()
    print()

def decimal_to_hexadecimal_string(matrix):
    for i in range(4):
        for j in range(4):
            matrix[i][j] = hex(matrix[i][j])
            matrix[i][j] = matrix[i][j][2:]
    return matrix

def hexadecimal_string_to_bitvector(matrix):
    for i in range(4):
        for j in range(4):
            matrix[i][j] = BitVector(hexstring=matrix[i][j])
    return matrix

def bitvector_to_hexadecimal_string(matrix):
    for i in range(4):
        for j in range(4):
            matrix[i][j] = matrix[i][j].get_bitvector_in_hex()
    return matrix

def text_to_word(text):
    size = len(text) // 4
    matrix = [[0 for x in range(4)] for y in range(size)]
    k=0
    for i in range(size):
        for j in range(4):
            matrix[i][j]=text[k]
            k += 1
    return matrix

def print_decimal_as_hexadecimal_1D(matrix):
    for i in range(len(matrix)):
        print(hex(matrix[i]), end=" ")
    print()
    print()

def remove_padding(text, original_length):
    text = text[:original_length]
    return text

def byte_to_text(byte):
    text = ""
    for i in range(len(byte)):
        text += chr(byte[i])
    return text

def text_to_byte(text):
    byte = []
    for i in range(len(text)):
        byte.append(ord(text[i]))
    return byte

def decimal_to_byte(decimal):
    byte = []
    for i in range(len(decimal)):
        byte.append(decimal[i])
    return byte
