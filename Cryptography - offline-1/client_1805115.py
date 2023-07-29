import socket

from aes_1805115 import *
from diffie_hellman_1805115 import *

client_socket = socket.socket()

port = 1805

#open client.txt to write
file = open("client.txt", "w")


client_socket.connect(('127.0.0.1', port))

print("Connected to server")

#receive key bits
key_bits = int(client_socket.recv(1024).decode())
client_socket.send("key bits received".encode())
#receive g
g = int(client_socket.recv(1024).decode())
client_socket.send("g received".encode())
#receive p
p = int(client_socket.recv(1024).decode())
client_socket.send("p received".encode())
#receive A
A = int(client_socket.recv(1024).decode())
client_socket.send("A received".encode())

server_feedback = client_socket.recv(1024).decode()

print("all received")

file.write("g = "+str(g))
file.write("\n")
file.write("p = "+str(p))
file.write("\n")
file.write("A = "+str(A))
file.write("\n")

B, b = generate_key(p, g, key_bits)

client_socket.send(str(B).encode())
server_feedback = client_socket.recv(1024).decode()

shared_key = generate_shared_key(p, A, b)

file.write("Shared key: "+str(shared_key))
file.write("\n")
file.close()

shared_key = str(shared_key)

message = read_file("sentence.txt")
print("Plain Text: ")
print("In ASCII: ", message)
print("In Hex: ", text_to_hexadecimal_string(message))

# print("Key: ")
# print("In ASCII: ", shared_key)
# print("In Hex: ", text_to_hexadecimal_string(shared_key))

encrypted_message, original_length = generate_encrypted_text(message, shared_key, key_bits)
encrypted_message = decimal_to_text(encrypted_message)

print("Cipher Text: ")
print("In Hex: ", text_to_hexadecimal_string(encrypted_message))
print("In ASCII: ", encrypted_message)

# client_socket.send(str(original_length).encode())
# server_feedback = client_socket.recv(1024).decode()
client_socket.send(bytes(encrypted_message, 'utf-8'))
