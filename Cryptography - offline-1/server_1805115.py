import socket

from aes_1805115 import *
from diffie_hellman_1805115 import *

key_bits = 192
print("Running server_1805115.py")
p,g = diffie_hellman(key_bits)
A, a = generate_key(p, g, key_bits)
file = open("server.txt", "w")
file.write("p = "+str(p))
file.write("\n")
file.write("g= "+str(g))
file.write("\n")
file.write("A= "+str(A))

server_socket = socket.socket()
port = 1805
server_socket.bind(('127.0.0.1', port))
print("Server is listening to port ", port)

server_socket.listen(5)     #can queue up to 5 requests

while True:
    client_socket, address = server_socket.accept()
    print("Connection from: " + str(address))

    client_socket.send(str(key_bits).encode())
    feedback = client_socket.recv(1024).decode()
    print("client feedback: ", feedback)
    client_socket.send(str(g).encode())
    feedback = client_socket.recv(1024).decode()
    print("client feedback: ", feedback)
    client_socket.send(str(p).encode())
    feedback = client_socket.recv(1024).decode()
    print("client feedback: ", feedback)
    client_socket.send(str(A).encode())
    feedback = client_socket.recv(1024).decode()
    print("client feedback: ", feedback)

    client_socket.send("send B".encode())
    #receive B
    B = int(client_socket.recv(1024).decode())

    shared_key = generate_shared_key(p, B, a)

    shared_key = str(shared_key)
    file.write("\n")
    file.write("Shared key: "+shared_key)
    file.close()
   

    #client_socket.send("send original text length".encode())
    # original_length = int(client_socket.recv(1024).decode())
    
    client_socket.send("send message".encode()) 
    message = client_socket.recv(1024).decode()
    # print("message: ", message)
    
    encrypted_message = text_to_decimal(message)
    decrypted_message = aes_decryption(encrypted_message, shared_key, key_bits)
    decrypted_message = decimal_to_text(decrypted_message)

    # print("In Hex: ", text_to_hexadecimal_string(decrypted_message))
    print("Decrypted Text: ", decrypted_message)

    client_socket.close()
    break



    