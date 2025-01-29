import socket

# Server setting
server_address  = "0.0.0.0" # Server's real IP address or Domain name
server_port     = 1316     # Server's port number

# Connect to server
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect((server_address, server_port))

# Transmitting data to server
name    = "Hee-Yong"
message = "Hello, Server! How are you?"

request = f"{name}&&{message}"
client_socket.send(request.encode("utf-8"))

# Receiving response from server
response    = client_socket.recv(1024).decode("utf-8")
print(f"{name} : {message}")
print(f"서버 : {response}\n")

# Client socket close
client_socket.close()