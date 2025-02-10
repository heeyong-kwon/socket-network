import socket

# 서버 설정
HOST_IP     = "0.0.0.0" # Server's real IP address or Domain name
HOST_PORT   = 1316     # Server's port number

# 서버 소켓 생성
server_socket   = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((HOST_IP, HOST_PORT))
server_socket.listen(5)

print(f"Server is waiting for data at {HOST_IP}:{HOST_PORT}...")

# Iterative server loop (allows multiple clients)
while True:
    # Wait for a client to connect
    client_socket, client_address   = server_socket.accept()
    print(f"Client {client_address} is connected.")
    
    try:
        # Receiving data from client
        data    = client_socket.recv(1024).decode("utf-8")
        if not data:
            continue

        # Parsing the request
        parts   = data.split("&&")
        if len(parts) != 0:
            name        = parts[0]
            message     = parts[1]
            response    = f"Welcome! {name}"

            # Printing client's name and message
            print(f"클라이언트 이름: {name}")
            print(f"클라이언트 메시지: {message}")
        else:
            response = "Invalid request. Please check the format. (name&&message)"

        # Transmitting response to client
        client_socket.send(response.encode("utf-8"))

    except Exception as e:
        print(f"Error is occured: {e}")

    finally:
        # Client socket close
        print(f"Terminating connection with client {client_address}.")
        client_socket.close()