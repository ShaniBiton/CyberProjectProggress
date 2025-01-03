import socket
import threading
import sqlite3
import logging
import random
import time

HOST = '127.0.0.1'  # localhost
PORT = 1729

NUM_DIGITS_LENGTH_FIELD = 2
RESPONSE_LENGTH_FIELD_FORMAT = '%0' + str(NUM_DIGITS_LENGTH_FIELD) + 'd'
MAX_RESPONSE_MESSAGE_LENGTH = 10**NUM_DIGITS_LENGTH_FIELD-1


logging.basicConfig(
    filename="server.log",  # Log file
    level=logging.INFO,     # Log level
    format="%(asctime)s - %(levelname)s - %(message)s",
)


def receive_message(client_socket):
    request_length_field = client_socket.recv(NUM_DIGITS_LENGTH_FIELD).decode()
    request_length = int(request_length_field)
    request = client_socket.recv(request_length).decode()
    print(request)

    # Simulated Latency - to mimic a real life system facing heavy traffic
    delay = random.uniform(0.1, 2)  # Delay between 100ms to 2 seconds
    time.sleep(delay)
    return request


def send_message(client_socket, response):
    response_length = len(response)
    if not (response_length > MAX_RESPONSE_MESSAGE_LENGTH):
        response_length_field = RESPONSE_LENGTH_FIELD_FORMAT % response_length
        response_data = response_length_field + response
        client_socket.send(response_data.encode())
        print("message sent successfully!")

    # Simulated Latency - to mimic a real life system facing heavy traffic
    delay = random.uniform(0.1, 2)  # Delay between 100ms to 2 seconds
    time.sleep(delay)


def login(client_socket):
    try:
        # Receiving the client's username
        client_username = receive_message(client_socket)

        # Receiving the client's password
        client_password = receive_message(client_socket)

        # Connecting to the database
        conn = sqlite3.connect("Small Business")

        # Creating a cursor
        curr = conn.cursor()

        # Execute a parameterized query to fetch the password
        # No input validation, vulnerable to SQL Injection
        query = f"SELECT password FROM accounts WHERE username = '{client_username}'"
        curr.execute(query)
        result1 = curr.fetchone()
        curr.execute("SELECT * FROM accounts")
        rows = curr.fetchall()
        print("accounts:")
        for row in rows:
            print(row)

        # No input validation, vulnerable to SQL Injection
        query = f"SELECT password FROM accounts WHERE username = '{client_username}'"
        curr.execute(query)
        result2 = curr.fetchone()
        curr.execute("SELECT * FROM admins")
        rows = curr.fetchall()
        print("admins:")
        for row in rows:
            print(row)

        print(result1)
        print(result2)
        # Check if we got a result from accounts
        if result1:
            password = result1[0]
            print(f"Password for {client_username}: {password}")

            # Weak password validation
            if password.lower() == client_password.lower():
                print("Login Successful- level of security: user ")
                send_message(client_socket, "Login Successful - level of security: user")
            else:
                send_message(client_socket, "Login Failed")
                print("Login Failed")

        # Check if we got a result from admins
        if result2:
            password = result2[0]
            print(f"Password for {client_username}: {password}")

            # Weak password validation
            if password.lower() == client_password.lower():
                print("Login Successful - level of security: admin")
                send_message(client_socket, "Login Successful - level of security: admin")
            else:
                send_message(client_socket, "Login Failed")
                print("Login Failed")
        else:
            print(f"No password found for username: {client_username}")
            send_message(client_socket, "Login Failed")

    except (ValueError, socket.error) as e:
        client_socket.close()
        print(f"Exception: {e}")
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        # Information leakage - revealing which part of a login attempt failed
        send_message(client_socket, f"Database error: {e}")
    finally:
        # Close the connection
        conn.close()


def sign_up(client_socket):
    try:
        # Connecting to the database
        conn = sqlite3.connect("Small Business")

        # Creating a cursor
        curr = conn.cursor()

        # Receive new user data
        # ID
        new_user_id = receive_message(client_socket)

        # Full name
        new_user_full_name = receive_message(client_socket)

        # Username
        new_user_username = receive_message(client_socket)

        # Password
        new_user_password = receive_message(client_socket)

        # Address
        new_user_address = receive_message(client_socket)

        # Execute a parameterized query to fetch the password
        # No input validation, vulnerable to SQL Injection
        query = (f"INSERT INTO accounts VALUES('{new_user_id}', '{new_user_full_name}', '{new_user_username}',"
                 f" '{new_user_full_name}', '{new_user_address}');")
        curr.execute(query)

        print("Successful user sign up!")

    except (ValueError, socket.error) as e:
        client_socket.close()
        print(f"Exception: {e}")
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        # Information leakage - revealing which part of a login attempt failed
        send_message(client_socket, f"Database error: {e}")
    finally:
        # Close the connection
        conn.close()


def client_place_order(client_socket):
    pass


def client_view_menu(client_socket):
    print("Sending pictures of meals to the client")


def client_view_client_profile(client_socket):
    try:
        # Connecting to the database
        conn = sqlite3.connect("Small Business")

        # Creating a cursor
        curr = conn.cursor()

        pass

    except (ValueError, socket.error) as e:
        client_socket.close()
        print(f"Exception: {e}")
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        # Information leakage - revealing which part of a login attempt failed
        send_message(client_socket, f"Database error: {e}")
    finally:
        # Close the connection
        conn.close()


def handle_client(client_socket):
    try:
        # Login or sign up
        send_message(client_socket, "Press 'L' for Login or 'S' for Sign Up: ")

        # Receive answer
        login_or_signup = receive_message(client_socket)

        if login_or_signup == "login":
            login(client_socket)
        if login_or_signup == "sign up":
            sign_up(client_socket)

        # User logged in, can execute several actions, now chose one:
        user_action = receive_message(client_socket)
        if user_action == "order":
            print("order")
            client_place_order()
        elif user_action == "menu":
            print("menu")
            client_view_menu()
        elif user_action == "profile":
            print("profile")
            client_view_client_profile()
    except (ValueError, socket.error) as e:
        client_socket.close()
        print(f"Exception: {e}")
        # Information leakage - revealing which part of a login attempt failed
        send_message(client_socket, f"Database error: {e}")


def main():
    # Setting up the server
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((HOST, PORT))
    server_socket.listen(5)
    print(f"Server listening on {HOST}:{PORT}")

    while True:
        client_socket, addr = server_socket.accept()
        print(f"Connection from {addr}")

        client_thread = threading.Thread(target=handle_client, args=((client_socket,)))
        client_thread.start()


if __name__ == "__main__":
    main()

# Next thing - send buy function or view clients option - checking if someone is admin or not
