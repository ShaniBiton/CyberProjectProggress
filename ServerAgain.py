import socket
import threading
import sqlite3
import logging
import random
import time
import json
from datetime import datetime
import os

HOST = '127.0.0.1'  # localhost
PORT = 1729

NUM_DIGITS_LENGTH_FIELD = 2
RESPONSE_LENGTH_FIELD_FORMAT = '%0' + str(NUM_DIGITS_LENGTH_FIELD) + 'd'
MAX_RESPONSE_MESSAGE_LENGTH = 10**NUM_DIGITS_LENGTH_FIELD-1


LOG_DIR = "logs"
os.makedirs(LOG_DIR, exist_ok=True)


def receive_message(client_socket, addr):
    try:
        request_length_field = client_socket.recv(NUM_DIGITS_LENGTH_FIELD).decode()
        request_length = int(request_length_field)
        request = client_socket.recv(request_length).decode()
        print(request)

        # Simulated Latency - to mimic a real life system facing heavy traffic
        delay = random.uniform(0.1, 2)  # Delay between 100ms to 2 seconds
        time.sleep(delay)
        return request
    except socket.error as e:
        print(f"Socket Error: {e}")
        client_socket.close()
        # Logging the error
        log_error(e, "socket.error", "NO QUERY", addr[0])
        return
    except ValueError as e:
        print(f"Value Error: {e}")
        # Logging the error
        log_error(e, "ValueError", "NO QUERY", addr[0])
        return
    except KeyboardInterrupt:
        print("Keyboard interrupt - stopping")
    except Exception as e:
        print(e)
        client_socket.close()
        # Logging the error
        log_error(e, "Unexpected Error", "NO QUERY", addr[0])
        return


def send_message(client_socket, response, addr):
    try:
        response_length = len(response)
        if not (response_length > MAX_RESPONSE_MESSAGE_LENGTH):
            response_length_field = RESPONSE_LENGTH_FIELD_FORMAT % response_length
            response_data = response_length_field + response
            client_socket.send(response_data.encode())
            # print("message sent successfully!")

        # Simulated Latency - to mimic a real life system facing heavy traffic
        delay = random.uniform(0.1, 2)  # Delay between 100ms to 2 seconds
        time.sleep(delay)
    except socket.error as e:
        print(f"Socket Error: {e}")
        client_socket.close()
        # Logging the error
        log_error(e, "socket.error", "NO QUERY", addr[0])
    except ValueError as e:
        print(f"Value Error: {e}")
        client_socket.close()
        # Logging the error
        log_error(e, "ValueError", "NO QUERY", addr[0])
    except KeyboardInterrupt:
        print("Keyboard interrupt - stopping")
    except Exception as e:
        print(f"Unexpected Error: {e}")
        client_socket.close()
        # Logging the error
        log_error(e, "Unexpected Error", "NO QUERY", addr[0])


def write_log(file_name, log_entry):
    file_path = os.path.join(LOG_DIR, file_name)

    # Loading existing logs if the file exists
    if os.path.exists(file_path):
        with open(file_path, "r", encoding="utf-8") as file:
            try:
                logs = json.load(file)
            except json.JSONDecodeError:
                logs = []
    else:
        logs = []


# Function to get timestamp
def get_timestamp():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


# The different types of logs
def log_connection(source_ip, username, password,  login_status):
    entry = {
        "timestamp": get_timestamp(),
        "source_ip": source_ip,
        "username": username,
        "password": password,
        "login_status": login_status
    }
    # login_status: SUCCESSFUL or FAILED

    write_log("connection_logs.json", entry)


def log_connection(source_ip, username, password,  login_status):
    entry = {
        "timestamp": get_timestamp(),
        "source_ip": source_ip,
        "username": username,
        "password": password,
        "login_status": login_status
    }
    # login_status: SUCCESSFUL or FAILED

    write_log("connection_logs.json", entry)


# Can send the error to the client for extra vulnerability
def log_error(error_message, error_type, query, source_ip):
    print("logging error")
    entry = {
        "timestamp": get_timestamp(),
        "error_type": error_type,
        "error_message": error_message,
        "query": query,
        "source_ip": source_ip
    }
    write_log("error_logs.json", entry)


def log_network(source_ip, connection_duration):
    entry = {
        "timestamp": get_timestamp(),
        "source_ip": source_ip,
        "connection_duration": connection_duration
    }
    write_log("network_logs.json", entry)


def log_interaction(source_ip, payload, resource_accessed, query):
    entry = {
        "timestamp": get_timestamp(),
        "source_ip": source_ip,
        "payload": payload,
        "query": query,
    }
    write_log("interaction_logs.json", entry)


def login(client_socket, addr):
    try:
        # Receiving the client's username
        client_username = receive_message(client_socket, addr)

        # Receiving the client's password
        client_password = receive_message(client_socket, addr)
        if client_password and client_username:
            # Connecting to the database
            conn = sqlite3.connect("Small Business")

            # Creating a cursor
            curr = conn.cursor()

            # Execute a parameterized query to fetch the password
            # No input validation, vulnerable to SQL Injection
            query = f"SELECT password FROM accounts WHERE username = '{client_username}'"
            curr.execute(query)
            result = curr.fetchone()
            curr.execute("SELECT * FROM accounts")
            rows = curr.fetchall()
            print("accounts:")
            for row in rows:
                print(row)

            # Check if we got a result from accounts
            if result:
                print(result)
                password = result[0]
                print(f"Password for {client_username}: {password}")

                # Weak password validation
                if password.lower() == client_password.lower():
                    print("Login Successful")
                    send_message(client_socket, "Login Successful", addr)

                    # Log new connection
                    log_connection(addr[0], client_username, client_password, "SUCCESSFUL")

                    # Close cursor
                    curr.close()

                    # Close connection
                    conn.close()

                    return client_username
                else:
                    send_message(client_socket, "Login Failed", addr)
                    print("Login Failed")

                    # Log new connection
                    log_connection(addr[0], client_username, client_password, "FAILED")

                    login(client_socket, addr)
            else:
                send_message(client_socket, "Login Failed", addr)
                print("Login Failed")

                # Log new connection
                log_connection(addr[0], client_username, client_password, "FAILED")

                login(client_socket, addr)
        else:
            return None
    except socket.error as e:
        print(e)
        client_socket.close()
        # Logging the error
        log_error(e, "socket.error", "NO QUERY", addr[0])
        return None
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        # # Information leakage - revealing which part of a login attempt failed
        # send_message(client_socket, f"Database error: {e}")

        # Logging the error
        log_error(e, "sqlite3.Error", f"SELECT password FROM accounts WHERE username ="
                  f" '{client_username}'", addr[0])
    except KeyboardInterrupt:
        print("Keyboard interrupt - stopping")
        return None
    except ValueError as e:
        client_socket.close()
        print(f"Exception: {e}")

        # Logging the error
        log_error(e, "ValueError", "NO QUERY", addr[0])
    finally:
        # Close cursor
        curr.close()

        # Close connection
        conn.close()


def client_entrance(client_socket, addr):
    try:
        # Login or sign up
        send_message(client_socket, "Press 'L' for Login or 'S' for Sign Up: ")

        # Receive answer
        login_or_signup = receive_message(client_socket, addr)

        if login_or_signup == "login":
            client_username = login(client_socket, addr)
        if login_or_signup == "sign up":
            client_username = sign_up(client_socket, addr)
        if client_username:
            handle_client(client_socket, client_username, addr)

    except (ValueError, socket.error) as e:
        client_socket.close()
        print(f"Exception: {e}")
        # Information leakage - revealing which part of a login attempt failed
        send_message(client_socket, f"Database error: {e}")
    except socket.error as e:
        print(e)
        client_socket.close()
        return
    except KeyboardInterrupt:
        print("Keyboard interrupt - stopping")
        client_socket.close()
    except Exception as e:
        print(e)
        client_socket.close()
        return


def main():
    try:
        # Setting up the server
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind((HOST, PORT))
        server_socket.listen(5)
        print(f"Server listening on {HOST}:{PORT}")

        # Accepting clients
        while True:
            client_socket, addr = server_socket.accept()
            print(f"Connection from {addr}")

            client_thread = threading.Thread(target=client_entrance, args=(client_socket, addr), daemon=True)
            client_thread.start()
    except socket.error as e:
        print(e)
        client_socket.close()
    except KeyboardInterrupt:
        print("Keyboard interrupt - stopping")
    except Exception as e:
        print(f"Unexpected error: {e}")
    finally:
        server_socket.close()


if __name__ == "__main__":
    main()
