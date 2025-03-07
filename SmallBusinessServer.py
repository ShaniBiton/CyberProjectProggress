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


def receive_message(client_socket):
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
        print(e)
        client_socket.close()
    except KeyboardInterrupt:
        print("Keyboard interrupt - stopping")
    except Exception as e:
        print(e)
        client_socket.close()


def send_message(client_socket, response):
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
        print(e)
        client_socket.close()
    except KeyboardInterrupt:
        print("Keyboard interrupt - stopping")
    except Exception as e:
        print(e)
        client_socket.close()


#   Writing the logs into the JSON files
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

    # Appending new log entry
    logs.append(log_entry)

    # Writing back to the file
    with open(file_path, "w", encoding="utf-8") as file:
        json.dump(logs, file, indent=4)


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


# Can send the error to the client for extra vulnerability
def log_error(error_message, error_type, query, source_ip):
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
        result = curr.fetchone()
        curr.execute("SELECT * FROM accounts")
        rows = curr.fetchall()
        print("accounts:")
        for row in rows:
            print(row)
        print(result)
        # Check if we got a result from accounts
        if result:
            password = result[0]
            print(f"Password for {client_username}: {password}")

            # Weak password validation
            if password.lower() == client_password.lower():
                print("Login Successful")
                send_message(client_socket, "Login Successful")

                # Log new connection
                log_connection(addr[0], client_username, client_password, "SUCCESSFUL")

                return client_username
            else:
                send_message(client_socket, "Login Failed")
                print("Login Failed")

                # Log new connection
                log_connection(addr[0], client_username, client_password, "FAILED")

                login(client_socket)
        else:
            send_message(client_socket, "Login Failed")
            print("Login Failed")

            # Log new connection
            log_connection(addr[0], client_username, client_password, "FAILED")

            login(client_socket)

    except ValueError as e:
        client_socket.close()
        print(f"Exception: {e}")

        # Logging the error
        log_error(e, "ValueError", "NO QUERY", addr[0])

    except socket.error as e:
        client_socket.close()
        print(f"Exception: {e}")

        # Logging the error
        log_error(e, "socket.error", "NO QUERY", addr[0])
        
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        # Information leakage - revealing which part of a login attempt failed
        send_message(client_socket, f"Database error: {e}")

        # Logging the error
        log_error(e, "sqlite3.Error", f"SELECT password FROM accounts WHERE username ="
                  f" '{client_username}'", addr[0])

    except KeyboardInterrupt:
        print("Keyboard interrupt - stopping")
    except Exception as e:
        print(e)
        client_socket.close()
    finally:
        # Close cursor
        curr.close()

        # Close connection
        conn.close()


def sign_up(client_socket, addr):
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

        # Execute a parameterized query to fetch the password
        # No input validation, vulnerable to SQL Injection
        query = (f"INSERT INTO accounts VALUES('{new_user_id}', '{new_user_full_name}', '{new_user_username}',"
                 f" '{new_user_full_name}', 2);")
        curr.execute(query)

        # Committing changes
        conn.commit()

        print("Successful user sign up!")

        # Print updated database
        curr.execute("SELECT * FROM accounts")
        rows = curr.fetchall()

        # Printing all rows
        for row in rows:
            print(row)

        return new_user_username

    except (ValueError, socket.error) as e:
        client_socket.close()
        print(f"Exception: {e}")
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        # Information leakage - revealing which part of a login attempt failed
        send_message(client_socket, f"Database error: {e}")
    except socket.error as e:
        print(e)
        client_socket.close()
    except KeyboardInterrupt:
        print("Keyboard interrupt - stopping")
    except Exception as e:
        print(e)
        client_socket.close()
    finally:
        # Committing changes
        conn.commit()

        # Close cursor
        curr.close()

        # Close connection
        conn.close()


def client_place_order(client_socket, client_username, addr):
    try:
        # Connecting to the database
        conn = sqlite3.connect("Small Business")

        # Creating a cursor
        curr = conn.cursor()

        # Receive order from client
        # Order details
        order_details = receive_message(client_socket)

        # Name
        order_client_name = receive_message(client_socket)

        # Address
        order_address = receive_message(client_socket)

        # Payment Information
        # Card number
        payment_card = receive_message(client_socket)

        # Expiry date
        payment_card_exdate = receive_message(client_socket)

        # CVV
        payment_card_cvv = receive_message(client_socket)

        # Amount
        payment_amount = receive_message(client_socket)

        # Randomize SUCCESSFUL or FAILED payment
        payment_status_random = random.randint(0, 2)
        quarry = ""
        if payment_status_random == 0:
            # Insert data into the orders and payments tables in the database
            # Execute a parameterized query to fetch the password
            # No input validation, vulnerable to SQL Injection
            curr.execute(
                f"INSERT INTO orders (customer_name, address, order_details, payment_status) VALUES ("
                f"{order_client_name}, {order_address}, {order_details}, 'FAILED');")

            #  Logging interaction with the database
            log_interaction(addr[0], (order_client_name, order_address, order_details),
                            f"INSERT INTO orders (customer_name, address, order_details, payment_status)"
                            f" VALUES ({order_client_name}, {order_address}, {order_details}, 'FAILED');")

            order_id = curr.lastrowid
            curr.execute(f"INSERT INTO payments (order_id, card_number, expiry_date, cvv, amount, status) VALUES "
                f"({order_id},{payment_card},{payment_card_exdate},{payment_card_cvv},{payment_amount},'FAILED');")

            log_interaction(addr[0], (payment_card, payment_card_exdate, payment_card_cvv),
                            f"INSERT INTO orders (customer_name, address, order_details, payment_status)"
                            f" VALUES ({order_client_name}, {order_address}, {order_details}, 'FAILED');")

            send_message(client_socket, "payment failed")
        else:
            # Insert data into the orders and payments tables in the database
            # Execute a parameterized query to fetch the password
            # No input validation, vulnerable to SQL Injection
            curr.execute(f"INSERT INTO orders (customer_name, address, order_details, payment_status) VALUES ("
                         f"{order_client_name}, {order_address}, {order_details}, 'FAILED');")
            order_id = curr.lastrowid
            curr.execute(f"INSERT INTO payments (order_id, card_number, expiry_date, cvv, amount, status) VALUES ("
                         f"{order_id},{payment_card},{payment_card_exdate},{payment_card_cvv},{payment_amount},"
                         f"'SUCCESSFUL');")
            send_message(client_socket, "Order placed! Payment complete!")

        # Print the orders table
        curr.execute("SELECT * FROM orders")
        orders = curr.fetchall()
        for order in orders:
            print(order)

        # Print the payments table
        curr.execute("SELECT * FROM payments")
        payments = curr.fetchall()
        for payment in payments:
            print(payment)

        handle_client(client_socket,client_username)
    except (ValueError, socket.error) as e:
        client_socket.close()
        print(f"Exception: {e}")
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        # Information leakage - revealing which part of a login attempt failed
        send_message(client_socket, f"Database error: {e}")
    except socket.error as e:
        print(e)
        client_socket.close()
    except KeyboardInterrupt:
        print("Keyboard interrupt - stopping")
    except Exception as e:
        print(e)
        client_socket.close()
    finally:
        # Committing changes
        conn.commit()

        # Close cursor
        curr.close()

        # Close connection
        conn.close()


def client_view_menu(client_socket, client_username, addr):
    try:
        print("Sending pictures of meals to the client")
        handle_client(client_socket, client_username, addr)
    except KeyboardInterrupt:
        print("Keyboard interrupt - stopping")
    except Exception as e:
        print(e)
        client_socket.close()


def client_view_client_profile(client_socket, client_username, addr):
    try:
        # Connecting to the database
        conn = sqlite3.connect("Small Business")

        # Creating a cursor
        curr = conn.cursor()

        # Client ID
        client_id_curr = curr.execute(f"SELECT id FROM accounts WHERE username = '{client_username}'")
        client_id = curr.fetchone()

        #  Logging interaction with the database
        log_interaction(addr[0], client_username, "accounts", f"SELECT id FROM accounts WHERE"
                                                              f" username = '{client_username}'")
        send_message(client_socket, client_id[0])
        # Client username
        send_message(client_socket, client_username)
        # Client password
        client_password_curr = curr.execute(f"SELECT password FROM accounts WHERE username = '{client_username}'")
        client_password = curr.fetchone()

        #  Logging interaction with the database
        log_interaction(addr[0], client_username, "accounts", f"SELECT password FROM accounts WHERE"
                                                              f" username = '{client_username}'")
        send_message(client_socket, client_password[0])
        # Client full name
        client_full_name_curr = curr.execute(f"SELECT full_name FROM accounts WHERE username = '{client_username}'")
        client_full_name = curr.fetchone()

        #  Logging interaction with the database
        log_interaction(addr[0], client_username, "accounts", f"SELECT full_name FROM accounts"
                                                              f" WHERE username = '{client_username}'")
        send_message(client_socket, client_full_name[0])
        handle_client(client_socket, client_username, addr)
    except (ValueError, socket.error) as e:
        client_socket.close()
        print(f"Exception: {e}")
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        # Information leakage - revealing which part of a login attempt failed
        send_message(client_socket, f"Database error: {e}")
    except socket.error as e:
        print(e)
        client_socket.close()
    except KeyboardInterrupt:
        print("Keyboard interrupt - stopping")
    except Exception as e:
        print(e)
        client_socket.close()
    finally:
        # Committing changes
        conn.commit()

        # Close cursor
        curr.close()

        # Close connection
        conn.close()


def handle_client(client_socket, client_username, addr):
    try:
        # Connecting to the database
        conn = sqlite3.connect("Small Business")

        # Creating a cursor
        curr = conn.cursor()

        client_sec_level_curr = curr.execute(f"SELECT security_level FROM accounts WHERE username = '{client_username}'")
        client_sec_level = curr.fetchone()
        print(client_sec_level[0])

        # Send Client's Security level
        send_message(client_socket, f"Security Level - {client_sec_level[0]}")

        # User logged in, can execute several actions, now chose one:
        user_action = receive_message(client_socket)
        if user_action == "order":
            print("order")
            client_place_order(client_socket, client_username, addr)
        elif user_action == "menu":
            print("menu")
            client_view_menu(client_socket, client_username)
        elif user_action == "profile":
            print("profile")
            client_view_client_profile(client_socket, client_username, addr)
        elif user_action == "view accounts":
            print("view accounts")
            send_message(client_socket, "The accounts table")
            handle_client(client_socket, client_username, addr)
        elif user_action == "view orders":
            print("view orders")
            send_message(client_socket, "The orders table")
            handle_client(client_socket, client_username, addr)
        elif user_action == "view payments":
            print("view payments")
            send_message(client_socket, "The payments table")
            handle_client(client_socket, client_username, addr)
        elif user_action == "exit":
            pass    # Add end timer, network log
    except (ValueError, socket.error) as e:
        client_socket.close()
        print(f"Exception: {e}")
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        # Information leakage - revealing which part of a login attempt failed
        send_message(client_socket, f"Database error: {e}")
    except KeyboardInterrupt:
        print("Keyboard interrupt - stopping")
    except Exception as e:
        print(e)
        client_socket.close()
    finally:
        # Committing changes
        conn.commit()

        # Close cursor
        curr.close()

        # Close connection
        conn.close()


def client_entrance(client_socket, addr):
    try:
        # Login or sign up
        send_message(client_socket, "Press 'L' for Login or 'S' for Sign Up: ")

        # Receive answer
        login_or_signup = receive_message(client_socket)

        if login_or_signup == "login":
            login_or_sign_up = login(client_socket, addr)
        if login_or_signup == "sign up":
            login_or_sign_up = sign_up(client_socket, addr)

        handle_client(client_socket, login_or_sign_up, addr)

    except (ValueError, socket.error) as e:
        client_socket.close()
        print(f"Exception: {e}")
        # Information leakage - revealing which part of a login attempt failed
        send_message(client_socket, f"Database error: {e}")
    except socket.error as e:
        print(e)
        client_socket.close()
    except KeyboardInterrupt:
        print("Keyboard interrupt - stopping")
    except Exception as e:
        print(e)
        client_socket.close()


def main():
    try:
        # Setting up the server
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind((HOST, PORT))
        server_socket.listen(5)
        print(f"Server listening on {HOST}:{PORT}")

        while True:
            client_socket, addr = server_socket.accept()
            print(f"Connection from {addr}")

            client_thread = threading.Thread(target=client_entrance, args=((client_socket, addr)))
            client_thread.start()
    except socket.error as e:
        print(e)
        client_socket.close()
    except KeyboardInterrupt:
        print("Keyboard interrupt - stopping")
    except Exception as e:
        print(e)
        client_socket.close()


if __name__ == "__main__":
    main()
