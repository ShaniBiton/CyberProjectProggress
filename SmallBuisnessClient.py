import socket

HOST = '127.0.0.1'  # localhost
PORT = 1729
ADDR = (HOST, PORT)

NUM_DIGITS_LENGTH_FIELD = 2
REQUEST_LENGTH_FIELD_FORMAT = '%0' + str(NUM_DIGITS_LENGTH_FIELD) + 'd'
MAX_REQUEST_MESSAGE_LENGTH = 10**NUM_DIGITS_LENGTH_FIELD-1


class ClientDisconnectedError(Exception):
    """Raised when client disconnects unexpectedly"""
    pass


def send_message(client_socket, request):
    try:
        request_length = len(request)
        if not (request_length > MAX_REQUEST_MESSAGE_LENGTH):
            request_length_field = REQUEST_LENGTH_FIELD_FORMAT % request_length
            request_data = request_length_field + request
            client_socket.send(request_data.encode())
            # print("message sent successfully!")
    except socket.error as e:
        print(e)
        client_socket.close()
        return
    except KeyboardInterrupt:
        print("Keyboard interrupt - stopping")
        return
    except Exception as e:
        print(e)
        return


def receive_message(client_socket):
    try:
        request_length_field = client_socket.recv(NUM_DIGITS_LENGTH_FIELD).decode()

        if not request_length_field:  # Client disconnected cleanly
            raise ConnectionResetError("Client disconnected unexpectedly")

        request_length = int(request_length_field)

        request = client_socket.recv(request_length).decode()

        if not request:  # Client disconnected during message
            raise ConnectionResetError("Client disconnected unexpectedly")

        return request

    except (socket.error, ValueError, ConnectionResetError) as e:
        print(f"{type(e).__name__}: {e}")
        client_socket.close()
        raise  # CRUCIAL: re-raising the error so login() can exit cleanly
    except KeyboardInterrupt:
        print("Keyboard interrupt - stopping")
    except Exception as e:
        print(f"Unexpected Error: {e}")
        client_socket.close()
        return



def login(client_socket):
    try:
        username = input("Enter username: ")
        send_message(client_socket, username)
        password = input("Enter password: ")
        send_message(client_socket, password)
        login_status = receive_message(client_socket)
        print(login_status)
        if login_status == "Login Successful":
            client_handling(client_socket)
        else:
            login(client_socket)
    except socket.error as e:
        print(e)
        client_socket.close()
        return
    except KeyboardInterrupt:
        print("Keyboard interrupt - stopping")
        return
    except Exception as e:
        print(e)
        return


def sign_up(client_socket):
    try:
        # ID
        user_id = input("Enter id: ")
        send_message(client_socket, user_id)

        # Full name
        user_full_name = input("Enter full name: ")
        send_message(client_socket, user_full_name)

        # Username
        user_username = input("Enter username: ")
        send_message(client_socket, user_username)

        # Password
        user_password = input("Enter password: ")
        send_message(client_socket, user_password)

        print("Successful user sign up!")
        client_handling(client_socket)
    except (socket.error, ValueError, ConnectionResetError) as e:
        print(e)
        client_socket.close()
        return
    except KeyboardInterrupt:
        print("Keyboard interrupt - stopping")
        return
    except Exception as e:
        print(e)
        return


def place_order(client_socket):
    try:
        # Receive order details
        print("Place an order: ")   # (in the UI, will be a checkbox)
        print("| Options:                   |")
        print(" ---------------------------- ")
        print("| Food:                      |")
        print("| PIZZA MARGARITTA - Press 1 |")
        print("| PESTO PASTA      - Press 2 |")
        print("| CREAMY PASTA     - Press 3 |")
        print("| FOCACCIA         - Press 4 |")
        print("| PASTA ROSA       - Press 5 |")
        print(" ---------------------------- ")
        print("| Drinks:                    |")
        print("| WATER            - Press 6 |")
        print("| COCA COLA        - Press 7 |")
        print("| ORANGE JUICE     - Press 8 |")
        print("| COFFEE           - Press 9 |")
        print("| TEA             - Press 10 |")
        print(" ---------------------------- ")
        print("| Enter FINISH to stop       |")
        order = ""
        order_sum = 0.0
        while True:
            curr_order = input("Order of choice: ")
            if curr_order == "1":
                order_sum += 49.90
                order += "PIZZA MARGARITTA, "
            elif curr_order == "2":
                order_sum += 59.90
                order += "PESTO PASTA, "
            elif curr_order == "3":
                order_sum += 59.90
                order += "CREAMY PASTA, "
            elif curr_order == "4":
                order_sum += 29.90
                order += "FOCACCIA, "
            elif curr_order == "5":
                order_sum += 49.90
                order += "PASTA ROSA, "
            elif curr_order == "6":
                order_sum += 6.90
                order += "WATER, "
            elif curr_order == "7":
                order_sum += 9.90
                order += "COCA COLA, "
            elif curr_order == "8":
                order_sum += 9.90
                order += "ORANGE JUICE, "
            elif curr_order == "9":
                order_sum += 16.90
                order += "COFFEE, "
            elif curr_order == "10":
                order_sum += 13.90
                order += "TEA, "
            elif curr_order.lower() == "finish":
                break

        print(f"Order: {order}")
        print(f"Total: {order_sum}")

        # Send order details to the server
        send_message(client_socket, order)

        # Name
        order_address = input("Enter your full name: ")
        send_message(client_socket, order_address)

        # Address
        order_address = input("Enter your address: ")
        send_message(client_socket, order_address)

        # Payment Information
        # Card number
        payment_card_number = input("Enter your card number: ")
        send_message(client_socket, payment_card_number)

        # Expiry date
        payment_card_exdate = input("Enter your card's expiry date: ")
        send_message(client_socket, payment_card_exdate)
        # CVV
        payment_card_cvv = input("Enter your card's CVV: ")
        send_message(client_socket, payment_card_cvv)

        # Amount
        print(f"Total: {order_sum}")
        send_message(client_socket, str(order_sum))

        # Receive message from the server - order successful or failed
        order_status = receive_message(client_socket)
        print(order_status)
        client_handling(client_socket)
    except (socket.error, ValueError, ConnectionResetError) as e:
        print(e)
        client_socket.close()
        return
    except KeyboardInterrupt:
        print("Keyboard interrupt - stopping")
        return
    except Exception as e:
        print(e)
        return


def view_menu(client_socket):
    try:
        print("receive from server and print pictures of the meals")
        client_handling(client_socket)
    except socket.error as e:
        print(e)
        client_socket.close()
        return
    except KeyboardInterrupt:
        print("Keyboard interrupt - stopping")
        return
    except Exception as e:
        print(e)
        return


def view_profile(client_socket):
    try:
        # Client ID
        client_id = receive_message(client_socket)
        print(f"ID - {client_id}")
        # Client username
        client_username = receive_message(client_socket)
        print(f"Username - {client_username}")
        # Client password
        client_password = receive_message(client_socket)
        print(f"Password - {client_password}")
        # Client full name
        client_full_name = receive_message(client_socket)
        print(f"Full Name - {client_full_name}")
        client_handling(client_socket)
    except (socket.error, ValueError, ConnectionResetError) as e:
        print(e)
        client_socket.close()
        return
    except KeyboardInterrupt:
        print("Keyboard interrupt - stopping")
        return
    except Exception as e:
        print(e)
        return


def view_accounts(client_socket):
    try:
        accounts_table = receive_message(client_socket)
        print(accounts_table)
        client_handling(client_socket)
    except (socket.error, ValueError, ConnectionResetError) as e:
        print(e)
        client_socket.close()
        return
    except KeyboardInterrupt:
        print("Keyboard interrupt - stopping")
        return
    except Exception as e:
        print(e)
        return


def view_orders(client_socket):
    try:
        orders_table = receive_message(client_socket)
        print(orders_table)
        client_handling(client_socket)
    except (socket.error, ValueError, ConnectionResetError) as e:
        print(e)
        client_socket.close()
        return
    except KeyboardInterrupt:
        print("Keyboard interrupt - stopping")
        return
    except Exception as e:
        print(e)
        return


def view_payments(client_socket):
    try:
        payments_table = receive_message(client_socket)
        print(payments_table)
        client_handling(client_socket)
    except (socket.error, ValueError, ConnectionResetError) as e:
        print(e)
        client_socket.close()
        return
    except KeyboardInterrupt:
        print("Keyboard interrupt - stopping")
        return
    except Exception as e:
        print(e)
        return


def client_handling(client_socket):
    try:
        sec_level = receive_message(client_socket)[-1]
        print(f"Security level - {sec_level}")

        # User logged in, can execute several actions:
        print("| Choose action:                 |")
        print("| Press 'O' to place an order    |")
        print("| Press 'M' to view the menu     |")
        print("| Press 'P' to view your profile |")
        if sec_level == '1':
            print("| Press 'A' to view all accounts |")
            print("| Press 'B' to view all orders   |")
            print("| Press 'C' to view all payments |")
        print("| Press 'E' to exit              |")
        choice = input("Enter Here: ")
        while True:
            if choice.lower() == 'o':
                send_message(client_socket, 'order')
                place_order(client_socket)
                break
            elif choice.lower() == 'm':
                send_message(client_socket, 'menu')
                view_menu(client_socket)
                break
            elif choice.lower() == 'p':
                send_message(client_socket, 'profile')
                view_profile(client_socket)
                break
            elif choice.lower() == 'a' and sec_level == '1':
                send_message(client_socket, 'view accounts')
                view_accounts(client_socket)
                break
            elif choice.lower() == 'b' and sec_level == '1':
                send_message(client_socket, 'view orders')
                view_orders(client_socket)
                break
            elif choice.lower() == 'c' and sec_level == '1':
                send_message(client_socket, 'view payments')
                view_payments(client_socket)
                break
            elif choice.lower() == 'e':
                break
            else:
                choice = input("Incorrect input! Try again: ")
    except (socket.error, ValueError, ConnectionResetError) as e:
        print(e)
        client_socket.close()
        return
    except KeyboardInterrupt:
        print("Keyboard interrupt - stopping")
        return
    except Exception as e:
        print(e)
        return


def main():
    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect(ADDR)
        # Login or Sign Up
        print(receive_message(client_socket), end="")
        login_or_signup = input()
        while True:
            if login_or_signup.lower() == 'l':
                send_message(client_socket, 'login')
                login(client_socket)
                break
            elif login_or_signup.lower() == 's':
                send_message(client_socket, 'sign up')
                sign_up(client_socket)
                break
            else:
                login_or_signup = input("Incorrect Input! Try again: ")
    except (socket.error, ValueError, ConnectionResetError) as e:
        print(e)
        return
    except KeyboardInterrupt:
        print("Keyboard interrupt - stopping")
        return
    except Exception as e:
        print(e)
        return
    finally:
        client_socket.close()


if __name__ == '__main__':
    main()
