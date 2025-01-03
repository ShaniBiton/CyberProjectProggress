import socket

HOST = '127.0.0.1'  # localhost
PORT = 1729
ADDR = (HOST, PORT)

NUM_DIGITS_LENGTH_FIELD = 2
REQUEST_LENGTH_FIELD_FORMAT = '%0' + str(NUM_DIGITS_LENGTH_FIELD) + 'd'
MAX_REQUEST_MESSAGE_LENGTH = 10**NUM_DIGITS_LENGTH_FIELD-1


def send_message(client_socket, request):
    request_length = len(request)
    if not (request_length > MAX_REQUEST_MESSAGE_LENGTH):
        request_length_field = REQUEST_LENGTH_FIELD_FORMAT % request_length
        request_data = request_length_field + request
        client_socket.send(request_data.encode())
        print("message sent successfully!")


def receive_message(client_socket):
    response_length_field = client_socket.recv(NUM_DIGITS_LENGTH_FIELD).decode()
    response_length = int(response_length_field)
    response = client_socket.recv(response_length).decode()
    print(response)
    return response


def login(client_socket):
    username = input("Enter username: ")
    send_message(client_socket, username)
    password = input("Enter password: ")
    send_message(client_socket, password)
    print(receive_message(client_socket))


def sign_up(client_socket):
    # ID
    user_id = input("Enter username: ")
    send_message(client_socket, user_id)

    # Full name
    user_full_name = input("Enter username: ")
    send_message(client_socket, user_full_name)

    # Username
    user_username = input("Enter username: ")
    send_message(client_socket, user_username)

    # Password
    user_password = input("Enter password: ")
    send_message(client_socket, user_password)

    # Address
    user_address = input("Enter password: ")
    send_message(client_socket, user_address)

    print("Successful user sign up!")


def place_order(client_socket):
    pass


def view_menu(client_socket):
    print("receive from server and print pictures of the meals")


def view_profile(client_socket):
    receive_message(client_socket)


def main():
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

    # User logged in, can execute several actions:
    print("| Choose action:                 |")
    print("| Press 'O' to place an order    |")
    print("| Press 'M' to view the menu     |")
    print("| Press 'P' to view your profile |")
    choice = input("")
    while True:
        if choice.lower() == 'o':
            send_message(client_socket, 'order')
            place_order()
            break
        elif choice.lower() == 'm':
            send_message(client_socket, 'menu')
            view_menu()
            break
        elif choice.lower() == 'p':
            send_message(client_socket, 'profile')
            view_profile()
            break
        else:
            choice = input("Incorrect input! Try again: ")


if __name__ == '__main__':
    main()



