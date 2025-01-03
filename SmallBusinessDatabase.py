import sqlite3

# Connecting to the database
conn = sqlite3.connect("Small Business")

# Creating a cursor
curr = conn.cursor()


# Creating a table for accounts (including sensitive information)
curr.execute("CREATE TABLE IF NOT EXISTS accounts(id text PRIMARY KEY, username text, password text, full_name txt, "
             "address text, security_level int)")
# Security levels: 1 - admin, 2 - user

# Inserting random information with weak passwords and basic details
curr.execute("INSERT INTO accounts VALUES('938476529','david_<3', 'david123', 'David Smith',  "
             "'Orange St. 7', '2');")
curr.execute("INSERT INTO accounts VALUES('123456789', 'johnny1', '12345', 'Johnny Taylor',  "
             "'Main St. 5', '2');")
curr.execute("INSERT INTO accounts VALUES('987654321', 'amyrocks', 'password', 'Amy Johnson', "
             "'Pine Ave. 42', '2');")
curr.execute("INSERT INTO accounts VALUES('543216789', 'mark_boi', 'qwerty', 'Mark Brown',  "
             "'Lake View Rd. 12', '2');")
curr.execute("INSERT INTO accounts VALUES('192837465', 'sarah_cute', 'letmein', 'Sarah Green',  "
             "'Elm St. 9', '2');")
curr.execute("INSERT INTO accounts VALUES('765432198','emma*cool', 'abc123', 'Emma White',  "
             "'Willow Blvd. 23', '2');")

# Adding admin users with a higher security level
curr.execute("INSERT INTO accounts VALUES('176435897', 'admin', 'admin', 'Robert Richerman',  "
             "'Hollywood St. 23', '1');")
curr.execute("INSERT INTO accounts VALUES('928475648', 'root', 'welcome', 'Lily Mickelson ',  "
             "'Hollywood St. 25', '1');")

curr.execute("SELECT * FROM accounts")
rows = curr.fetchall()

# Printing all rows
for row in rows:
    print(row)

# SQL script
sql_script = """
-- Create the 'orders' table
CREATE TABLE IF NOT EXISTS orders (
    order_id INTEGER PRIMARY KEY,
    customer_name TEXT NOT NULL,
    address TEXT NOT NULL,
    order_details TEXT NOT NULL,
    payment_status TEXT CHECK (payment_status IN ('SUCCESSFUL', 'FAILED'))
);

-- Create the 'payments' table
CREATE TABLE IF NOT EXISTS payments (
    payment_id INTEGER PRIMARY KEY,
    order_id INTEGER,
    card_number TEXT NOT NULL,  
    expiry_date TEXT NOT NULL,
    cvv TEXT NOT NULL,
    amount REAL NOT NULL,
    status TEXT CHECK (status IN ('SUCCESSFUL', 'FAILED')) NOT NULL,
    FOREIGN KEY (order_id) REFERENCES orders(order_id)
        ON DELETE CASCADE
);

-- Create a trigger to update payment_status in the orders table
CREATE TRIGGER IF NOT EXISTS update_payment_status
AFTER INSERT ON payments
FOR EACH ROW
BEGIN
    UPDATE orders
    SET payment_status = NEW.status
    WHERE order_id = NEW.order_id;
END;
"""

# Execute the script
curr.executescript(sql_script)
print("Tables and trigger created successfully!")


# Inserting random information into the orders table
curr.execute("INSERT INTO orders VALUES(1, 'John Doe', '123 Elm St, Springfield', 'Pizza Order', 'FAILED');")
curr.execute("INSERT INTO orders VALUES(2, 'Jane Smith', '456 Oak St, Springfield', 'Pasta Order', 'SUCCESSFUL');")
curr.execute("INSERT INTO orders VALUES(3, 'Jim Brown', '789 Pine St, Springfield', 'Salad Order', 'FAILED');")
curr.execute("INSERT INTO orders VALUES(4, 'Alice Green', '101 Maple St, Springfield', 'Burger Order',"
             " 'SUCCESSFUL');")
curr.execute("INSERT INTO orders VALUES(5, 'Bob White', '202 Birch St, Springfield', 'Steak Order', 'FAILED');")
curr.execute("INSERT INTO orders VALUES(6, 'Eve Black', '303 Cedar St, Springfield', 'Fish Order', 'SUCCESSFUL');")
curr.execute("INSERT INTO orders VALUES(7, 'Charlie Blue', '404 Cherry St, Springfield', 'Chicken Order', 'FAILED');")
curr.execute("INSERT INTO orders VALUES(8, 'David Red', '505 Walnut St, Springfield', 'Tacos Order', 'SUCCESSFUL');")
curr.execute("INSERT INTO orders VALUES(9, 'Grace Yellow', '606 Willow St, Springfield', 'Soup Order', 'FAILED');")
curr.execute("INSERT INTO orders VALUES(10, 'Hank Purple', '707 Maple St, Springfield', 'Pizza Order', "
             "'SUCCESSFUL');")

# Inserting random information into the payments table
curr.execute("INSERT INTO payments VALUES(1, 1, '4111111111111111', '12/25', '123', 20.0, 'FAILED');")
curr.execute("INSERT INTO payments VALUES(2, 2, '4222222222222222', '11/24', '456', 15.0, 'SUCCESSFUL');")
curr.execute("INSERT INTO payments VALUES(3, 3, '4333333333333333', '10/23', '789', 12.0, 'FAILED');")
curr.execute("INSERT INTO payments VALUES(4, 4, '4444444444444444', '09/22', '012', 18.0, 'SUCCESSFUL');")
curr.execute("INSERT INTO payments VALUES(5, 5, '4555555555555555', '08/21', '345', 25.0, 'FAILED');")
curr.execute("INSERT INTO payments VALUES(6, 6, '4666666666666666', '07/20', '678', 22.0, 'SUCCESSFUL');")
curr.execute("INSERT INTO payments VALUES(7, 7, '4777777777777777', '06/19', '901', 19.0, 'FAILED');")
curr.execute("INSERT INTO payments VALUES(8, 8, '4888888888888888', '05/18', '234', 16.0, 'SUCCESSFUL');")
curr.execute("INSERT INTO payments VALUES(9, 9, '4999999999999999', '04/17', '567', 14.0, 'FAILED');")
curr.execute("INSERT INTO payments VALUES(10, 10, '5000000000000000', '03/16', '890', 21.0, 'SUCCESSFUL');")


# Verify the insertions (optional)
curr.execute("SELECT * FROM orders")
orders = curr.fetchall()
for order in orders:
    print(order)

curr.execute("SELECT * FROM payments")
payments = curr.fetchall()
for payment in payments:
    print(payment)

# Committing changes
conn.commit()

# Close cursor
curr.close()

# Close connection
conn.close()
