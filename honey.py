import sqlite3
import json
import pandas as pd
import matplotlib.pyplot as plt
import plotly.express as px
import re
import datetime
from collections import defaultdict, deque
from datetime import datetime
import seaborn as sns

TIME_WINDOW_SECONDS = 10
MIN_REQUESTS_IN_WINDOW = 8


def interactions_over_time(gs):
    try:
        # Connecting to the database
        conn = sqlite3.connect("HoneyStats")

        # Creating a cursor
        curr = conn.cursor()
        logs = []
        with open("logs/interaction_logs.json", 'r', encoding='utf-8') as file:
            for line in file:
                if line.strip():  # Skip empty lines
                    log_entry = json.loads(line)
                    logs.append(log_entry)

        if logs:
            for log in logs:
                curr.execute("SELECT num_interactions FROM interaction_over_time WHERE time = (?)",
                             (log["timestamp"][:10],))
                num_inter = curr.fetchone()
                if num_inter:
                    updated_num_inter = num_inter[0] + 1
                    # Add one more interaction for this date
                    curr.execute("UPDATE interaction_over_time SET num_interactions = ? WHERE time = ?",
                                 (updated_num_inter, log["timestamp"][:10]))
                else:
                    curr.execute("INSERT INTO interaction_over_time VALUES(?, ?)",
                                  (log["timestamp"][:10], 1))

        # Query the data
        query = "SELECT time, num_interactions FROM interaction_over_time"
        df = pd.read_sql_query(query, conn)

        # Convert 'time' column to datetime
        df['time'] = pd.to_datetime(df['time'])

        # Add this line here to extract just MM-DD for the x-axis labels
        df['date_label'] = df['time'].dt.strftime('%m-%d')

        # Now plot using the simplified label
        plt.figure(figsize=(10, 6))
        plt.plot(df['date_label'], df['num_interactions'], marker='o', linestyle='-', color='royalblue')
        plt.title("Number of Interactions Over Time")
        plt.xlabel("Time")
        plt.ylabel("Interactions")
        plt.xticks(rotation=45)
        plt.tight_layout()
        plt.grid(True)
        plt.show()
    except FileNotFoundError:
        print("File not found: logs/interaction_logs.json")
    except json.JSONDecodeError as e:
        print(f"Error decoding JSON: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
    except sqlite3.error as e:
        print(e)
    finally:
        # Committing changes
        conn.commit()

        # Close cursor
        curr.close()

        # Close connection
        conn.close()


def error_types(fig, ds):
    # Connecting to the database
    conn = sqlite3.connect("HoneyStats")

    # Creating a cursor
    curr = conn.cursor()
    logs = []
    with open("logs/error_logs.json", 'r', encoding='utf-8') as file:
        for line in file:
            if line.strip():  # Skip empty lines
                log_entry = json.loads(line)
                logs.append(log_entry)

    if logs:
        for log in logs:
            curr.execute("SELECT amount FROM error_types WHERE type = (?)",
                         (log["error_type"],))
            num_inter = curr.fetchone()
            if num_inter:
                updated_num_inter = num_inter[0] + 1
                # Add one more interaction for this date
                curr.execute("UPDATE error_types SET amount = ? WHERE type = ?",
                             (updated_num_inter, log["error_type"]))
            else:
                curr.execute("INSERT INTO error_types VALUES(?, ?)",
                             (log["error_type"], 1))

    # Query the data
    query = "SELECT type, amount FROM error_types"
    df = pd.read_sql_query(query, conn)

    # Create plots
    bar_fig = px.bar(df, x="amount", y="type", orientation='h', title="Error Types")

    # Create the horizontal bar chart
    plt.figure(figsize=(10, 6))
    plt.barh(df["type"], df["amount"], color="skyblue")

    # Add labels and title
    plt.xlabel("Amount")
    plt.ylabel("Error Type")
    plt.title("Error Types and Their Frequencies")

    # Show the plot
    plt.tight_layout()
    plt.show()


def payload_detector(sus_inputs, rg_pattern, input_txt):
    print(input_txt)
    for keyword in sus_inputs:
        if keyword.upper() in input_txt.upper():
            return True
    for pattern in rg_pattern:
        if re.search(pattern, input_txt):
            return True
    return False


def parse_timestamp(ts):
    return datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")


def time_difference(first_time, second_time):
    time_in_sec1 = int(first_time[11:13])*3600 + int(first_time[14:16])*60 + int(first_time[17:])
    time_in_sec2 = int(second_time[11:13])*3600 + int(second_time[14:16])*60 + int(second_time[17:])
    return time_in_sec2 - time_in_sec1


def attack_types():
    # Connecting to the database
    conn = sqlite3.connect("HoneyStats")

    # Creating a cursor
    curr = conn.cursor()
    # SQL Injection
    # Analysing the payloads
    sql_payloads = ["' OR '1'='1", "' OR 1=1--", "' OR '' = '", "' UNION SELECT username, password FROM users--",
                    "' UNION SELECT username, password FROM accounts--", "' AND 1=CONVERT(int, 'text')--",
                    "' OR IF(1=1, SLEEP(3), 0)--", "'; DROP TABLE users--", "'; DROP TABLE accounts--",
                    "'; INSERT INTO users (username) VALUES ('evil')--", "' OR '1'='1' --", "' OR '1'='1' /* ",
                    "' UNION SELECT number, cvv FROM credit_cards--", "' UNION SELECT card_number, cvv FROM payments--",
                    "' UNION SELECT address FROM orders--"]
    sql_trigger_words = ["UNION", "DROP", "SELECT", "OR", "INSERT", "CONVERT", "1=1"]

    sql_rg_patterns = [r"(?i)('|\")?\s*or\s+.*=.*", r"('|\")?\s*OR\s+.*=.*", r"(?i)union\s+select", r"(?i)drop\s+table",
                       r"(?i)sleep\s*\(", r"(?i)('|\")?\s*or\s+.*=.*--", r"\s*AND\s*\d\s*=\s*CONVERT\s*\(",
                       r"\s*OR\s+IF\s*\(.*\s*=.*\s*\,\s*SLEEP\s*\(\d\)\s*\,\s*.*\)", r".*\s*;\s*INSERT\s+INTO"]

    # XSS
    xss_payloads = ["<script>", "<run>", "</script>", "</run>", "<img", "<style", "<form", "<body", "<input", "alert(",
                    "prompt(", "confirm(", "eval(", "setTimeout(", "setInterval(", "Function(", "onerror=", "onload=",
                    "onclick=", "onmouseover=", "onfocus=", "onblur=", "onsubmit=", "onkeydown=", "onmousemove=",
                    "onmouseout=", "onkeypress="]

    xss_rg_patterns = [r"<\s*(script|img|iframe|onerror|onload).*?>", r"<\s*script[^>]*>", "on\w+\s*=", r"<\s*img[^>]*>",
                       r"<\s*iframe[^>]*>", r"<\s*svg[^>]*onload\s*="]

    # Data structure for the database hit barchart
    database_hits = {
        "accounts": {
            "id": 0,
            "username": 0,
            "password": 0,
            "full_name": 0,
            "security_level": 0
        },
        "orders": {
            "order_id": 0,
            "customer_name": 0,
            "address": 0,
            "order_details": 0,
            "payment_status": 0
        },
        "payments": {
            "payment_id": 0,
            "order_id": 0,
            "card_number": 0,
            "expiry_date": 0,
            "cvv": 0,
            "amount": 0,
            "status": 0
        }
    }

    interaction_logs = []
    with open("logs/interaction_logs.json", 'r', encoding='utf-8') as file:
        for line in file:
            if line.strip():  # Skip empty lines
                log_entry = json.loads(line)
                interaction_logs.append(log_entry)

    if interaction_logs:
        for log in interaction_logs:
            for payload in log["payload"]:
                print(type(payload))
                # SQL Injection
                if payload_detector(sql_trigger_words, sql_rg_patterns, payload):
                    curr.execute("SELECT num_attacks FROM attack_types WHERE a_type = 'SQL Injection'")
                    num_attacks = curr.fetchone()
                    if num_attacks:
                        curr.execute("UPDATE attack_types SET num_attacks = ? WHERE a_type = 'SQL Injection'",
                                     (num_attacks[0]+1,))
                    else:
                        curr.execute("INSERT INTO attack_types VALUES(?,?)", ("SQL Injection", 1))

                    for column in log["resource_accessed"][1]:
                        database_hits[log["resource_accessed"][0]][column] += 1

                # XSS
                if payload_detector(xss_payloads, xss_rg_patterns, payload):
                    curr.execute("SELECT num_attacks FROM attack_types WHERE a_type = 'XSS'")
                    num_attacks = curr.fetchone()
                    if num_attacks:
                        updated_num_attacks = num_attacks[0] + 1
                        curr.execute("UPDATE attack_types SET num_attacks = ? WHERE a_type = 'XSS'",
                                     (updated_num_attacks,))
                    else:
                        curr.execute("INSERT INTO attack_types VALUES(?,?)", ("XSS", 1))

                    for column in log["resource_accessed"][1]:
                        database_hits[log["resource_accessed"][0]][column] += 1

    # Brute Force
    brute_force_usernames = ["admin", "user", "root", "administrator", "privileged", "hyperuser", "megauser", "manager",
                             "guest", "rootuser", "adminuser", "adm", "info", "test", "mysql", "Oracle", "Demo",
                             "admin123"]
    brute_force_passwords = ["12345", "123456", "password", "p@ssword", "secret", "letmein"]

    connection_logs = []
    with open("logs/interaction_logs.json", 'r', encoding='utf-8') as file:
        for line in file:
            if line.strip():  # Skip empty lines
                log_entry = json.loads(line)
                connection_logs.append(log_entry)

    ip_windows = defaultdict(deque)
    attacks = []

    for entry in connection_logs:
        ip = entry["source_ip"]
        timestamp = parse_timestamp(entry["timestamp"])

        # Add the current timestamp to the IP's deque
        ip_windows[ip].append(timestamp)

        # Remove timestamps outside the sliding window
        while (ip_windows[ip] and
               (timestamp - ip_windows[ip][0]).total_seconds() > TIME_WINDOW_SECONDS):
            ip_windows[ip].popleft()

        # If enough requests are in the window, log the brute-force attempt
        if len(ip_windows[ip]) >= MIN_REQUESTS_IN_WINDOW:
            attacks.append({
                "source_ip": ip,
                "start_time": ip_windows[ip][0].strftime("%Y-%m-%d %H:%M:%S"),
                "end_time": ip_windows[ip][-1].strftime("%Y-%m-%d %H:%M:%S"),
                "requests_count": len(ip_windows[ip])
            })
            # Optional: clear deque to avoid multiple logs of same burst
            ip_windows[ip].clear()

    # Result
    for attack in attacks:
        print(attack)
    curr.execute("SELECT num_attacks FROM attack_types WHERE a_type = 'Brute Force'")
    num_brute_force = curr.fetchone()
    if num_brute_force:
        curr.execte("UPDATE attack_types SET num_attacks = ? WHERE a_type = ?", (num_brute_force[0] + len(attacks),
                                                                                 'Brute Force'))
    else:
        curr.execute("INSERT INTO attack_types VALUES(?, ?)", ('Brute Force', len(attacks)))

    # Creating the graph - a pie chart
    # Fetch the data
    # curr.execute("SELECT a_type, num_attacks FROM attack_types")
    # data = curr.fetchall()
    #
    # # Separate the data into labels and sizes
    # labels = [row[0] for row in data]
    # sizes = [row[1] for row in data]
    #
    # # Create the pie chart
    # plt.figure(figsize=(7, 7))
    # plt.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=90)
    # plt.title("Distribution of Things")
    # plt.axis('equal')
    # plt.tight_layout()
    # plt.show()

    # Prepare data for bar plot
    bar_data = []

    for table, columns in database_hits.items():
        for column, count in columns.items():
            bar_data.append({
                "Table": table,
                "Column": column,
                "Count": count
            })

    bar_df = pd.DataFrame(bar_data)

    # Define color palette per table
    palette = {
        "accounts": "#FF9999",
        "orders": "#99CCFF",
        "payments": "#99FF99"
    }

    # Plot grouped bar graph
    plt.figure(figsize=(12, 6))
    sns.barplot(data=bar_df, x="Column", y="Count", hue="Table", palette=palette)
    plt.title("Column Access Frequency by Table")
    plt.xlabel("Column")
    plt.ylabel("Access Count")
    plt.xticks(rotation=45)
    plt.legend(title="Table")
    plt.tight_layout()
    plt.show()

    # Close the connection
    curr.close()
    conn.close()


def main():
    # Connecting to the database
    conn = sqlite3.connect("HoneyStats")

    # Creating a cursor
    curr = conn.cursor()

    # Creating the table for interactions over time
    curr.execute("CREATE TABLE IF NOT EXISTS interaction_over_time(time text PRIMARY KEY, num_interactions int)")

    # Creating the table for types of errors
    curr.execute("CREATE TABLE IF NOT EXISTS error_types(type text PRIMARY KEY, amount int)")

    # Creating the table for attack types
    curr.execute("CREATE TABLE IF NOT EXISTS attack_types(a_type text PRIMARY KEY, num_attacks int)")

    # Committing changes
    conn.commit()

    # Close cursor
    curr.close()

    # Close connection
    conn.close()

    attack_types()

    # Create dashboard
    fig = plt.figure(constrained_layout=True, figsize=(18, 12))
    gs = fig.add_gridspec(3, 3)

    # interactions_over_time(gs)
    # error_types(fig, gs)


if __name__ == "__main__":
    main()
