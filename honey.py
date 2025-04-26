import sqlite3
import json
from typing import Iterable
import pandas as pd
import matplotlib.pyplot as plt
import plotly.express as px
import re


def interactions_over_time(gs):
    try:
        # Connecting to the database
        conn = sqlite3.connect("HoneyStats")

        # Creating a cursor
        curr = conn.cursor()
        with open("logs/interaction_logs.json", 'r', encoding='utf-8') as file:
            logs = json.load(file)

        if isinstance(logs, Iterable):
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
        else:
            curr.execute("SELECT num_interactions WHERE time = (?)", logs["timestamp"][:10])
            num_inter = curr.fetchone()
            if num_inter:
                updated_num_inter = num_inter[0] + 1
                # Add one more interaction for this date
                curr.execute("UPDATE interaction_over_time SET num_interactions = (?) WHERE time = (?)",
                             (updated_num_inter, logs["timestamp"][:10]))
            else:
                curr.execute("INSERT INTO interaction_over_time VALUES(?, '1')", logs["timestamp"][:10])

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
    with open("logs/error_logs.json", 'r', encoding='utf-8') as file:
        logs = json.load(file)

    if isinstance(logs, Iterable):
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
    else:
        curr.execute("SELECT amount WHERE type = (?)", logs["error_type"])
        num_inter = curr.fetchone()
        if num_inter:
            updated_num_inter = num_inter[0] + 1
            # Add one more interaction for this date
            curr.execute("UPDATE error_types SET amount = (?) WHERE type = (?)",
                         (updated_num_inter, logs["error_type"]))
        else:
            curr.execute("INSERT INTO error_types VALUES(?,?)", (logs["error_type"], 1))

    # Query the data
    query = "SELECT type, amount FROM error_types"
    df = pd.read_sql_query(query, conn)

    # Create plots
    bar_fig = px.bar(df, x="amount", y="error_type", orientation='h', title="Error Types")

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
    for keyword in sus_inputs:
        if keyword.upper() in input_txt.upper():
            return True
    for pattern in rg_pattern:
        if re.search(pattern, input_txt):
            return True
    return False


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
                       r"`(?i)(alert", r"<\s*iframe[^>]*>", r"<\s*svg[^>]*onload\s*="]

    with open("logs/interaction_logs.json", 'r', encoding='utf-8') as file:
        logs = json.load(file)

    if isinstance(logs, Iterable):
        for log in logs:
            for payload in log["payload"]:
                # SQL Injection
                if payload_detector(payload, sql_rg_patterns, sql_trigger_words):
                    curr.execute("SELECT num_attacks WHERE a_type = 'SQL Injection'")
                    num_attacks = curr.fetchone()
                    updated_num_attacks = num_attacks + 1
                    if num_attacks[0]:
                        curr.execute("UPDATE attack_types SET num_attacks = ? WHERE a_type = 'SQL Injection'",
                                     (updated_num_attacks,))
                    else:
                        curr.execute("INSERT INTO attack_types VALUES(?,?)", ("SQL Injection", 1))

                # XSS
                if payload_detector(payload, xss_rg_patterns, xss_payloads):
                    curr.execute("SELECT num_attacks WHERE a_type = 'XSS'")
                    num_attacks = curr.fetchone()
                    updated_num_attacks = num_attacks + 1
                    if num_attacks[0]:
                        curr.execute("UPDATE attack_types SET num_attacks = ? WHERE a_type = 'XSS'",
                                     (updated_num_attacks,))
                    else:
                        curr.execute("INSERT INTO attack_types VALUES(?,?)", ("XSS", 1))








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

    # Create dashboard
    fig = plt.figure(constrained_layout=True, figsize=(18, 12))
    gs = fig.add_gridspec(3, 3)

    # interactions_over_time(gs)
    error_types(fig, gs)


if __name__ == "__main__":
    main()
