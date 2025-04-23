import sqlite3
import json
from typing import Iterable
import pandas as pd
import sqlite3
import matplotlib.pyplot as plt


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


def error_types():
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

    # Sort values if needed (optional)
    df = df.sort_values(by="amount", ascending=True)

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


def main():
    # Connecting to the database
    conn = sqlite3.connect("HoneyStats")

    # Creating a cursor
    curr = conn.cursor()

    # Creating the table for interactions over time
    curr.execute("CREATE TABLE IF NOT EXISTS interaction_over_time(time text PRIMARY KEY, num_interactions int)")

    # Creating the table for types of errors
    curr.execute("CREATE TABLE IF NOT EXISTS error_types(type text PRIMARY KEY, amount int)")

    # Create dashboard
    # fig = plt.figure(constrained_layout=True, figsize=(18, 12))
    # gs = fig.add_gridspec(3, 3)

    # interactions_over_time(gs)
    error_types()

    # Committing changes
    conn.commit()

    # Close cursor
    curr.close()

    # Close connection
    conn.close()


if __name__ == "__main__":
    main()
