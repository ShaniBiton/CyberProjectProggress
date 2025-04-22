import sqlite3
import json
from typing import Iterable
import pandas as pd
import sqlite3
import matplotlib.pyplot as plt


def interactions_over_time():
    try:
        # Connecting to the database
        conn = sqlite3.connect("HoneyStats")

        # Creating a cursor
        curr = conn.cursor()
        with open("logs/interaction_logs.json", 'r', encoding='utf-8') as file:
            logs = json.load(file)

        if isinstance(logs, Iterable):
            for log in logs:
                curr.execute("SELECT num_interactions WHERE time = (?)", log["timestamp"][:10])
                num_inter = curr.fetchone()
                if num_inter:
                    num_inter += 1
                    # Add one more interaction for this date
                    curr.execute("UPDATE interaction_over_time SET num_interactions = (?) WHERE time = (?)",
                                 (num_inter, log["timestamp"][:10]))
                else:
                    curr.execute("INSERT INTO interaction_over_time VALUES(?, '1')", log["timestamp"][:10])
        else:
            curr.execute("SELECT num_interactions WHERE time = (?)", logs["timestamp"][:10])
            num_inter = curr.fetchone()
            if num_inter:
                num_inter += 1
                # Add one more interaction for this date
                curr.execute("UPDATE interaction_over_time SET num_interactions = (?) WHERE time = (?)",
                             (num_inter, logs["timestamp"][:10]))
            else:
                curr.execute("INSERT INTO interaction_over_time VALUES(?, '1')", logs["timestamp"][:10])

        # Query the data
        query = "SELECT time, num_interactions FROM interaction_over_time"
        df = pd.read_sql_query(query, conn)

        plt.figure(figsize=(10, 6))
        plt.plot(df['time'], df['interactions'], marker='o', linestyle='-', color='royalblue')
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


def main():
    # Connecting to the database
    conn = sqlite3.connect("HoneyStats")

    # Creating a cursor
    curr = conn.cursor()

    # Creating the table for interactions over time
    curr.execute("CREATE TABLE IF NOT EXISTS interaction_over_time(time text PRIMARY KEY, num_interactions int)")

    # Creating the table for types of errors
    curr.execute("CREATE TABLE IF NOT EXISTS error_types(type text PRIMARY KEY, amount int)")

    interactions_over_time()

    # Committing changes
    conn.commit()

    # Close cursor
    curr.close()

    # Close connection
    conn.close()


if __name__ == "__main__":
    main()
