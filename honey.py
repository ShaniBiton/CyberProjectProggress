import sqlite3
import json
from typing import Iterable


def interactions_over_time():
    try:
        # Connecting to the database
        conn = sqlite3.connect("HoneyStats")

        # Creating a cursor
        curr = conn.cursor()
        with open("logs/interaction_logs.json", 'r', encoding='utf-8') as file:
            logs = json.load(file)

        if isinstance(logs, Iterable):
            for i in range(1, len(logs)):
                if logs[i-1]["timestamp"][:10] == logs[i]["timestamp"][:10]:
                    curr.execute("SELECT num_interactions FROM interaction_over_time WHERE time = (?)",
                                 logs[i-1]["timestamp"][:10])
                    num_inter = curr.fetchone()
                    num_inter += 1
                    # Add one more interaction for this date
                    curr.execute("UPDATE interaction_over_time SET num_interactions = (?) WHERE time = (?)",
                                 (num_inter, logs[i-1]["timestamp"][:10]))
                else:
                    curr.execute("INSERT INTO interaction_over_time VALUES(?, '1')", )
        else:
            print(logs)










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

    # Committing changes
    conn.commit()

    # Close cursor
    curr.close()

    # Close connection
    conn.close()


if __name__ == "__main__":
    main()
