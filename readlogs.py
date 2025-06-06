import json
from typing import Iterable

from cv2.aruco import Dictionary


def read_logs_from_json(file_path):
    """
    Reads logs from a JSON file and returns the content as a Python object.

    Parameters:
        file_path (str): Path to the JSON file.

    Returns:
        data (dict or list): Parsed JSON content from the file.
    """
    try:
        logs = []
        with open(file_path, 'r', encoding='utf-8') as file:
            for line in file:
                if line.strip():  # Skip empty lines
                    log_entry = json.loads(line)
                    logs.append(log_entry)
        return logs
    except FileNotFoundError:
        print(f"File not found: {file_path}")
    except json.JSONDecodeError as e:
        print(f"Error decoding JSON: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

    return None


logs = read_logs_from_json('logs/error_logs.json')

if isinstance(logs, Iterable):
    for log in logs:
        print(log)
else:
    print(logs)
