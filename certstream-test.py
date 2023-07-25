import os
import logging
import datetime
import certstream
import sqlite3
import threading
import time

# List to store registered terms from the txt file
registered_terms = set()

def print_callback(message, context):
    logging.debug("Message -> {}".format(message))

    if message['message_type'] == "heartbeat":
        return

    if message['message_type'] == "certificate_update":
        all_domains = message['data']['leaf_cert']['all_domains']

        if len(all_domains) == 0:
            domain = "NULL"
        else:
            domain = all_domains[0]

        timestamp = datetime.datetime.now().strftime('%m/%d/%y %H:%M:%S')

        message_text = "[{}] {} (SAN: {})".format(
            timestamp, domain, ", ".join(message['data']['leaf_cert']['all_domains'][1:])
        )

        # Check if any registered term is present in the message
        global registered_terms  # Use the global keyword to reference the global variable
        with threading.Lock():
            for term in registered_terms:
                if term in message_text.lower():
                    # Extract the domain name for uniqueness
                    domain_name = domain.split(':')[0]
                    # Check if the domain name is already present in the database
                    try:
                        with sqlite3.connect('db/certstream_db.sqlite') as conn:
                            cursor = conn.cursor()
                            cursor.execute("SELECT COUNT(*) FROM sent_messages WHERE domain=?", (domain_name,))
                            result = cursor.fetchone()
                            if result and result[0] == 0:
                                # Print the message to the console with matched term
                                print(f"{message_text} [Matched Term: {term}]")
                                log_matched_terms(timestamp, domain_name, term)
                                # Save the matched domain name and timestamp to the database
                                cursor.execute("INSERT INTO sent_messages (timestamp, domain, term) VALUES (?, ?, ?)", (timestamp, domain_name, term))
                                conn.commit()
                            else:
                                # Log to the db_checks.log file that the domain was already present
                                with open('logs/db_checks.log', 'a') as db_log_file:
                                    db_log_file.write(f"[{timestamp}] Domain '{domain_name}' already exists in the database.\n")
                    except sqlite3.Error as e:
                        logging.error("SQLite error: {}".format(e))
                    break  # Stop checking further terms once a match is found

def log_matched_terms(timestamp, message, term):
    with open('logs/matched-terms.log', 'a') as file:
        file.write(f"[{timestamp}] {message} [Matched Term: {term}]\n")

def read_terms_from_file(file_path):
    with open(file_path, 'r') as file:
        terms = set(file.read().splitlines())
    return terms

def reload_terms():
    global registered_terms
    while True:
        # Read the terms from the txt file
        new_terms = read_terms_from_file('terms.txt')
        with threading.Lock():
            registered_terms = new_terms
            print("List of terms reloaded:", registered_terms)  # Print the updated list of terms
        # Sleep for 60 seconds before reloading the terms again
        time.sleep(60)

def main():
    global registered_terms
    # Read the terms from the txt file
    registered_terms = read_terms_from_file('terms.txt')

    logging.basicConfig(format='[%(levelname)s:%(name)s] %(asctime)s - %(message)s', level=logging.INFO)

    # Create the logs folder if it doesn't exist
    if not os.path.exists('logs'):
        os.makedirs('logs')

    # Create the db folder if it doesn't exist
    if not os.path.exists('db'):
        os.makedirs('db')

    # SQLite database initialization
    with sqlite3.connect('db/certstream_db.sqlite') as conn:
        cursor = conn.cursor()
        # Drop the old table if it exists
        cursor.execute("DROP TABLE IF EXISTS sent_messages")
        # Create a new table with the updated schema
        cursor.execute('''CREATE TABLE IF NOT EXISTS sent_messages 
                          (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL, domain TEXT NOT NULL, term TEXT NOT NULL)''')
        conn.commit()

    # Start the CertStream monitor
    certstream_thread = threading.Thread(target=certstream.listen_for_events, args=(print_callback,), kwargs={'url': 'wss://certstream.calidog.io/'})
    certstream_thread.start()

    # Start the timer to reload terms periodically
    reload_timer = threading.Thread(target=reload_terms)
    reload_timer.start()

    # Wait for the CertStream thread to finish
    certstream_thread.join()

if __name__ == "__main__":
    main()