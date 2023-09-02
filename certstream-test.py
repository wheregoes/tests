import os
import logging
import datetime
import certstream
import sqlite3
import threading
import time
import whois
import json
import sched
from json import JSONEncoder
import shutil
import gzip

# List to store registered terms from the txt file
registered_terms = set()

class DateTimeEncoder(JSONEncoder):
    # Custom JSON encoder for datetime objects
    def default(self, obj):
        if isinstance(obj, datetime.datetime):
            return obj.strftime('%Y-%m-%d %H:%M:%S')
        return JSONEncoder.default(self, obj)

# Define the interval (in seconds) for database backup - default: 3600 - 1 hour
backup_interval_seconds = 3600

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

        timestamp = datetime.datetime.now().strftime('%Y/%m/%d %H:%M:%S')

        message_text = "[{}] {} (SAN: {})".format(
            timestamp, domain, ", ".join(message['data']['leaf_cert']['all_domains'][1:])
        )

        # Check if any registered term is present in the message
        global registered_terms
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

                                # Perform WHOIS lookup
                                whois_info = get_whois_info(domain_name)

                                # Save the matched domain name, timestamp, and WHOIS information to the database
                                cursor.execute("INSERT INTO sent_messages (timestamp, domain, term, whois) VALUES (?, ?, ?, ?)",
                                               (timestamp, domain_name, term, json.dumps(whois_info, cls=DateTimeEncoder)))
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

def get_whois_info(domain):
    try:
        whois_info = whois.whois(domain)
        return whois_info
    except whois.parser.PywhoisError as e:
        return {"error": str(e)}

def perform_database_backup(sc):
    # Get the current timestamp
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
    
    # Create a backup file name with the timestamp
    backup_filename = f"backup-{timestamp}.sqlite"
    
    # Path to save the backup in the "backups" folder
    backup_filepath = os.path.join('backups', backup_filename)
    
    # Path for the compressed backup file
    compressed_backup_filepath = f"{backup_filepath}.gz"
    
    # Copy the database file to create a backup
    try:
        shutil.copy('db/certstream_db.sqlite', backup_filepath)
        
        # Compress the backup file
        with open(backup_filepath, 'rb') as backup_file:
            with gzip.open(compressed_backup_filepath, 'wb') as compressed_file:
                shutil.copyfileobj(backup_file, compressed_file)
        
        # Remove the original (uncompressed) backup file
        os.remove(backup_filepath)
        
        print(f"Database backup created and compressed: {compressed_backup_filepath}")
    except Exception as e:
        print(f"Error creating database backup: {str(e)}")
    
    # Schedule the next backup
    sc.enter(backup_interval_seconds, 1, perform_database_backup, (sc,))

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

    # Create the "backups" folder if it doesn't exist
    if not os.path.exists('backups'):
        os.makedirs('backups')

    # SQLite database initialization
    with sqlite3.connect('db/certstream_db.sqlite') as conn:
        cursor = conn.cursor()
        # Drop the old table if it exists
        cursor.execute("DROP TABLE IF EXISTS sent_messages")
        # Create a new table with the updated schema
        cursor.execute('''CREATE TABLE IF NOT EXISTS sent_messages 
                          (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL, domain TEXT NOT NULL, term TEXT NOT NULL, whois TEXT)''')
        conn.commit()

    # Start the CertStream monitor
    certstream_thread = threading.Thread(target=certstream.listen_for_events, args=(print_callback,), kwargs={'url': 'wss://certstream.calidog.io/'})
    certstream_thread.start()

    # Start the timer to reload terms periodically
    reload_timer = threading.Thread(target=reload_terms)
    reload_timer.start()

    # Initialize the scheduler for database backup
    backup_scheduler = sched.scheduler(time.time, time.sleep)
    
    # Schedule the initial database backup
    backup_scheduler.enter(backup_interval_seconds, 1, perform_database_backup, (backup_scheduler,))
    
    # Start the backup scheduler thread
    backup_thread = threading.Thread(target=backup_scheduler.run)
    backup_thread.start()

    # Wait for the CertStream thread to finish
    certstream_thread.join()

if __name__ == "__main__":
    main()