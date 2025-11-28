

# pwned_lookup.py
#
# This script checks exported password vaults (Bitwarden JSON/CSV, LastPass CSV) against the Have I Been Pwned Pwned Passwords API.
# It is designed for privacy and auditability:
#   - Only the first 5 characters of the SHA-1 hash of each password are sent to the API (k-anonymity model).
#   - No plaintext passwords or full hashes are sent over the network.
#   - Only the minimum required fields are processed for each export type.
#   - All sensitive operations are clearly commented for auditability.

import hashlib
import requests
import json
import sys
import logging
import csv
import os
from typing import List, Dict, Optional

def check_pwned_password(password: str, session: Optional[requests.Session] = None, max_retries: int = 5, backoff_start: int = 1) -> int:
    """
    Hashes the password using SHA-1 and queries the HIBP Pwned Passwords API using the k-anonymity model.
    Only the first 5 characters of the hash are sent to the API. The suffix is checked locally.
    Returns the breach count if found, otherwise 0.
    """
    sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix = sha1_hash[:5]
    suffix = sha1_hash[5:]
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    headers = {"Add-Padding": "true"}
    backoff = backoff_start
    session = session or requests.Session()
    for attempt in range(max_retries):
        try:
            response = session.get(url, headers=headers)
        except requests.RequestException as e:
            logging.error(f"Request error: {e}")
            return 0
        if response.status_code == 200:
            break
        elif response.status_code == 429:
            logging.warning("Rate limited by API, retrying...")
            import time
            time.sleep(backoff)
            backoff *= 2
        else:
            logging.error(f"Error querying API: {response.status_code}")
            return 0
    else:
        logging.error("Max retries exceeded due to rate limiting.")
        return 0
    hashes = (line.split(':') for line in response.text.splitlines())
    for hash_suffix, count in hashes:
        if hash_suffix == suffix:
            return int(count)
    return 0

def log_and_exit(message: str) -> None:
    """
    Log an error and exit the program. Used for all fatal errors to ensure clear audit trail.
    """
    logging.error(message)
    sys.exit(1)

def append_match(matches: List[Dict], name: str, username: str, password: str, count: int) -> None:
    """
    Append a credential match to the results list. Passwords are only stored in memory for reporting.
    """
    matches.append({
        'name': name,
        'username': username,
        'password': password,
        'count': count
    })

def parse_bitwarden_json(filename: str, session: requests.Session, matches: List[Dict]) -> None:
    """
    Parse a Bitwarden JSON export and check all login passwords.
    Only the 'login.password' field is checked for each item.
    """
    try:
        with open(filename, 'r') as f:
            data = json.load(f)
    except (IOError, json.JSONDecodeError) as e:
        log_and_exit(f"Failed to read or parse JSON file: {e}")
    items = data.get('items')
    if not isinstance(items, list):
        log_and_exit("No 'items' list found in Bitwarden export.")
    for item in items:
        name = item.get('name', '<no name>')
        login = item.get('login', {})
        username = login.get('username', '<no username>')
        password = login.get('password')
        if password:
            count = check_pwned_password(password, session=session)
            if count:
                append_match(matches, name, username, password, count)

def parse_bitwarden_csv(reader: csv.DictReader, session: requests.Session, matches: List[Dict]) -> None:
    """
    Parse a Bitwarden CSV export and check only rows where 'type' == 'login'.
    Only the 'login_password' column is checked for each row.
    """
    for row in reader:
        if row.get('type', '').strip().lower() != 'login':
            continue
        name = row.get('name', '<no name>')
        username = row.get('login_username', '<no username>')
        password = row.get('login_password')
        if password:
            count = check_pwned_password(password, session=session)
            if count:
                append_match(matches, name, username, password, count)

def parse_lastpass_csv(reader: csv.DictReader, session: requests.Session, matches: List[Dict]) -> None:
    """
    Parse a LastPass CSV export and check only rows where 'url' != 'http://sn' (secure note).
    Only the 'password' column is checked for each row.
    """
    for row in reader:
        url = row.get('url', '')
        if url.strip().lower() == 'http://sn':
            continue
        name = row.get('name', '<no name>')
        username = row.get('username', '<no username>')
        password = row.get('password')
        if password:
            count = check_pwned_password(password, session=session)
            if count:
                append_match(matches, name, username, password, count)
def main(filename: str) -> None:
    """
    Main entry point. Detects file type and delegates to the appropriate parser.
    All sensitive operations are logged and commented for auditability.
    """
    logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
    matches: List[Dict] = []
    session = requests.Session()
    ext = os.path.splitext(filename)[1].lower()
    if ext == '.json':
        parse_bitwarden_json(filename, session, matches)
    elif ext == '.csv':
        try:
            with open(filename, newline='', encoding='utf-8') as csvfile:
                reader = csv.DictReader(csvfile)
                headers = reader.fieldnames
                if headers and 'login_password' in headers:
                    parse_bitwarden_csv(reader, session, matches)
                else:
                    parse_lastpass_csv(reader, session, matches)
        except Exception as e:
            log_and_exit(f"Failed to read or parse CSV file: {e}")
    else:
        log_and_exit("Unsupported file type. Please provide a Bitwarden JSON or LastPass CSV export.")
    if matches:
        logging.info("Compromised credentials found:")
        for match in matches:
            logging.info(f"Name: {match['name']}, Username: {match['username']}, Password: {match['password']}, Breach Count: {match['count']}")
    else:
        logging.info("No compromised credentials found.")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python pwned_lookup.py <bitwarden_export.json|lastpass_export.csv>")
        sys.exit(1)
    main(sys.argv[1])
