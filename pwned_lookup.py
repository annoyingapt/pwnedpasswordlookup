
import hashlib
import requests
import json
import sys
import logging

def check_pwned_password(password, session=None, max_retries=5, backoff_start=1):
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
            return False
        if response.status_code == 200:
            break
        elif response.status_code == 429:
            logging.warning("Rate limited by API, retrying...")
            import time
            time.sleep(backoff)
            backoff *= 2
        else:
            logging.error(f"Error querying API: {response.status_code}")
            return False
    else:
        logging.error("Max retries exceeded due to rate limiting.")
        return False
    hashes = (line.split(':') for line in response.text.splitlines())
    for hash_suffix, count in hashes:
        if hash_suffix == suffix:
            return int(count)
    return 0

def main(filename):
    logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
    try:
        with open(filename, 'r') as f:
            data = json.load(f)
    except (IOError, json.JSONDecodeError) as e:
        logging.error(f"Failed to read or parse JSON file: {e}")
        sys.exit(1)
    matches = []
    session = requests.Session()
    items = data.get('items')
    if not isinstance(items, list):
        logging.error("No 'items' list found in Bitwarden export.")
        sys.exit(1)
    for item in items:
        name = item.get('name', '<no name>')
        login = item.get('login', {})
        username = login.get('username', '<no username>')
        password = login.get('password')
        if password:
            count = check_pwned_password(password, session=session)
            if count:
                matches.append({
                    'name': name,
                    'username': username,
                    'password': password,
                    'count': count
                })
    if matches:
        logging.info("Compromised credentials found:")
        for match in matches:
            logging.info(f"Name: {match['name']}, Username: {match['username']}, Password: {match['password']}, Breach Count: {match['count']}")
    else:
        logging.info("No compromised credentials found.")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python pwned_lookup.py <bitwarden_export.json>")
        sys.exit(1)
    main(sys.argv[1])
