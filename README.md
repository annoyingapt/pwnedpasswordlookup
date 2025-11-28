# pwnedpasswordlookup

## Reference

- [Have I Been Pwned Pwned Passwords API Documentation](https://haveibeenpwned.com/api/v3#PwnedPasswords)

## Exporting from Bitwarden browser extension

1. Click the Bitwarden extension icon in your browser.
2. Log in to your vault if prompted.
3. Click the gear icon (Settings) in the lower right corner of the extension popup.
4. Select **Vault Options**.
5. Select **Export Vault**.
6. Choose **JSON (.json)** or **CSV (.csv)** as the export format.
7. Enter your master password and confirm the export.
8. Save the exported file (e.g., `bitwarden_export.json`) securely.


## Exporting from LastPass

1. Log in to your LastPass vault via the web.
2. Go to **Advanced Options** > **Export**.
3. Enter your master password and confirm the export.
4. Save the file (e.g., `lastpass_export.csv`).

## Exporting from Bitwarden Vault

1. Log in to your Bitwarden vault via the web.
2. Go to **Tools** > **Export Vault**.
3. Choose **JSON (.json)** or **CSV (.csv)** as the export format.
4. Enter your master password and export.
5. Save the exported file (e.g., `bitwarden_csv_export.csv`).

## Running the Pwned Password Lookup

1. Make sure you have Python 3 installed.
2. Install dependencies from `requirements.txt`:
	```bash
	pip install -r requirements.txt
	```
3. Place your Bitwarden JSON, Bitwarden CSV, or LastPass CSV export file in the project directory.
4. Run the program with your export file:
	```bash
	python3 pwned_lookup.py <your_export_file>
	```
	For example:
	```bash
	python3 pwned_lookup.py bitwarden_export.json
	python3 pwned_lookup.py bitwarden_csv_export.csv
	python3 pwned_lookup.py lastpass_export.csv
	```
5. The program will check each password in your vault against the Have I Been Pwned database and list any compromised credentials.

### Notes on Supported Export Types

- **Bitwarden JSON**: All items in the `items` list are checked for passwords in the `login.password` field.
- **Bitwarden CSV**: Only rows where the `type` column is `login` are checked, and only the `login_password` column is used for lookups.
- **LastPass CSV**: Only rows where the `url` column is not exactly `http://sn` (Secure Note) are checked, and only the `password` column is used for lookups.
