# pwnedpasswordlookup
Export your Bitwarden vault and check it against HIBP PwnedPasswords. Delete the export after checking.

## Export your Bitwarden vault to JSON Using the Bitwarden Chrome Extension

1. Click the Bitwarden extension icon in your Chrome browser.
2. Log in to your vault if prompted.
3. Click the gear icon (Settings) in the lower right corner of the extension popup.
4. Select **Vault Options**.
5. Select **Export Vault**.
6. Choose **JSON (.json)** as the export format.
7. Enter your master password and confirm the export.
8. Save the exported file (e.g., `bitwarden_export.json`) securely.

## Running the Pwned Password Lookup

1. Make sure you have Python 3 installed.
2. Install dependencies from `requirements.txt`:
	```bash
	pip install -r requirements.txt
	```
2. Place your Bitwarden JSON export file in the project directory.
3. Run the program:
	```bash
	python3 pwned_lookup.py bitwarden_export.json
	```
4. The program will check each password in your vault against the Have I Been Pwned database and list any compromised credentials.