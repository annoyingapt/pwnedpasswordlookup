# pwnedpasswordlookup

## Exporting your Bitwarden vault to JSON

1. Log in to your Bitwarden web vault at https://vault.bitwarden.com/.
2. Go to **Tools** > **Export Vault**.
3. Select **JSON (.json)** as the export format.
4. Enter your master password and click **Export Vault**.
5. Save the exported file (e.g., `bitwarden_export.json`) securely.

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