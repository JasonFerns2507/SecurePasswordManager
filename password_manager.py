import csv
import base64
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import getpass # To securely get password input without showing it


# --- Constants ---
SALT_FILE = "salt.key"
DATA_FILE = "passwords.dat"
# --- End Constants ---

def generate_salt():
    """Generates a new random salt and saves it to SALT_FILE."""
    salt = os.urandom(16) # Generate 16 random bytes
    try:
        with open(SALT_FILE, "wb") as f: # Write in binary mode
            f.write(salt)
        print("[+] New salt generated and saved.")
        return salt
    except IOError as e:
        print(f"[!] ERROR: Could not write salt file: {e}")
        return None

def load_salt():
    """Loads the salt from SALT_FILE. Generates a new one if it doesn't exist."""
    try:
        with open(SALT_FILE, "rb") as f: # Read in binary mode
            salt = f.read()
        if len(salt) != 16:
             print("[!] WARNING: Salt file exists but seems corrupted. Generating new salt.")
             return generate_salt()
        print("[+] Salt loaded successfully.")
        return salt
    except FileNotFoundError:
        print("[+] Salt file not found. Generating a new salt...")
        return generate_salt()
    except IOError as e:
        print(f"[!] ERROR: Could not read salt file: {e}")
        return None

def derive_key(salt, password):
    """Derives the encryption key from the salt and password using PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32, # Fernet keys are 32 bytes
        salt=salt,
        iterations=480000, # Number of rounds (higher is more secure but slower)
    )
    # Important: Encode password to bytes before deriving
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key

def load_data(f):
    """Loads and decrypts password data from DATA_FILE using the Fernet object."""
    passwords = {}
    try:
        with open(DATA_FILE, "r") as file: # Read in text mode
            reader = csv.reader(file)
            for row in reader:
                if len(row) == 3: # Ensure row has 3 parts
                    website, username, encrypted_pass = row
                    try:
                        # Decrypt the password
                        decrypted_pass = f.decrypt(encrypted_pass.encode()).decode()
                        # Store in a dictionary: passwords['website_name'] = {'username': username, 'password': decrypted_pass}
                        passwords[website] = {'username': username, 'password': decrypted_pass}
                    except Exception as e:
                        print(f"[!] Warning: Could not decrypt entry for {website}. Skipping. Error: {e}")
                else:
                    print(f"[!] Warning: Skipping malformed line: {row}")
        print(f"[+] Loaded {len(passwords)} entries.")
        return passwords
    except FileNotFoundError:
        print("[+] Data file not found. Starting fresh.")
        return {} # Return an empty dictionary if file doesn't exist
    except IOError as e:
        print(f"[!] ERROR: Could not read data file: {e}")
        return None # Indicate an error

def save_data(f, passwords):
    """Encrypts and saves password data to DATA_FILE."""
    try:
        with open(DATA_FILE, "w", newline='') as file: # Write in text mode
            writer = csv.writer(file)
            for website, credentials in passwords.items():
                username = credentials['username']
                password = credentials['password']
                # Encrypt the password before saving
                encrypted_pass = f.encrypt(password.encode()).decode()
                writer.writerow([website, username, encrypted_pass])
        print(f"[+] Saved {len(passwords)} entries.")
        return True
    except IOError as e:
        print(f"[!] ERROR: Could not write data file: {e}")
        return False

def add_password(f, passwords):
    """Adds or updates a password entry."""
    website = input("Enter website name: ").strip().lower()
    username = input("Enter username: ").strip()
    password = getpass.getpass("Enter password: ") # Use getpass for password input

    passwords[website] = {'username': username, 'password': password}
    print(f"[+] Password for {website} added/updated.")
    # Save immediately after adding/updating
    save_data(f, passwords)

def get_password(passwords):
    """Retrieves and prints the password for a given website."""
    website = input("Enter website name to retrieve password for: ").strip().lower()
    if website in passwords:
        credentials = passwords[website]
        print(f"\n--- Credentials for {website} ---")
        print(f"  Username: {credentials['username']}")
        print(f"  Password: {credentials['password']}")
        print("-" * (23 + len(website))) # Dynamic separator length
    else:
        print(f"[!] No password found for {website}.")

def list_websites(passwords):
    """Lists all websites for which passwords are stored."""
    if not passwords:
        print("[i] No passwords stored yet.")
        return

    print("\n--- Stored Websites ---")
    for website in sorted(passwords.keys()): # Sort alphabetically
        print(f"- {website}")
    print("-" * 23)

# --- Main Setup ---
# --- Main Execution Loop ---
if __name__ == "__main__":
    print("--- Secure Password Manager ---")
    
    # Load or generate the salt
    my_salt = load_salt()
    
    if not my_salt:
        print("[!] Exiting due to salt error.")
        exit() # Exit the script if salt loading failed

    master_password = getpass.getpass("Please enter your master password: ")
    
    # Derive the key
    try:
        encryption_key = derive_key(my_salt, master_password)
        f = Fernet(encryption_key)
        print("\n[+] Master password accepted. Cipher initialized.")
    except Exception as e:
        # Catch potential errors during key derivation (e.g., incorrect password with Fernet)
        # Note: A more specific error catch might be needed depending on library version
        print(f"[!] ERROR: Invalid master password or key derivation failed. {e}")
        exit()

    # Load existing password data using the derived key
    passwords_data = load_data(f)
    if passwords_data is None: # Check if loading failed critically
        print("[!] Exiting due to data load error.")
        exit()

    # --- Main Menu Loop ---
    while True:
        print("\n--- Menu ---")
        print("1. Add/Update Password")
        print("2. Get Password")
        print("3. List Websites")
        print("4. Quit")
        
        choice = input("Enter your choice (1-4): ").strip()
        
        if choice == '1':
            add_password(f, passwords_data)
        elif choice == '2':
            get_password(passwords_data)
        elif choice == '3':
            list_websites(passwords_data)
        elif choice == '4':
            print("[+] Exiting Password Manager. Goodbye!")
            break # Exit the while loop
        else:
            print("[!] Invalid choice. Please enter a number between 1 and 4.")