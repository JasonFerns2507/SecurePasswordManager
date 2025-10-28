# Secure Command-Line Password Manager (Python)

### Objective
This project demonstrates the creation of a secure, command-line based password manager using Python. It securely stores website credentials (website name, username, password) by encrypting them using a master password and industry-standard cryptographic techniques.

This project showcases skills in:
-   Python programming for practical applications
-   Implementation of symmetric encryption (AES via Fernet)
-   Secure key derivation from a user password (PBKDF2HMAC with salting)
-   Handling sensitive data securely in memory and at rest
-   Building a basic command-line interface (CLI)

---

### How It Works

1.  **Master Password & Key Derivation:**
    * Upon first run, a unique cryptographic **salt** is generated and saved (`salt.key`).
    * The user provides a **master password**.
    * A strong encryption key is derived from the master password and the salt using **PBKDF2HMAC** with a high iteration count. This key is *never stored directly*.
2.  **Encryption:**
    * The derived key is used to initialize a **Fernet** cipher from the `cryptography` library. Fernet provides authenticated symmetric encryption (AES-128-CBC with HMAC-SHA256).
3.  **Data Storage:**
    * Credentials (website, username, password) are stored in a simple CSV file (`passwords.dat`).
    * Only the **password** field for each entry is encrypted using Fernet before being written to the file. Website and username are stored in plaintext for easier listing and retrieval.
4.  **Loading & Decryption:**
    * When the program starts, the user enters the master password.
    * The encryption key is re-derived using the stored salt.
    * The `passwords.dat` file is read, and the encrypted passwords are decrypted using the derived key, loading the data into memory.
5.  **User Interface:**
    * A simple command-line menu allows the user to add/update credentials, retrieve a password for a specific site, list all stored sites, or quit.
    * Password input uses `getpass` to prevent echoing characters to the screen.

---

### Security Features

-   **Strong Encryption:** Uses AES-128-CBC via Fernet, a well-regarded standard.
-   **Authenticated Encryption:** Fernet ensures data integrity; tampered ciphertext won't decrypt.
-   **Salted Key Derivation:** Uses PBKDF2HMAC to protect the master password against rainbow table and brute-force attacks. The unique salt prevents precomputation attacks.
-   **Secure Password Input:** Uses `getpass` to hide master password entry.
-   **No Plaintext Key Storage:** The encryption key is derived on-the-fly and only held in memory.

---

### How to Use

1.  **Prerequisites:**
    * Python 3 installed
    * `pip` (Python package installer)

2.  **Clone the repository:**
    ```bash
    git clone [https://github.com/your-username/Python-Password-Manager.git](https://github.com/your-username/Python-Password-Manager.git)
    cd Python-Password-Manager
    ```

3.  **Set up a virtual environment (Recommended):**
    ```bash
    python3 -m venv venv
    source venv/bin/activate  # On Windows use `venv\Scripts\activate`
    ```

4.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

5.  **Run the script:**
    ```bash
    python3 password_manager.py
    ```
    * The first time you run it, it will generate a `salt.key` file.
    * You will be prompted to enter a master password. **Remember this password!**
    * Follow the on-screen menu (1-4) to manage your passwords. Data is saved automatically when you add/update.

---

### Disclaimer
This is an educational project. While it uses strong cryptographic libraries and practices, always be cautious when handling real passwords. Consider using established, audited password managers for critical credentials. Do not share your `salt.key` file or commit it to public repositories if using real sensitive data.

---
