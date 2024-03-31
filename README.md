# Autsec Password Manager

Protects passwords with AES-GCM encryption. Requires a master password for secure storage and retrieval. Simple interface for managing passwords securely.

Autsec Password Manager is a Python-based application built with Kivy framework. It enables users to securely store and retrieve passwords for various services.

# Features

- Password Encryption: Passwords are encrypted using AES-GCM encryption before storing in the database.
- Secure Storage: Utilizes SQLite database to securely store encrypted passwords.
- Master Password: Requires a master password to encrypt and decrypt passwords.
- Simple Interface: Provides a simple and intuitive interface for adding and retrieving passwords.

# How to Use

Installation:

- Ensure you have Python installed on your system.

- Install the required dependencies using pip:

pip install kivy

Running the Application:

- Run the following command to start the application:

python password_manager.py

# Adding a Password:
- Click on the "Add New Password" button.
- Enter the service name, username, and password in the popup window.
- Submit the information to securely store the password.
# Retrieving a Password:
- Click on the "Retrieve a Password" button.
- Enter the service name for which you want to retrieve the password.
- Provide your master password to decrypt and retrieve the password.

# Security Considerations

- Master Password: Choose a strong and unique master password to ensure the security of your stored passwords.
- Database Encryption: The SQLite database is encrypted with the master password to prevent unauthorized access to stored passwords.

# Disclaimer

- This application is intended for personal use and should not be used to store sensitive or critical passwords.
- While efforts have been made to implement security measures, no system can be guaranteed to be completely secure.
