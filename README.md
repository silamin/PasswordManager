Password Manager
This is a simple password manager application developed as a project for secure software development. The goal of the project is to securely store credentials on a single device while providing functionality for generating strong passwords.

Security Model Discussion
Threat Actors:
Unauthorized users attempting to access stored credentials.
Malicious software attempting to extract sensitive information from the application.
The developers themselves, as they have access to the codebase and cryptographic keys.
Security Model:
Encryption: Utilizing the Fernet symmetric encryption scheme from the cryptography library to encrypt user credentials stored on disk. This ensures that even if the data is compromised, it remains unreadable without the encryption key.
Key Handling: The encryption key is stored in a separate file (key.key) and is only accessible to the application during runtime. It is generated once and stored securely.
User Authentication: Users are required to log in with a username and password. Passwords are hashed for storage and compared during authentication.
Pitfalls/Limitations:
Key Management: While the encryption key is stored securely, any compromise of this key could lead to the exposure of all stored credentials. Therefore, protecting the key file (key.key) is crucial.
Password Strength: While the application provides a mechanism to generate strong passwords, the strength of user-generated passwords is not enforced beyond basic guidelines.
Protect Data at Rest
User credentials are encrypted using the Fernet symmetric encryption scheme before being stored on disk. This ensures that even if an attacker gains access to the stored data, it remains encrypted and unreadable without the encryption key.
Cryptographic Decisions Justification
Fernet was chosen for encryption due to its simplicity, security, and compatibility with the cryptography library. It provides authenticated encryption, protecting against data tampering and decryption by unauthorized parties.

Instructions to Run the Application
Clone the repository from GitHub.
Ensure you have Python installed on your system.
Install the required dependencies using pip install -r requirements.txt.
Run the application by executing the script password_manager.py.
Screenshots of the Product

