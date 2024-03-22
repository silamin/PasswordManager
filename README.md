# Password Manager

This is a simple password manager application developed as a project for secure software development. The goal of the project is to securely store credentials on a single device while providing functionality for generating strong passwords.

## Security Model Discussion

### Threat Actors
- Unauthorized users attempting to access stored credentials.
- Malicious software attempting to extract sensitive information from the application.
- The developers themselves, as they have access to the codebase and cryptographic keys.

### Security Model
- **Encryption:** Utilizing the Fernet symmetric encryption scheme from the cryptography library to encrypt user credentials stored on disk.
- **Key Handling:** The encryption key is stored in a separate file (`key.key`) and is only accessible to the application during runtime.
- **User Authentication:** Users are required to log in with a username and password. Passwords are hashed for storage and compared during authentication.

### Pitfalls/Limitations
- **Key Management:** While the encryption key is stored securely, any compromise of this key could lead to the exposure of all stored credentials.
- **Password Strength:** While the application provides a mechanism to generate strong passwords, the strength of user-generated passwords is not enforced beyond basic guidelines.

## Protect Data at Rest

User credentials are encrypted using the Fernet symmetric encryption scheme before being stored on disk. This ensures that even if an attacker gains access to the stored data, it remains encrypted and unreadable without the encryption key.

### Cryptographic Decisions Justification

Fernet was chosen for encryption due to its simplicity, security, and compatibility with the cryptography library. It provides authenticated encryption, protecting against data tampering and decryption by unauthorized parties.

<div align="center">
  <img src="https://github.com/silamin/PasswordManager/assets/91031103/19441ebf-fb85-48a4-bdd6-6a9af691e256" alt="Fernet Encryption Model">
</div>

## Instructions to Run the Application

1. Clone the repository from GitHub.
2. Ensure you have Python installed on your system.
3. Install the required dependencies using `pip install -r requirements.txt`.
4. Run the application by executing the script `password_manager.py`.

## Screenshots of the Product

<div align="center">
  <img src="https://github.com/silamin/PasswordManager/assets/91031103/2b5903b7-91cb-4b93-b5bd-cd86896f9aea" alt="Screenshot 1">
</div>

<div align="center">
  <img src="https://github.com/silamin/PasswordManager/assets/91031103/6258be8e-24c5-4a58-99eb-5e4d9e9160ab" alt="Screenshot 2">
</div>
