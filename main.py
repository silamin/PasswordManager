import base64
import tkinter as tk
from tkinter import messagebox, ttk
import math
import json
import secrets
import string
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.fernet import Fernet

# Constants
PASSWORD_LENGTH = 12
USERS_FILE = "users.json"
PASSWORD_PROMPT = "Password"
USERNAME_PROMPT = "Username"
SERVICE_PROMPT = "Service"
SEARCH_PROMPT = "Search"


def generate_strong_password(length=PASSWORD_LENGTH):
    charset = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(secrets.choice(charset) for _ in range(length))
    return password


def derive_key(username, password):
    salt = username.encode("utf-8")  # Use username as salt for salting
    key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100000)
    return key


def encrypt_data(data, key):
    f = Fernet(key)
    ciphertext = f.encrypt(data.encode())
    print(ciphertext)
    return ciphertext


def decrypt_data(ciphertext, key):
    f = Fernet(key)
    plaintext = f.decrypt(ciphertext).decode()
    print(plaintext)
    return json.loads(plaintext)


class LoginWindow:
    def __init__(self, root, app):
        self.root = root
        self.root.title("Password Manager")
        self.app = app

        self.root.configure(bg="#f0f0f4")

        # Logo Image
        self.logo_image = tk.PhotoImage(file="assets/img.png")
        self.logo_label = tk.Label(self.root, image=self.logo_image, bg="#f0f0f4")
        self.logo_label.pack(pady=20)

        self.welcome_label = tk.Label(self.root, text="Welcome to Password Manager", font=("Segoe UI", 16, "bold"),
                                      bg="#f0f0f4", fg="#333333")
        self.welcome_label.pack()

        self.frame = tk.Frame(self.root, bg="#f0f0f4")
        self.frame.pack(padx=20, pady=10)

        self.username_label = tk.Label(self.frame, text="Username", font=("Segoe UI", 12), bg="#f0f0f4")
        self.username_label.grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.username_entry = tk.Entry(self.frame, font=("Segoe UI", 12))
        self.username_entry.grid(row=0, column=1, padx=5, pady=5, sticky="ew")

        self.password_label = tk.Label(self.frame, text="Password", font=("Segoe UI", 12), bg="#f0f0f4")
        self.password_label.grid(row=1, column=0, padx=5, pady=5, sticky="w")
        self.password_entry = tk.Entry(self.frame, show="*", font=("Segoe UI", 12))
        self.password_entry.grid(row=1, column=1, padx=5, pady=5, sticky="ew")

        self.action_button = tk.Button(self.frame, text="Login", command=self.login_or_signup,
                                       font=("Segoe UI", 12), bg="#54a0ff", fg="white", relief=tk.FLAT)
        self.action_button.grid(row=2, column=0, columnspan=2, padx=5, pady=10, sticky="ew")

        self.switch_button_text = tk.StringVar()
        self.switch_button = tk.Button(self.root, textvariable=self.switch_button_text,
                                       command=self.switch_form, font=("Segoe UI", 10), bg="#f0f0f4", fg="#0078d4",
                                       borderwidth=0, activeforeground="#005a9e", activebackground="#f0f0f4")
        self.switch_button_text.set("Don't have an account? Sign up")
        self.switch_button.pack(pady=(5, 20))

    def login_or_signup(self):
        username = self.username_entry.get()
        password = self.password_entry.get()

        if self.action_button["text"] == "Login":
            self.login(username, password)
        else:
            self.signup(username, password)

    def login(self, username, password):

        if self.app.authenticate_user(username, password):
            messagebox.showinfo("Login Successful", "Welcome!")
            self.app.show_main_window(username)
            self.root.destroy()
        else:
            messagebox.showerror("Login Failed", "Invalid username or password")

    def signup(self, username, password):
        if self.app.register_user(username, password):
            messagebox.showinfo("Success", "User registered successfully!")
            self.app.save_users()  # Save user data after successful registration
            self.app.show_main_window(username)  # Automatically log in the user after registration
        else:
            messagebox.showerror("Error", "Username already exists. Please choose a different username.")

    def switch_form(self):
        current_action = self.action_button["text"]
        if current_action == "Login":
            self.action_button.config(text="Signup")
            self.switch_button_text.set("Already have an account? Login")
        else:
            self.action_button.config(text="Login")
            self.switch_button_text.set("Don't have an account? Sign up")

        # Clear entry fields
        self.username_entry.delete(0, tk.END)
        self.password_entry.delete(0, tk.END)


class PasswordManagerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Password Manager")
        self.root.geometry("800x600")

        self.users = self.load_users()

        self.show_login_window()

    def show_login_window(self):
        self.root.withdraw()

        self.login_window = LoginWindow(tk.Toplevel(), self)

    def show_main_window(self, username):
        self.root.deiconify()

        self.frame = tk.Frame(self.root, bg="#f0f0f4")
        self.frame.pack(fill="both", expand=True)

        filter_frame = tk.Frame(self.frame, bg="#f0f0f4")
        filter_frame.pack(side="top", fill="x", padx=20, pady=10)

        self.filter_entry = ttk.Entry(filter_frame, font=("Segoe UI", 12))
        self.filter_entry.insert(tk.END, SEARCH_PROMPT)
        self.filter_entry.bind("<FocusIn>", self.clear_filter_placeholder)
        self.filter_entry.bind("<FocusOut>", self.restore_filter_placeholder)
        self.filter_entry.bind("<KeyRelease>", self.filter_credentials)
        self.filter_entry.pack(side="left", padx=(0, 5), pady=5, fill="x", expand=True)

        clear_filter_button = ttk.Button(filter_frame, text="Clear Filter", command=self.clear_filter)
        clear_filter_button.pack(side="left", padx=(0, 5), pady=5)

        self.logout_button = ttk.Button(filter_frame, text="Logout", command=self.logout)
        self.logout_button.pack(side="right", padx=(5, 0), pady=5)

        self.treeview = ttk.Treeview(self.frame, columns=("Service", "Username", "Password"), show="headings")
        self.treeview.heading("Service", text="Service", command=lambda: self.sort_credentials("Service"))
        self.treeview.heading("Username", text="Username", command=lambda: self.sort_credentials("Username"))
        self.treeview.heading("Password", text="Password", command=lambda: self.sort_credentials("Password"))
        self.treeview.pack(padx=20, pady=(0, 10), fill="both", expand=True)

        self.show_password_button = ttk.Checkbutton(self.frame, text="Show Password",
                                                    command=self.show_password)
        self.show_password_button.pack(side="left", padx=5, pady=5)

        add_button = ttk.Button(self.frame, text="Add", command=lambda: self.show_add_window(username))
        add_button.pack(side="right", padx=5, pady=5)

        self.populate_treeview(username)

    def clear_filter(self):
        self.filter_entry.delete(0, tk.END)
        self.filter_entry.insert(tk.END, SEARCH_PROMPT)
        for child in self.treeview.get_children():
            self.treeview.item(child, tags=())

    def populate_treeview(self, username):
        self.treeview.delete(*self.treeview.get_children())
        credentials = self.users[username]["credentials"]
        for service, data in credentials.items():
            self.treeview.insert("", "end", values=(service, data["username"], data["password"]))

    def filter_credentials(self, event=None):
        query = self.filter_entry.get().lower()
        for child in self.treeview.get_children():
            values = self.treeview.item(child)["values"]
            if query in values[0].lower() or query in values[1].lower() or query in values[2].lower():
                self.treeview.item(child, tags=("matched",))
            else:
                self.treeview.item(child, tags=())

    def clear_filter_placeholder(self, event):
        if self.filter_entry.get() == SEARCH_PROMPT:
            self.filter_entry.delete(0, tk.END)
            self.filter_entry.config(foreground="black")

    def restore_filter_placeholder(self, event):
        if not self.filter_entry.get():
            self.filter_entry.insert(tk.END, SEARCH_PROMPT)
            self.filter_entry.config(foreground="grey")

    def sort_credentials(self, column):
        items = self.treeview.get_children("")
        items = sorted(items, key=lambda x: self.treeview.set(x, column))
        for index, item in enumerate(items):
            self.treeview.move(item, "", index)

    def show_password(self):
        if self.show_password_button.instate(['selected']):
            self.treeview["displaycolumns"] = ("Service", "Username")
        else:
            self.treeview["displaycolumns"] = ("Service", "Username", "Password")

    def logout(self):
        self.show_login_window()
        self.root.destroy()

    def add_credentials(self, username, service, credentials):
        self.users[username]["credentials"][service] = credentials
        self.save_users()
        self.populate_treeview(username)

    def show_add_window(self, username):
        self.add_window = AddWindow(self, username)

    def save_users(self):
        master_password = input("Enter master password: ")
        key = derive_key("master_password", master_password)
        # Ensure the key is properly encoded
        key = base64.urlsafe_b64encode(key)

        # Create a copy of users data with credentials encrypted
        encrypted_users = {}
        for username, userdata in self.users.items():
            encrypted_credentials = {}
            for service, credentials in userdata["credentials"].items():
                encrypted_username = encrypt_data(credentials["username"], key)
                encrypted_password = encrypt_data(credentials["password"], key)
                encrypted_credentials[service] = {
                    "username": encrypted_username.decode(),  # Convert bytes to string for JSON serialization
                    "password": encrypted_password.decode()   # Convert bytes to string for JSON serialization
                }
            encrypted_users[username] = {
                "password": userdata["password"],
                "credentials": encrypted_credentials
            }

        with open(USERS_FILE, "wb") as users_file:
            # Serialize the dictionary to a JSON string
            json_data = json.dumps(encrypted_users)
            # Encrypt the JSON string
            ciphertext = encrypt_data(json_data, key)
            # Write the ciphertext to the file
            users_file.write(ciphertext)

    def load_users(self):
        try:
            with open(USERS_FILE, "rb") as users_file:
                ciphertext = users_file.read()
                print("Read ciphertext from file:", ciphertext)  # Add print statement
                if ciphertext:
                    master_password = input("Enter master password: ")
                    key = derive_key("master_password", master_password)
                    key = base64.urlsafe_b64encode(key)

                    print("Derived key:", key)  # Add print statement
                    decrypted_data = decrypt_data(ciphertext, key)
                    print("Decrypted data:", decrypted_data)  # Add print statement
                    if decrypted_data:
                        return decrypted_data
                    else:
                        return {}  # Return empty dictionary if decrypted data is empty or invalid
                else:
                    return {}  # Empty dictionary for new users
        except (FileNotFoundError, json.decoder.JSONDecodeError):
            return {}  # Empty dictionary for new users

    # Modify the authenticate_user method to compare hashed passwords
    def authenticate_user(self, username, password):
        if username in self.users:
            stored_password = self.users[username].get("password")
            hashed_password = hashlib.sha256(password.encode()).hexdigest()
            return stored_password == hashed_password
        return False
    import hashlib

    # Modify the register_user method to hash the password before storing it
    def register_user(self, username, password):
        if username not in self.users:
            hashed_password = hashlib.sha256(password.encode()).hexdigest()
            self.users[username] = {"password": hashed_password, "credentials": {}}
            return True
        return False


class AddWindow:
    def __init__(self, app, username):
        self.app = app
        self.user = username

        self.root = tk.Toplevel()
        self.root.title("Add Credentials")

        self.frame = tk.Frame(self.root)
        self.frame.pack(padx=20, pady=10)

        self.service_label = ttk.Label(self.frame, text="Service", font=("Segoe UI", 12))
        self.service_label.grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.service_entry = ttk.Entry(self.frame, font=("Segoe UI", 12))
        self.service_entry.grid(row=0, column=1, padx=5, pady=5, sticky="ew")

        self.username_label = ttk.Label(self.frame, text="Username", font=("Segoe UI", 12))
        self.username_label.grid(row=1, column=0, padx=5, pady=5, sticky="w")
        self.username_entry = ttk.Entry(self.frame, font=("Segoe UI", 12))
        self.username_entry.grid(row=1, column=1, padx=5, pady=5, sticky="ew")

        self.password_label = ttk.Label(self.frame, text="Password", font=("Segoe UI", 12))
        self.password_label.grid(row=2, column=0, padx=5, pady=5, sticky="w")
        self.password_entry = ttk.Entry(self.frame, font=("Segoe UI", 12))
        self.password_entry.grid(row=2, column=1, padx=5, pady=5, sticky="ew")

        self.generate_password_button = ttk.Button(self.frame, text="Generate Password",
                                                   command=self.generate_password)
        self.generate_password_button.grid(row=2, column=2, padx=5, pady=5)

        self.add_button = ttk.Button(self.frame, text="Add", command=self.add_credentials)
        self.add_button.grid(row=3, column=0, columnspan=2, pady=10)

    def generate_password(self):
        password = generate_strong_password()
        self.password_entry.delete(0, tk.END)
        self.password_entry.insert(tk.END, password)

    def add_credentials(self):
        service = self.service_entry.get()
        username = self.username_entry.get()
        password = self.password_entry.get()

        if service and username and password:
            self.app.add_credentials(self.user, service, {"username": username, "password": password})
            self.root.destroy()
        else:
            messagebox.showerror("Error", "All fields are required.")


def main():
    root = tk.Tk()
    app = PasswordManagerApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
