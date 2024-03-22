import secrets
import tkinter as tk
from tkinter import messagebox, ttk
import json
from cryptography.fernet import Fernet
from datetime import datetime
import math
import string


def generate_strong_password(length=12):
    charset = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(secrets.choice(charset) for _ in range(length))
    return password


class LoginWindow:
    def __init__(self, root, app):
        self.root = root
        self.root.title("Password Manager")
        self.app = app
        self.last_activity_time = datetime.now()

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
        if username and password:
            if self.app.register_user(username, password):
                messagebox.showinfo("Signup Successful", "User registered successfully. You can now login.")
                self.switch_form()
            else:
                messagebox.showerror("Signup Failed", "Username already exists.")
        else:
            messagebox.showerror("Signup Failed", "Please fill in all fields.")

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

    def check_activity(self):
        current_time = datetime.now()
        if (current_time - self.last_activity_time).total_seconds() > 300:
            self.root.destroy()
        else:
            self.root.after(1000, self.check_activity)


class PasswordManagerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Password Manager")
        self.root.geometry("800x600")
        self.logged_in_user = None
        self.credentials = {}

        try:
            with open("key.key", "rb") as key_file:
                self.key = key_file.read()
        except FileNotFoundError:
            self.key = Fernet.generate_key()
            with open("key.key", "wb") as key_file:
                key_file.write(self.key)

        self.users = self.load_users()

        self.show_login_window()

    def show_login_window(self):
        self.root.withdraw()

        self.login_window = LoginWindow(tk.Toplevel(), self)

    def clear_filter(self):
        self.filter_entry.delete(0, tk.END)
        self.display_credentials_in_treeview(sorted(self.logged_in_user_credentials.items()))

    def show_main_window(self, username):
        self.logged_in_user = username

        self.root.deiconify()

        user_credentials = self.users.get(username, {}).get("credentials", {})

        self.frame = tk.Frame(self.root, bg="#f0f0f4")
        self.frame.pack(fill="both", expand=True)

        filter_frame = tk.Frame(self.frame, bg="#f0f0f4")
        filter_frame.pack(side="top", fill="x", padx=20, pady=10)

        self.filter_entry = ttk.Entry(filter_frame, font=("Segoe UI", 12))
        self.filter_entry.insert(tk.END, "Search")
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

        self.password_entry = ttk.Entry(self.frame, show="*", font=("Segoe UI", 12))
        self.password_entry.insert(tk.END, "Password")
        self.password_entry.bind("<FocusIn>", self.clear_password_placeholder)
        self.password_entry.bind("<FocusOut>",
                                 self.restore_password_placeholder)
        self.password_entry.pack(side="left", padx=5, pady=5, fill="x", expand=True)

        self.strength_label = ttk.Label(self.frame, text="", font=("Segoe UI", 10), foreground="gray")
        self.strength_label.pack(side="left", padx=5, pady=5)


        self.service_entry = ttk.Entry(self.frame, font=("Segoe UI", 12))
        self.service_entry.insert(tk.END, "Service")
        self.service_entry.bind("<FocusIn>", self.clear_service_placeholder)
        self.service_entry.bind("<FocusOut>", self.restore_service_placeholder)
        self.username_entry = ttk.Entry(self.frame, font=("Segoe UI", 12))
        self.username_entry.insert(tk.END, "Username")
        self.username_entry.bind("<FocusIn>", self.clear_username_placeholder)
        self.username_entry.bind("<FocusOut>",
                                 self.restore_username_placeholder)

        # Add Credential Controls
        self.service_entry.pack(side="left", padx=5, pady=5, fill="x", expand=True)
        self.username_entry.pack(side="left", padx=5, pady=5, fill="x", expand=True)

        self.add_button = ttk.Button(self.frame, text="Add Credential", command=self.add_credential,
                                     style="Add.TButton")
        self.add_button.pack(side="left", padx=5, pady=5)
        self.edit_button = ttk.Button(self.frame, text="Edit Credential", command=self.edit_credential,
                                      style="Edit.TButton", state=tk.DISABLED)
        self.edit_button.pack(side="left", padx=5, pady=5)
        self.delete_button = ttk.Button(self.frame, text="Delete Credential", command=self.delete_credential,
                                        style="Delete.TButton")
        self.delete_button.pack(side="left", padx=5, pady=5)
        self.generate_button = ttk.Button(self.frame, text="Generate Password",
                                          command=self.generate_password,
                                          style="Generate.TButton")
        self.generate_button.pack(side="left", padx=5, pady=5)

        self.display_credentials_in_treeview(sorted(user_credentials.items()))

        self.treeview.bind("<<TreeviewSelect>>", self.on_treeview_select)

        self.bind_events()

    def logout(self):
        self.root.withdraw()

        self.logged_in_user = None
        self.credentials = {}

        self.login_window = LoginWindow(tk.Toplevel(), self)

    def clear_filter_placeholder(self, event):
        if self.filter_entry.get() == "Search":
            self.filter_entry.delete(0, tk.END)

    def restore_filter_placeholder(self, event):
        if not self.filter_entry.get():
            self.filter_entry.insert(tk.END, "Search")

    def generate_password(self):
        password = generate_strong_password()
        self.password_entry.delete(0, tk.END)
        self.password_entry.insert(tk.END, password)
        self.update_password_strength()

    def clear_password_placeholder(self, event):
        if self.password_entry.get() == "Password":
            self.password_entry.delete(0, tk.END)

    def restore_password_placeholder(self, event):
        if not self.password_entry.get():
            self.password_entry.insert(tk.END, "Password")

    def clear_service_placeholder(self, event):
        if self.service_entry.get() == "Service":
            self.service_entry.delete(0, tk.END)

    def restore_service_placeholder(self, event):
        if not self.service_entry.get():
            self.service_entry.insert(tk.END, "Service")

    def clear_username_placeholder(self, event):
        if self.username_entry.get() == "Username":
            self.username_entry.delete(0, tk.END)

    def restore_username_placeholder(self, event):
        if not self.username_entry.get():
            self.username_entry.insert(tk.END, "Username")

    def clear_entries(self):
        # Clear entry fields
        self.service_entry.delete(0, tk.END)
        self.username_entry.delete(0, tk.END)
        self.password_entry.delete(0, tk.END)
        self.password_entry.insert(tk.END, "Password")
        self.strength_label.config(text="")

    def bind_events(self):
        if self.password_entry is not None:
            self.password_entry.bind("<KeyRelease>", self.update_password_strength)

    def update_password_strength(self, event=None):
        password = self.password_entry.get()
        strength = self.check_password_strength(password)
        self.strength_label.config(text=f"Password Strength: {strength}")

    def check_password_strength(self, password):
        length = len(password)
        unique_chars = len(set(password))
        entropy = length * math.log2(unique_chars)

        if length < 8:
            return "Very Weak"
        elif length < 12 and (unique_chars < 8 or entropy < 40):
            return "Weak"
        elif length < 16 and (unique_chars < 12 or entropy < 60):
            return "Medium"
        elif length < 20 and (unique_chars < 16 or entropy < 80):
            return "Strong"
        elif length >= 20 and (unique_chars < 20 or entropy < 100):
            return "Very Strong"
        else:
            return "Invalid Password"

    def save_users(self):
        encrypted_data = Fernet(self.key).encrypt(json.dumps(self.users).encode())
        with open("users.json", "wb") as users_file:
            users_file.write(encrypted_data)

    def show_password(self):
        if self.password_entry.cget("show") == "*":
            self.password_entry.config(show="")
        else:
            self.password_entry.config(show="*")

    def load_users(self):
        try:
            with open("users.json", "rb") as users_file:
                encrypted_data = users_file.read()
                cipher = Fernet(self.key)
                decrypted_data = cipher.decrypt(encrypted_data)
                return json.loads(decrypted_data)
        except (FileNotFoundError, json.decoder.JSONDecodeError):
            return {}

    def display_credentials_in_treeview(self, credentials):
        for row in self.treeview.get_children():
            self.treeview.delete(row)

        for service, data in credentials:
            username = data.get("username", "")
            self.treeview.insert("", "end", values=(service, username, "*" * 8))  # Fixed length of stars

    def add_credential(self):
        if not self.logged_in_user:
            messagebox.showerror("User Not Found", "User not found. Please login again.")
            return

        service = self.service_entry.get()
        username = self.username_entry.get()
        password = self.password_entry.get()

        if service and username and password:
            if service in self.credentials:
                messagebox.showwarning("Service Exists", "Service already exists. Please edit existing credential.")
            else:
                self.credentials[service] = {"username": username, "password": password, "history": []}
                self.save_users()  # Save updated user credentials
                messagebox.showinfo("Success", "Credential added successfully.")
                self.clear_entries()
                self.display_credentials_in_treeview(sorted(self.credentials.items()))  # Update data grid
        else:
            messagebox.showerror("Error", "Please fill in all fields")

    def edit_credential(self):
        selected_item = self.treeview.selection()
        if not selected_item:
            messagebox.showwarning("No Selection", "Please select a credential to edit.")
            return

        service = self.treeview.item(selected_item, "values")[0]

        existing_data = self.credentials.get(service)

        if existing_data:
            old_username = existing_data["username"]
            old_password = existing_data["password"]

            existing_data["username"] = self.username_entry.get()
            existing_data["password"] = self.password_entry.get()

            if existing_data["username"] != old_username or existing_data["password"] != old_password:
                if existing_data["password"] != old_password and self.check_password_strength(
                        existing_data["password"]) == "Weak":
                    confirm = messagebox.askyesno("Password Weak",
                                                  "The new password is weak. Are you sure you want to continue?")
                    if not confirm:
                        # Revert changes
                        existing_data["username"] = old_username
                        existing_data["password"] = old_password
                        self.username_entry.delete(0, tk.END)
                        self.username_entry.insert(tk.END, old_username)
                        self.password_entry.delete(0, tk.END)
                        self.password_entry.insert(tk.END, old_password)
                        return

                self.save_users()

                messagebox.showinfo("Success", "Credential updated successfully.")

                self.clear_entries()

                self.display_credentials_in_treeview(sorted(self.credentials.items()))
            else:
                messagebox.showinfo("No Changes", "No changes have been made to the credential.")
        else:
            messagebox.showerror("Credential Not Found", f"Credentials for service '{service}' not found.")

    def delete_credential(self):
        selected_item = self.treeview.selection()
        if not selected_item:
            messagebox.showwarning("No Selection", "Please select a credential to delete.")
            return

        service = self.treeview.item(selected_item, "values")[0]

        confirm = messagebox.askyesno("Confirm Deletion",
                                      f"Are you sure you want to delete the credential for '{service}'?")
        if confirm:
            del self.credentials[service]

            self.save_users()

            messagebox.showinfo("Success", "Credential deleted successfully.")

            self.display_credentials_in_treeview(sorted(self.credentials.items()))

    def on_treeview_select(self, event):
        selected_item = self.treeview.focus()
        if selected_item:
            service = self.treeview.item(selected_item, "values")[0]

            existing_data = self.credentials.get(service)

            if existing_data:
                self.service_entry.delete(0, tk.END)
                self.service_entry.insert(tk.END, service)
                self.username_entry.delete(0, tk.END)
                self.username_entry.insert(tk.END, existing_data.get("username", ""))
                self.password_entry.delete(0, tk.END)
                self.password_entry.insert(tk.END, existing_data.get("password", ""))

                self.update_password_strength()

                self.edit_button.config(state=tk.NORMAL)
            else:
                self.clear_entries()
                self.edit_button.config(state=tk.DISABLED)

                messagebox.showerror("Error", f"Credential for service '{service}' not found.")
        else:
            self.edit_button.config(state=tk.DISABLED)

    def sort_credentials(self, key):
        self.display_credentials_in_treeview(sorted(self.credentials.items(), key=lambda x: x[1][key].lower()))

    def filter_credentials(self, *args):
        filter_text = self.filter_entry.get().lower()

        for row in self.treeview.get_children():
            self.treeview.delete(row)

        for service, data in self.credentials.items():
            if filter_text in service.lower() or filter_text in data["username"].lower():
                self.treeview.insert("", "end", values=(service, data["username"], "*" * 8))  # Fixed length of stars

    def register_user(self, username, password):
        if username in self.users:
            return False
        else:
            self.users[username] = {"password": password, "credentials": {}}
            self.save_users()
            return True

    def authenticate_user(self, username, password):
        if username in self.users and self.users[username]["password"] == password:
            self.credentials = self.users[username].get("credentials", {})
            return True
        else:
            return False


if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordManagerApp(root)
    root.mainloop()
