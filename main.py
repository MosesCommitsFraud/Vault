import os
import sys
import base64
import hashlib
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import ctypes
import winreg
import keyboard
import win32api
import win32con
import win32process
from threading import Thread
from pathlib import Path
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from PIL import Image, ImageTk
import io

# Modern color scheme
COLORS = {
    "primary": "#2563eb",  # Blue
    "primary_dark": "#1d4ed8",  # Darker blue
    "accent": "#7c3aed",  # Purple
    "bg_dark": "#111827",  # Very dark blue-gray
    "bg_medium": "#1f2937",  # Dark blue-gray
    "bg_light": "#374151",  # Medium blue-gray
    "text_light": "#f9fafb",  # Off-white
    "text_muted": "#9ca3af",  # Gray
    "success": "#10b981",  # Green
    "warning": "#f59e0b",  # Orange
    "error": "#ef4444",  # Red
}


class SecureFileSystem:
    """Handles the encryption and decryption of files"""

    def __init__(self, master_password):
        self.salt = b'VaultSecureSalt_456'  # Fixed salt for key derivation
        self.master_password = master_password
        self.cipher = self._generate_cipher()

    def _generate_cipher(self):
        """Generate a Fernet cipher based on the password"""
        password = self.master_password.encode()
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password))
        return Fernet(key)

    def encrypt_file(self, source_path, dest_path=None):
        """Encrypt a file and save it with .vault extension"""
        if dest_path is None:
            dest_path = str(source_path) + '.vault'

        try:
            with open(source_path, 'rb') as file:
                file_data = file.read()

            # Store filename in the encrypted data
            filename = os.path.basename(source_path).encode()
            filename_len = len(filename).to_bytes(4, byteorder='big')

            # Prepare data: [4 bytes filename length][filename bytes][file data]
            data_to_encrypt = filename_len + filename + file_data

            # Encrypt the data
            encrypted_data = self.cipher.encrypt(data_to_encrypt)

            with open(dest_path, 'wb') as file:
                file.write(encrypted_data)

            return dest_path
        except Exception as e:
            print(f"Encryption error: {e}")
            return None

    def decrypt_file(self, encrypted_path, output_dir=None):
        """Decrypt a .vault file and restore the original file"""
        try:
            with open(encrypted_path, 'rb') as file:
                encrypted_data = file.read()

            # Decrypt the data
            decrypted_data = self.cipher.decrypt(encrypted_data)

            # Extract filename length (first 4 bytes)
            filename_len = int.from_bytes(decrypted_data[:4], byteorder='big')

            # Extract filename
            filename = decrypted_data[4:4 + filename_len].decode()

            # Extract file contents
            file_data = decrypted_data[4 + filename_len:]

            # Determine where to save the decrypted file
            if output_dir:
                output_path = os.path.join(output_dir, filename)
            else:
                # Save in the same directory as the encrypted file
                output_path = os.path.join(os.path.dirname(encrypted_path), filename)

            with open(output_path, 'wb') as file:
                file.write(file_data)

            return output_path
        except Exception as e:
            print(f"Decryption error: {e}")
            return None


# Custom UI elements
class ModernButton(tk.Canvas):
    def __init__(self, master, text, command=None, width=120, height=36, bg=COLORS["primary"],
                 hover_bg=COLORS["primary_dark"], fg=COLORS["text_light"], radius=18, **kwargs):
        super().__init__(master, width=width, height=height, bg=master["bg"],
                         highlightthickness=0, **kwargs)
        self.bg = bg
        self.hover_bg = hover_bg
        self.fg = fg
        self.width = width
        self.height = height
        self.radius = radius
        self.command = command
        self.text = text

        # Create rounded rectangle button
        self._draw_button(bg)

        # Bind events
        self.bind("<Enter>", self._on_enter)
        self.bind("<Leave>", self._on_leave)
        self.bind("<Button-1>", self._on_click)
        self.bind("<ButtonRelease-1>", self._on_release)

    def _draw_button(self, color):
        self.delete("all")
        self.create_rounded_rect(0, 0, self.width, self.height, self.radius, fill=color, outline="")
        self.create_text(self.width / 2, self.height / 2, text=self.text, fill=self.fg, font=("Segoe UI", 10, "bold"))

    def create_rounded_rect(self, x1, y1, x2, y2, radius, **kwargs):
        points = [x1 + radius, y1,
                  x2 - radius, y1,
                  x2, y1,
                  x2, y1 + radius,
                  x2, y2 - radius,
                  x2, y2,
                  x2 - radius, y2,
                  x1 + radius, y2,
                  x1, y2,
                  x1, y2 - radius,
                  x1, y1 + radius,
                  x1, y1]
        return self.create_polygon(points, **kwargs, smooth=True)

    def _on_enter(self, event):
        self._draw_button(self.hover_bg)

    def _on_leave(self, event):
        self._draw_button(self.bg)

    def _on_click(self, event):
        self._draw_button(COLORS["bg_light"])

    def _on_release(self, event):
        self._draw_button(self.hover_bg)
        if self.command:
            self.command()


class ModernEntry(ttk.Entry):
    def __init__(self, master, **kwargs):
        style = ttk.Style()
        style.configure("Modern.TEntry",
                        fieldbackground=COLORS["bg_light"],
                        foreground=COLORS["text_light"],
                        borderwidth=0)

        super().__init__(master, style="Modern.TEntry", **kwargs)


class VaultApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Vault")
        self.root.geometry("900x600")
        self.root.resizable(True, True)
        self.root.minsize(800, 500)

        # Configure the root with dark theme
        self.root.configure(bg=COLORS["bg_dark"])

        # Set custom icon (embedded icon)
        self._set_app_icon()

        # Password and authentication state
        self.password = None
        self.authenticated = False
        self.filesystem = None

        # Hidden folder path
        documents_path = Path.home() / "Documents"
        self.hidden_folder_path = documents_path / ".vault_data"

        # Config file path
        self.config_path = self.hidden_folder_path / ".vault_config"

        # Ensure the hidden folder exists
        self.ensure_hidden_folder_exists()

        # Password hash (if previously set)
        self.password_hash = self.load_password_hash()

        # Set up startup registry entry
        self.setup_startup()

        # Set up keyboard listener
        self.setup_keyboard_listener()

        # Configure custom styles for ttk widgets
        self._configure_styles()

        # Set up the UI (either login or main interface)
        self.setup_ui()

    def _set_app_icon(self):
        """Set custom icon for the application"""
        # Base64 encoded small lock icon (you can replace with your own)
        icon_data = """
        iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAYAAABzenr0AAAACXBIWXMAAA7EAAAOxAGVKw4bAAAE5UlEQVRYhb2Xa2xTZRjHf+e0XbuurBuXbuJlGzK2dXGbYQMGZgR1mokoBmYiJgYTE5QP+EHjB6OJCR9M/CCJJiZGlAQwEYJGFLnELZssI2FzUlgHG2tbdjnQrj1tz3l9oO1Zd9pSWPw+nfd9n/M///N/nvO85xUiQorl8/nc8Xj8bcADNGcYCcADIjLoDIeHR5sXbty40ZicY7LuIxAIHHPmB7OHgs73ROQDwP2fEAiHw+8C24F46nhTg4uXlxXR6LYAsKz0hCduFJE25zh3NssYCoUcRORDEdleLp+WL6m05Zev7hPvAa/h9XqN6urqR+x2+3f5NB1AKZ2YTJJnTENSzGCVFRcLxiIjmJZJRcpVU+Mgy55DPKaxoDxOPBnHKoXJHGQ2AmVlJSilEBGamupobKzF6XQQiYyglJ5d88xJVEqRSCQ5dOgHotEolhXn9On9jI3FUEohhJ4tAZZlsXXri1y/fv3hg40hHo/T2zuIaZrTch4qAaXAlHmswCZpmKYgqmaQaZpEo1FmCwKlbGkLDEtHZA4rMJRO1SfvfZJPDh7Fio8Ri8Xo6upiaGjoge3oeRPQ0NREa2sroVAIgP7+fgYGBmag/4AE1q9fT09PD5s3b6a9vZ3W1lYOHDjAwMBAfsETUiWYAZs3b6arq4vjx4/T09PDyMgIGzZsoL29nVWrVqVfKC+BnBaEw2GuXr2K3+/n1KlTdHR0cPbsWXw+H5s2baKrqyvfctmToKOjg3PnztHe3k5nZyerV6/m+PHjdHd309vbm1dTRHImQdolGAzS19fHmTNn6O7uZu/evVy5coXly5fT2tpKMBiktbWV5cuXZ12I5EtCpZGTQGtra1phKBSiu7ubzs5O+vr6OHr0KB0dHezYsYMlS5Zw6NAh1q5dy759+zh58iT79++nrq4us8tZJ6FhGNTX19PV1cXly5c5fPgwy5Yt49ChQ/h8Pi5cuEBHRwft7e2YpsmSJUuora3NupBsNVBKpzLn6UFUAqXqUFoRZrIUpVXT2CiQpVVgqGosFcWMJ7h5M0I0OkI8Hk9bZqIHBEV9vZPCQjuGoadqQARMM0lVVR0+XwtLl/pRSiFiomkKw+YmaiW5FUti0xNImWRVT0PFJoIYSqX1THSmXwKRscw9VUr5FQoSqQRKJ+PMqAmGspGQBDIBNGKpbKeFTBUixKZ9YlOdyElDEKKZEkPZSeYIXhKVuiNmtNTUESCqyJBN12kEmgxjyiNTtKjUI9Pn0ojm1JrpSUmEhIANQZR5Px5MnQQmbRNFJm1Tjow2aTuxVtDuE+A6cBGYcgOZUgMTl8jEU5sYm9Cy5tD96pCkSAGQBK4DA8B14G8gDtTf78OMO8CJCREg+YBrTF0Dm4BoSn8UuArsBGqAw8AfMq6fkXEuNDf3C/Cz3++/AqwDmgHXA5KIAyPAMPA78BVQDLQBrwB+YCETd8X0O8CyLNra2k4MDg6+4XQ6l2maFrAs62dgtaZpdcBjoih/JE9cKGMo9fTXUvYSk5PsQAL4BfgOOAJcBAqA94CXgdx3gUlPIXQNaFicIw5YZi3X4q8RFQVNM1BAFAgDPwJfAteAeuBN4A3gkftdAymlngLeT60w10oCF9C0b9E4hdPRQI2zDoWOiDAyEuXWrSgJrQTo5Xbsa+A74JfZiIuI/At8I9OD/lXYkQAAAABJRU5ErkJggg==
        """
        try:
            icon_data = base64.b64decode(icon_data)
            icon_image = Image.open(io.BytesIO(icon_data))
            photo = ImageTk.PhotoImage(icon_image)
            self.root.iconphoto(True, photo)
        except Exception as e:
            print(f"Error setting icon: {e}")

    def _configure_styles(self):
        """Configure ttk styles for modern look"""
        style = ttk.Style()

        # Use clam as base
        style.theme_use('clam')

        # Configure TFrame
        style.configure("TFrame", background=COLORS["bg_dark"])
        style.configure("Secondary.TFrame", background=COLORS["bg_medium"])

        # Configure TLabel
        style.configure("TLabel",
                        background=COLORS["bg_dark"],
                        foreground=COLORS["text_light"],
                        font=("Segoe UI", 10))

        style.configure("Title.TLabel",
                        background=COLORS["bg_dark"],
                        foreground=COLORS["text_light"],
                        font=("Segoe UI", 18, "bold"))

        style.configure("Subtitle.TLabel",
                        background=COLORS["bg_dark"],
                        foreground=COLORS["text_light"],
                        font=("Segoe UI", 12))

        style.configure("Status.TLabel",
                        background=COLORS["bg_dark"],
                        foreground=COLORS["text_muted"],
                        font=("Segoe UI", 9))

        # Configure TEntry
        style.configure("TEntry",
                        fieldbackground=COLORS["bg_light"],
                        foreground=COLORS["text_light"],
                        borderwidth=0,
                        padding=5)

        # Configure Treeview
        style.configure("Treeview",
                        background=COLORS["bg_medium"],
                        foreground=COLORS["text_light"],
                        rowheight=25,
                        borderwidth=0,
                        font=("Segoe UI", 10))

        style.configure("Treeview.Heading",
                        background=COLORS["bg_light"],
                        foreground=COLORS["text_light"],
                        borderwidth=0,
                        font=("Segoe UI", 10, "bold"))

        style.map("Treeview",
                  background=[('selected', COLORS["primary"])],
                  foreground=[('selected', COLORS["text_light"])])

        # Configure TButton
        style.configure("TButton",
                        background=COLORS["primary"],
                        foreground=COLORS["text_light"],
                        borderwidth=0,
                        font=("Segoe UI", 10, "bold"),
                        padding=5)

        style.map("TButton",
                  background=[('active', COLORS["primary_dark"])],
                  relief=[('pressed', 'flat'), ('!pressed', 'flat')])

        # Configure TLabelframe
        style.configure("TLabelframe",
                        background=COLORS["bg_medium"],
                        foreground=COLORS["text_light"],
                        borderwidth=1,
                        relief="flat")

        style.configure("TLabelframe.Label",
                        background=COLORS["bg_medium"],
                        foreground=COLORS["text_light"],
                        font=("Segoe UI", 10, "bold"))

    def ensure_hidden_folder_exists(self):
        """Create the hidden folder if it doesn't exist and set hidden attribute"""
        if not self.hidden_folder_path.exists():
            self.hidden_folder_path.mkdir(parents=True, exist_ok=True)

        # Set folder attributes to hidden and system
        if sys.platform == 'win32':
            ctypes.windll.kernel32.SetFileAttributesW(
                str(self.hidden_folder_path),
                win32con.FILE_ATTRIBUTE_HIDDEN | win32con.FILE_ATTRIBUTE_SYSTEM
            )

    def load_password_hash(self):
        """Load password hash from config file"""
        if self.config_path.exists():
            try:
                with open(self.config_path, 'r') as f:
                    return f.read().strip()
            except:
                return None
        return None

    def save_password_hash(self, password):
        """Save password hash to config file"""
        # Create a simple hash of the password
        password_hash = hashlib.sha256(password.encode()).hexdigest()

        try:
            with open(self.config_path, 'w') as f:
                f.write(password_hash)

            # Set config file as hidden
            if sys.platform == 'win32':
                ctypes.windll.kernel32.SetFileAttributesW(
                    str(self.config_path),
                    win32con.FILE_ATTRIBUTE_HIDDEN
                )

            return password_hash
        except Exception as e:
            print(f"Error saving password: {e}")
            return None

    def setup_startup(self):
        """Add program to Windows startup registry"""
        if sys.platform == 'win32':
            try:
                # Get the path to the current executable
                exe_path = sys.executable
                if exe_path.endswith('python.exe'):
                    # If running as a script, use the script path
                    exe_path = f'"{exe_path}" "{os.path.abspath(__file__)}"'

                # Open the registry key for startup programs
                key = winreg.OpenKey(
                    winreg.HKEY_CURRENT_USER,
                    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                    0,
                    winreg.KEY_SET_VALUE
                )

                # Add our program to startup
                winreg.SetValueEx(
                    key,
                    "Vault",
                    0,
                    winreg.REG_SZ,
                    exe_path
                )
                winreg.CloseKey(key)
            except Exception as e:
                print(f"Failed to add to startup: {e}")

    def setup_keyboard_listener(self):
        """Set up keyboard shortcut for showing the application"""

        # Use a separate thread for keyboard monitoring
        def keyboard_thread():
            keyboard.add_hotkey('ctrl+alt+v', self.show_app)
            keyboard.wait()

        Thread(target=keyboard_thread, daemon=True).start()

    def show_app(self):
        """Show the application window"""
        self.root.deiconify()
        self.root.lift()
        self.root.focus_force()

    def hide_app(self):
        """Hide the application window"""
        self.root.withdraw()

    def setup_ui(self):
        """Set up the user interface"""
        # Clear any existing widgets
        for widget in self.root.winfo_children():
            widget.destroy()

        if not self.authenticated:
            self.setup_login_ui()
        else:
            self.setup_main_ui()

    def setup_login_ui(self):
        """Set up the login screen"""
        # Main container with padding
        container = ttk.Frame(self.root, style="TFrame")
        container.pack(fill=tk.BOTH, expand=True)

        # Make container grid expandable
        container.columnconfigure(0, weight=1)
        container.rowconfigure(0, weight=1)

        # Center the login box
        login_container = ttk.Frame(container, style="Secondary.TFrame", padding=30)
        login_container.grid(row=0, column=0, sticky="")
        container.grid_rowconfigure(0, weight=1)
        container.grid_columnconfigure(0, weight=1)

        # App logo/icon (placeholder)
        logo_frame = ttk.Frame(login_container, style="Secondary.TFrame")
        logo_frame.pack(pady=(0, 20))

        # Try to create a simple lock icon
        canvas = tk.Canvas(logo_frame, width=80, height=80, bg=COLORS["bg_medium"],
                           highlightthickness=0)
        canvas.pack()

        # Draw a simple lock shape
        canvas.create_oval(20, 15, 60, 40, outline=COLORS["primary"], width=3, fill="")
        canvas.create_rectangle(15, 30, 65, 70, outline=COLORS["primary"], width=3, fill=COLORS["primary_dark"])
        canvas.create_rectangle(35, 40, 45, 60, outline=COLORS["bg_medium"], width=2, fill=COLORS["bg_medium"])

        # Title
        title_label = ttk.Label(login_container, text="Vault", style="Title.TLabel")
        title_label.pack(pady=(0, 5))

        subtitle = ttk.Label(login_container, text="Secure File Storage", style="Subtitle.TLabel")
        subtitle.pack(pady=(0, 20))

        # Password field with modern styling
        password_frame = ttk.Frame(login_container, style="Secondary.TFrame")
        password_frame.pack(fill=tk.X, pady=10)

        password_label = ttk.Label(password_frame, text="Password", style="TLabel")
        password_label.pack(anchor=tk.W, pady=(0, 5))

        self.password_entry = ModernEntry(password_frame, show="•", width=25)
        self.password_entry.pack(fill=tk.X, ipady=8)
        self.password_entry.focus()

        # Login button (custom rounded button)
        button_frame = ttk.Frame(login_container, style="Secondary.TFrame")
        button_frame.pack(fill=tk.X, pady=20)

        login_btn = ModernButton(
            button_frame,
            text="Login" if self.password_hash else "Create Vault",
            command=self.handle_login,
            width=240,
            height=40
        )
        login_btn.pack()

        # Bind Enter key to login
        self.root.bind('<Return>', lambda e: self.handle_login())

        # Status message
        self.status_label = ttk.Label(login_container, text="", foreground=COLORS["error"],
                                      style="Status.TLabel")
        self.status_label.pack(pady=10)

        # Keyboard shortcut info
        info_label = ttk.Label(
            login_container,
            text="Press Ctrl+Alt+V to open Vault",
            style="Status.TLabel"
        )
        info_label.pack(side=tk.BOTTOM, pady=10)

    def handle_login(self):
        """Handle login or vault creation"""
        password = self.password_entry.get()

        if not password:
            self.status_label.config(text="Password cannot be empty")
            return

        if self.password_hash:
            # Verify existing password
            entered_hash = hashlib.sha256(password.encode()).hexdigest()
            if entered_hash == self.password_hash:
                self.password = password
                self.authenticated = True
                self.filesystem = SecureFileSystem(password)
                self.setup_main_ui()
            else:
                self.status_label.config(text="Incorrect password")
        else:
            # Create new vault with this password
            self.password_hash = self.save_password_hash(password)
            if self.password_hash:
                self.password = password
                self.authenticated = True
                self.filesystem = SecureFileSystem(password)
                self.setup_main_ui()
            else:
                self.status_label.config(text="Error creating vault")

    def setup_main_ui(self):
        """Set up the main application interface"""
        # Unbind the Enter key from login
        self.root.unbind('<Return>')

        # Main container
        main_container = ttk.Frame(self.root, style="TFrame", padding=0)
        main_container.pack(fill=tk.BOTH, expand=True)

        # Top navigation panel
        nav_panel = ttk.Frame(main_container, style="Secondary.TFrame", padding=10)
        nav_panel.pack(fill=tk.X)

        # App title in nav panel
        title_label = ttk.Label(nav_panel, text="Vault", style="Title.TLabel")
        title_label.pack(side=tk.LEFT, padx=10)

        # Action buttons in nav panel
        logout_btn = ModernButton(
            nav_panel,
            text="Logout",
            command=self.logout,
            width=100,
            height=32,
            bg=COLORS["bg_light"],
            hover_bg=COLORS["error"]
        )
        logout_btn.pack(side=tk.RIGHT, padx=5)

        minimize_btn = ModernButton(
            nav_panel,
            text="Minimize",
            command=self.hide_app,
            width=100,
            height=32,
            bg=COLORS["bg_light"],
            hover_bg=COLORS["bg_medium"]
        )
        minimize_btn.pack(side=tk.RIGHT, padx=5)

        # Content area
        content_frame = ttk.Frame(main_container, style="TFrame", padding=20)
        content_frame.pack(fill=tk.BOTH, expand=True)

        # Action buttons
        button_frame = ttk.Frame(content_frame, style="TFrame")
        button_frame.pack(fill=tk.X, pady=(0, 15))

        add_btn = ModernButton(
            button_frame,
            text="Add Files",
            command=self.add_files,
            width=120,
            height=36,
            bg=COLORS["success"]
        )
        add_btn.pack(side=tk.LEFT, padx=(0, 10))

        extract_btn = ModernButton(
            button_frame,
            text="Extract Files",
            command=self.extract_files,
            width=120,
            height=36,
            bg=COLORS["primary"]
        )
        extract_btn.pack(side=tk.LEFT, padx=(0, 10))

        delete_btn = ModernButton(
            button_frame,
            text="Delete Selected",
            command=self.delete_files,
            width=140,
            height=36,
            bg=COLORS["error"]
        )
        delete_btn.pack(side=tk.LEFT)

        # Files list with frame
        files_frame = ttk.LabelFrame(content_frame, text="Secured Files", padding=10)
        files_frame.pack(fill=tk.BOTH, expand=True)

        # Treeview and scrollbar in container
        tree_container = ttk.Frame(files_frame, style="TFrame")
        tree_container.pack(fill=tk.BOTH, expand=True)

        # Scrollbar
        scrollbar = ttk.Scrollbar(tree_container)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Treeview for files
        columns = ("name", "size", "date")
        self.files_tree = ttk.Treeview(tree_container, columns=columns, show="headings",
                                       yscrollcommand=scrollbar.set)

        self.files_tree.heading("name", text="Filename")
        self.files_tree.heading("size", text="Size")
        self.files_tree.heading("date", text="Date Added")

        self.files_tree.column("name", width=300)
        self.files_tree.column("size", width=100)
        self.files_tree.column("date", width=150)

        self.files_tree.pack(fill=tk.BOTH, expand=True)
        scrollbar.config(command=self.files_tree.yview)

        # Status bar
        self.status_bar = ttk.Label(main_container, text="Vault ready", style="Status.TLabel", padding=10)
        self.status_bar.pack(fill=tk.X, side=tk.BOTTOM)

        # Load secured files
        self.load_secured_files()

        # Add alternate row colors
        self.files_tree.tag_configure('oddrow', background=COLORS["bg_light"])
        self.files_tree.tag_configure('evenrow', background=COLORS["bg_medium"])

    def load_secured_files(self):
        """Load and display secured files in the treeview"""
        # Clear existing items
        for item in self.files_tree.get_children():
            self.files_tree.delete(item)

        # Find all .vault files in the hidden folder
        try:
            secure_files = list(self.hidden_folder_path.glob("*.vault"))

            if not secure_files:
                self.status_bar.config(text="No secured files found")
                return

            for i, file_path in enumerate(secure_files):
                # Get file stats
                stats = file_path.stat()
                size_kb = stats.st_size / 1024

                # Format size display
                if size_kb < 1024:
                    size_display = f"{size_kb:.1f} KB"
                else:
                    size_mb = size_kb / 1024
                    size_display = f"{size_mb:.1f} MB"

                # Format date
                import datetime
                date_display = datetime.datetime.fromtimestamp(stats.st_mtime).strftime("%Y-%m-%d %H:%M:%S")

                # Extract original filename (without the path and .vault extension)
                filename = file_path.name.replace(".vault", "")

                # Alternate row coloring
                tag = 'evenrow' if i % 2 == 0 else 'oddrow'

                self.files_tree.insert("", tk.END, values=(filename, size_display, date_display), tags=(tag,))

            self.status_bar.config(text=f"{len(secure_files)} secured file(s) found")
        except Exception as e:
            self.status_bar.config(text=f"Error loading files: {e}")

    def add_files(self):
        """Select and add files to the secure vault"""
        filepaths = filedialog.askopenfilenames(title="Select files to secure")

        if not filepaths:
            return

        successful = 0
        for filepath in filepaths:
            # Generate destination path in the hidden folder
            filename = os.path.basename(filepath)
            dest_path = self.hidden_folder_path / f"{filename}.vault"

            # Encrypt and save the file
            if self.filesystem.encrypt_file(filepath, dest_path):
                successful += 1

        # Refresh the file list
        self.load_secured_files()

        if successful:
            self.status_bar.config(text=f"Successfully secured {successful} of {len(filepaths)} file(s)")
        else:
            self.status_bar.config(text="Failed to secure any files")

    def extract_files(self):
        """Extract selected files from the vault"""
        selected_items = self.files_tree.selection()

        if not selected_items:
            messagebox.showinfo("Selection Required", "Please select files to extract")
            return

        # Ask for extraction directory
        output_dir = filedialog.askdirectory(title="Select output directory")

        if not output_dir:
            return

        successful = 0
        for item in selected_items:
            filename = self.files_tree.item(item, "values")[0]
            encrypted_path = self.hidden_folder_path / f"{filename}.vault"

            if self.filesystem.decrypt_file(encrypted_path, output_dir):
                successful += 1

        if successful:
            self.status_bar.config(text=f"Successfully extracted {successful} of {len(selected_items)} file(s)")
            messagebox.showinfo("Extraction Complete", f"Successfully extracted {successful} file(s) to {output_dir}")
        else:
            self.status_bar.config(text="Failed to extract any files")

    def delete_files(self):
        """Delete selected secured files"""
        selected_items = self.files_tree.selection()

        if not selected_items:
            messagebox.showinfo("Selection Required", "Please select files to delete")
            return

        confirm = messagebox.askyesno(
            "Confirm Deletion",
            f"Are you sure you want to delete {len(selected_items)} file(s)? This cannot be undone."
        )

        if not confirm:
            return

        deleted = 0
        for item in selected_items:
            filename = self.files_tree.item(item, "values")[0]
            file_path = self.hidden_folder_path / f"{filename}.vault"

            try:
                os.remove(file_path)
                deleted += 1
            except Exception as e:
                print(f"Error deleting {file_path}: {e}")

        # Refresh the file list
        self.load_secured_files()

        self.status_bar.config(text=f"Deleted {deleted} of {len(selected_items)} file(s)")

    def logout(self):
        """Log out of the vault"""
        self.authenticated = False
        self.password = None
        self.filesystem = None
        self.setup_ui()

    def hide_process(self):
        """Hide the process from the task manager (limited effectiveness)"""
        if sys.platform == 'win32':
            try:
                # This is a basic approach
                pid = os.getpid()
                handle = win32api.OpenProcess(win32con.PROCESS_SET_INFORMATION, False, pid)
                win32process.SetPriorityClass(handle, win32process.IDLE_PRIORITY_CLASS)
            except Exception as e:
                print(f"Failed to hide process: {e}")


def main():
    # Create the root window but don't show it
    root = tk.Tk()
    root.withdraw()  # Hide initially

    app = VaultApp(root)

    # Hide the process
    app.hide_process()

    # Start the application
    root.protocol("WM_DELETE_WINDOW", app.hide_app)  # Minimize instead of close
    root.mainloop()


if __name__ == "__main__":
    main()