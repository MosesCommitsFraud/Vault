# vault_qt.py - Modern Windows 11-style Vault application

import os
import sys
import base64
import hashlib
from pathlib import Path
import datetime
from threading import Thread

# Qt imports
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
                             QLabel, QLineEdit, QPushButton, QTableWidget, QTableWidgetItem,
                             QHeaderView, QFileDialog, QMessageBox, QFrame, QStackedWidget,
                             QSizePolicy, QSpacerItem, QStyle, QToolBar, QMenu, QStatusBar)
from PyQt6.QtCore import Qt, QSize, QThread, pyqtSignal
from PyQt6.QtGui import QIcon, QPixmap, QColor, QPalette, QFont, QAction

# Cryptography imports
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# System imports for hiding folders and keyboard shortcuts
import keyboard
import ctypes
import winreg
import win32api
import win32con
import win32process

# Style constants - Windows 11 style with purple accent
COLORS = {
    "window_bg": "#202020",  # Dark grey for window background
    "sidebar_bg": "#2d2d2d",  # Lighter grey for sidebar
    "card_bg": "#333333",  # Card/panel background
    "primary": "#a55eea",  # Purple primary
    "primary_dark": "#8f44fd",  # Darker purple
    "accent": "#b76efa",  # Light purple
    "text_light": "#ffffff",  # White text
    "text_secondary": "#cccccc",  # Light grey text
    "text_disabled": "#888888",  # Grey text
    "border": "#444444",  # Border color
    "success": "#0abb87",  # Green
    "warning": "#ffb822",  # Orange/yellow
    "error": "#ff5252",  # Red
}

# Stylesheet for the entire application
STYLESHEET = f"""
QWidget {{
    background-color: {COLORS['window_bg']};
    color: {COLORS['text_light']};
    font-family: 'Segoe UI', 'MS Sans Serif';
    font-size: 10pt;
}}

QMainWindow {{
    background-color: {COLORS['window_bg']};
}}

QLabel {{
    color: {COLORS['text_light']};
}}

QLabel#titleLabel {{
    font-size: 24pt;
    font-weight: bold;
    color: {COLORS['text_light']};
}}

QLabel#subtitleLabel {{
    font-size: 12pt;
    color: {COLORS['text_secondary']};
}}

QLineEdit {{
    background-color: {COLORS['card_bg']};
    color: {COLORS['text_light']};
    border: 1px solid {COLORS['border']};
    border-radius: 4px;
    padding: 8px;
    selection-background-color: {COLORS['primary']};
}}

QPushButton {{
    background-color: {COLORS['primary']};
    color: {COLORS['text_light']};
    border: none;
    border-radius: 4px;
    padding: 8px 16px;
    font-weight: bold;
    min-height: 36px;
}}

QPushButton:hover {{
    background-color: {COLORS['primary_dark']};
}}

QPushButton:pressed {{
    background-color: {COLORS['accent']};
}}

QPushButton:disabled {{
    background-color: {COLORS['card_bg']};
    color: {COLORS['text_disabled']};
}}

QPushButton#successButton {{
    background-color: {COLORS['success']};
}}

QPushButton#successButton:hover {{
    background-color: #09a478;
}}

QPushButton#warningButton {{
    background-color: {COLORS['warning']};
}}

QPushButton#warningButton:hover {{
    background-color: #f0ad2c;
}}

QPushButton#dangerButton {{
    background-color: {COLORS['error']};
}}

QPushButton#dangerButton:hover {{
    background-color: #e04343;
}}

QTableWidget {{
    background-color: {COLORS['card_bg']};
    alternate-background-color: {COLORS['sidebar_bg']};
    border: 1px solid {COLORS['border']};
    border-radius: 4px;
    selection-background-color: {COLORS['primary']};
    selection-color: {COLORS['text_light']};
    gridline-color: {COLORS['border']};
}}

QHeaderView::section {{
    background-color: {COLORS['sidebar_bg']};
    color: {COLORS['text_light']};
    border: 1px solid {COLORS['border']};
    padding: 6px;
}}

QTableWidget::item {{
    padding: 6px;
}}

QToolBar {{
    background-color: {COLORS['sidebar_bg']};
    border-bottom: 1px solid {COLORS['border']};
    spacing: 10px;
}}

QStatusBar {{
    background-color: {COLORS['sidebar_bg']};
    color: {COLORS['text_secondary']};
    border-top: 1px solid {COLORS['border']};
}}

QMenu {{
    background-color: {COLORS['card_bg']};
    border: 1px solid {COLORS['border']};
}}

QMenu::item {{
    padding: 6px 25px 6px 20px;
}}

QMenu::item:selected {{
    background-color: {COLORS['primary']};
}}
"""


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


class KeyboardWatcher(QThread):
    """Thread class to watch for keyboard shortcut"""
    triggered = pyqtSignal()

    def run(self):
        keyboard.add_hotkey('ctrl+alt+v', self.on_hotkey)
        keyboard.wait()

    def on_hotkey(self):
        self.triggered.emit()


class LoginScreen(QWidget):
    """Login screen widget"""
    login_successful = pyqtSignal(str)  # Signal to emit the password on success

    def __init__(self, parent=None, is_new_vault=False):
        super().__init__(parent)
        self.is_new_vault = is_new_vault
        self.setup_ui()

    def setup_ui(self):
        # Main layout
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)

        # Content container with padding
        content = QWidget()
        content_layout = QVBoxLayout(content)
        content_layout.setContentsMargins(40, 40, 40, 40)
        content_layout.setSpacing(20)

        # Center the login form
        main_layout.addStretch(1)
        main_layout.addWidget(content, alignment=Qt.AlignmentFlag.AlignCenter)
        main_layout.addStretch(1)

        # App logo/icon
        logo_layout = QHBoxLayout()
        logo_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        logo_label = QLabel()
        pixmap = QPixmap(64, 64)
        pixmap.fill(Qt.GlobalColor.transparent)
        logo_label.setPixmap(pixmap)
        logo_label.setFixedSize(80, 80)
        logo_layout.addWidget(logo_label)
        content_layout.addLayout(logo_layout)

        # Title and subtitle
        title_label = QLabel("Vault")
        title_label.setObjectName("titleLabel")
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        content_layout.addWidget(title_label)

        subtitle_label = QLabel("Secure File Storage")
        subtitle_label.setObjectName("subtitleLabel")
        subtitle_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        content_layout.addWidget(subtitle_label)

        # Spacer
        content_layout.addSpacing(20)

        # Password field
        password_layout = QVBoxLayout()
        password_label = QLabel("Password")
        password_layout.addWidget(password_label)

        self.password_field = QLineEdit()
        self.password_field.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_field.setMinimumHeight(40)
        self.password_field.setMinimumWidth(280)
        password_layout.addWidget(self.password_field)
        content_layout.addLayout(password_layout)

        # Spacer
        content_layout.addSpacing(10)

        # Login button
        button_text = "Create Vault" if self.is_new_vault else "Login"
        self.login_button = QPushButton(button_text)
        self.login_button.setMinimumHeight(40)
        self.login_button.clicked.connect(self.handle_login)
        content_layout.addWidget(self.login_button)

        # Status message
        self.status_label = QLabel("")
        self.status_label.setStyleSheet(f"color: {COLORS['error']};")
        self.status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        content_layout.addWidget(self.status_label)

        # Hotkey info
        key_info = QLabel("Press Ctrl+Alt+V to open Vault")
        key_info.setStyleSheet(f"color: {COLORS['text_secondary']}; font-size: 9pt;")
        key_info.setAlignment(Qt.AlignmentFlag.AlignCenter)
        content_layout.addWidget(key_info)

        # Connect enter key to login
        self.password_field.returnPressed.connect(self.handle_login)

    def handle_login(self):
        password = self.password_field.text()

        if not password:
            self.status_label.setText("Password cannot be empty")
            return

        # Signal that login/creation was successful, pass password to parent
        self.login_successful.emit(password)

    def set_status(self, message, is_error=True):
        """Set status message with appropriate color"""
        color = COLORS['error'] if is_error else COLORS['success']
        self.status_label.setStyleSheet(f"color: {color};")
        self.status_label.setText(message)


class MainScreen(QWidget):
    """Main application screen after login"""
    logout_requested = pyqtSignal()

    def __init__(self, parent=None, filesystem=None, vault_path=None):
        super().__init__(parent)
        self.filesystem = filesystem
        self.vault_path = vault_path
        self.setup_ui()
        self.load_secured_files()

    def setup_ui(self):
        # Main layout
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # Toolbar
        toolbar = QToolBar()
        toolbar.setMovable(False)
        toolbar.setIconSize(QSize(18, 18))

        # App title in toolbar
        title_label = QLabel("Vault")
        title_label.setObjectName("titleLabel")
        title_label.setContentsMargins(10, 0, 20, 0)
        toolbar.addWidget(title_label)

        # Add spacer to push logout button to the right
        spacer = QWidget()
        spacer.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        toolbar.addWidget(spacer)

        # Minimize button
        minimize_btn = QPushButton("Minimize")
        minimize_btn.setFixedWidth(100)
        minimize_btn.clicked.connect(self.minimize)
        toolbar.addWidget(minimize_btn)

        # Logout button
        logout_btn = QPushButton("Logout")
        logout_btn.setFixedWidth(100)
        logout_btn.setObjectName("dangerButton")
        logout_btn.clicked.connect(self.logout)
        toolbar.addWidget(logout_btn)

        main_layout.addWidget(toolbar)

        # Content area
        content = QWidget()
        content_layout = QVBoxLayout(content)
        content_layout.setContentsMargins(20, 20, 20, 20)

        # Action buttons
        button_layout = QHBoxLayout()
        button_layout.setSpacing(10)

        add_btn = QPushButton("Add Files")
        add_btn.setObjectName("successButton")
        add_btn.clicked.connect(self.add_files)
        button_layout.addWidget(add_btn)

        extract_btn = QPushButton("Extract Files")
        extract_btn.clicked.connect(self.extract_files)
        button_layout.addWidget(extract_btn)

        delete_btn = QPushButton("Delete Selected")
        delete_btn.setObjectName("dangerButton")
        delete_btn.clicked.connect(self.delete_files)
        button_layout.addWidget(delete_btn)

        button_layout.addStretch()
        content_layout.addLayout(button_layout)

        # Files table
        self.files_table = QTableWidget()
        self.files_table.setColumnCount(3)
        self.files_table.setHorizontalHeaderLabels(["Filename", "Size", "Date Added"])
        self.files_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.files_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.files_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.files_table.setAlternatingRowColors(True)
        self.files_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.files_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)

        content_layout.addWidget(self.files_table, 1)  # 1 for stretch factor

        main_layout.addWidget(content, 1)  # 1 for stretch factor

        # Status bar
        self.status_bar = QStatusBar()
        self.status_bar.setSizeGripEnabled(False)
        self.status_bar.showMessage("Vault ready")
        main_layout.addWidget(self.status_bar)

    def load_secured_files(self):
        """Load and display secured files in the table"""
        self.files_table.setRowCount(0)  # Clear existing items

        # Find all .vault files in the hidden folder
        try:
            vault_path = Path(self.vault_path)
            secure_files = list(vault_path.glob("*.vault"))

            if not secure_files:
                self.status_bar.showMessage("No secured files found")
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
                date_display = datetime.datetime.fromtimestamp(stats.st_mtime).strftime("%Y-%m-%d %H:%M:%S")

                # Extract original filename (without the path and .vault extension)
                filename = file_path.name.replace(".vault", "")

                # Add to table
                row_position = self.files_table.rowCount()
                self.files_table.insertRow(row_position)
                self.files_table.setItem(row_position, 0, QTableWidgetItem(filename))
                self.files_table.setItem(row_position, 1, QTableWidgetItem(size_display))
                self.files_table.setItem(row_position, 2, QTableWidgetItem(date_display))

            self.status_bar.showMessage(f"{len(secure_files)} secured file(s) found")
        except Exception as e:
            self.status_bar.showMessage(f"Error loading files: {e}")

    def add_files(self):
        """Select and add files to the secure vault"""
        filepaths, _ = QFileDialog.getOpenFileNames(self, "Select files to secure")

        if not filepaths:
            return

        successful = 0
        for filepath in filepaths:
            # Generate destination path in the hidden folder
            filename = os.path.basename(filepath)
            dest_path = os.path.join(self.vault_path, f"{filename}.vault")

            # Encrypt and save the file
            if self.filesystem.encrypt_file(filepath, dest_path):
                successful += 1

        # Refresh the file list
        self.load_secured_files()

        if successful:
            self.status_bar.showMessage(f"Successfully secured {successful} of {len(filepaths)} file(s)")
        else:
            self.status_bar.showMessage("Failed to secure any files")

    def extract_files(self):
        """Extract selected files from the vault"""
        selected_rows = set(item.row() for item in self.files_table.selectedItems())

        if not selected_rows:
            QMessageBox.information(self, "Selection Required", "Please select files to extract")
            return

        # Ask for extraction directory
        output_dir = QFileDialog.getExistingDirectory(self, "Select output directory")

        if not output_dir:
            return

        successful = 0
        for row in selected_rows:
            filename = self.files_table.item(row, 0).text()
            encrypted_path = os.path.join(self.vault_path, f"{filename}.vault")

            if self.filesystem.decrypt_file(encrypted_path, output_dir):
                successful += 1

        if successful:
            self.status_bar.showMessage(f"Successfully extracted {successful} of {len(selected_rows)} file(s)")
            QMessageBox.information(self, "Extraction Complete",
                                    f"Successfully extracted {successful} file(s) to {output_dir}")
        else:
            self.status_bar.showMessage("Failed to extract any files")

    def delete_files(self):
        """Delete selected secured files"""
        selected_rows = set(item.row() for item in self.files_table.selectedItems())

        if not selected_rows:
            QMessageBox.information(self, "Selection Required", "Please select files to delete")
            return

        confirm = QMessageBox.question(
            self, "Confirm Deletion",
            f"Are you sure you want to delete {len(selected_rows)} file(s)? This cannot be undone.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )

        if confirm != QMessageBox.StandardButton.Yes:
            return

        deleted = 0
        for row in selected_rows:
            filename = self.files_table.item(row, 0).text()
            file_path = os.path.join(self.vault_path, f"{filename}.vault")

            try:
                os.remove(file_path)
                deleted += 1
            except Exception as e:
                print(f"Error deleting {file_path}: {e}")

        # Refresh the file list
        self.load_secured_files()

        self.status_bar.showMessage(f"Deleted {deleted} of {len(selected_rows)} file(s)")

    def minimize(self):
        """Minimize the application window"""
        self.parent().hide()

    def logout(self):
        """Log out of the vault"""
        self.logout_requested.emit()


class VaultApplication(QMainWindow):
    """Main application window"""

    def __init__(self):
        super().__init__()

        # Set up window properties
        self.setWindowTitle("Vault")
        self.setMinimumSize(900, 600)

        # Set up paths
        documents_path = Path.home() / "Documents"
        self.vault_path = str(documents_path / ".vault_data")
        self.config_path = os.path.join(self.vault_path, ".vault_config")

        # Ensure the vault folder exists
        self.ensure_vault_folder_exists()

        # Set up stacked widget for different screens
        self.main_widget = QStackedWidget()
        self.setCentralWidget(self.main_widget)

        # Check if vault exists
        self.password_hash = self.load_password_hash()
        is_new_vault = self.password_hash is None

        # Create login screen
        self.login_screen = LoginScreen(is_new_vault=is_new_vault)
        self.login_screen.login_successful.connect(self.handle_login)
        self.main_widget.addWidget(self.login_screen)

        # Keyboard shortcut watcher
        self.keyboard_watcher = KeyboardWatcher()
        self.keyboard_watcher.triggered.connect(self.show_application)
        self.keyboard_watcher.start()

        # Set up startup registry entry
        self.setup_startup()

        # Initially hide the application
        self.hide()

    def show_application(self):
        """Show and activate the application window"""
        self.show()
        self.raise_()
        self.activateWindow()

    def ensure_vault_folder_exists(self):
        """Create the vault folder if it doesn't exist"""
        os.makedirs(self.vault_path, exist_ok=True)

        # Set folder attributes to hidden and system on Windows
        if sys.platform == 'win32':
            try:
                ctypes.windll.kernel32.SetFileAttributesW(
                    self.vault_path,
                    win32con.FILE_ATTRIBUTE_HIDDEN | win32con.FILE_ATTRIBUTE_SYSTEM
                )
            except Exception as e:
                print(f"Failed to hide vault folder: {e}")

    def load_password_hash(self):
        """Load password hash from config file"""
        if os.path.exists(self.config_path):
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

            # Set config file as hidden on Windows
            if sys.platform == 'win32':
                ctypes.windll.kernel32.SetFileAttributesW(
                    self.config_path,
                    win32con.FILE_ATTRIBUTE_HIDDEN
                )

            return password_hash
        except Exception as e:
            print(f"Error saving password: {e}")
            return None

    def handle_login(self, password):
        """Handle login attempt or vault creation"""
        if self.password_hash is None:
            # Create new vault
            self.password_hash = self.save_password_hash(password)
            if self.password_hash:
                self.show_main_screen(password)
            else:
                self.login_screen.set_status("Error creating vault")
        else:
            # Verify password
            entered_hash = hashlib.sha256(password.encode()).hexdigest()
            if entered_hash == self.password_hash:
                self.show_main_screen(password)
            else:
                self.login_screen.set_status("Incorrect password")

    def show_main_screen(self, password):
        """Show the main application screen"""
        # Create filesystem with password
        filesystem = SecureFileSystem(password)

        # Create main screen if it doesn't exist
        if self.main_widget.count() < 2:
            self.main_screen = MainScreen(filesystem=filesystem, vault_path=self.vault_path)
            self.main_screen.logout_requested.connect(self.logout)
            self.main_widget.addWidget(self.main_screen)

        # Switch to main screen
        self.main_widget.setCurrentIndex(1)

    def logout(self):
        """Handle logout request"""
        # Switch back to login screen
        self.main_widget.setCurrentIndex(0)

        # Clear password field
        self.login_screen.password_field.clear()

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

    def hide_process(self):
        """Reduce process priority to make it less visible in Task Manager"""
        if sys.platform == 'win32':
            try:
                pid = os.getpid()
                handle = win32api.OpenProcess(win32con.PROCESS_SET_INFORMATION, False, pid)
                win32process.SetPriorityClass(handle, win32process.IDLE_PRIORITY_CLASS)
            except Exception as e:
                print(f"Failed to hide process: {e}")


def main():
    # Create application
    app = QApplication(sys.argv)
    app.setStyleSheet(STYLESHEET)

    # Create main window
    window = VaultApplication()

    # Hide the process
    window.hide_process()

    # Run the application
    sys.exit(app.exec())


if __name__ == "__main__":
    main()