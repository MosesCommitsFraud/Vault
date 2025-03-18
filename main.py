# siva.py - Enhanced Black & Red Code-Themed Secure Storage Application

import os
import sys
import base64
import hashlib
import shutil
import tempfile
import subprocess
from pathlib import Path
import datetime
from threading import Thread
import mimetypes

# Qt imports
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
                             QLabel, QLineEdit, QPushButton, QTableWidget, QTableWidgetItem,
                             QHeaderView, QFileDialog, QMessageBox, QFrame, QStackedWidget,
                             QSizePolicy, QSpacerItem, QStyle, QToolBar, QMenu, QStatusBar,
                             QToolButton, QInputDialog, QTreeView, QSplitter, QDialog, QFormLayout,
                             QComboBox)
from PyQt6.QtCore import Qt, QSize, QThread, pyqtSignal, QPoint, QDir, QSettings
from PyQt6.QtGui import QIcon, QPixmap, QColor, QPalette, QFont, QAction, QFontDatabase, QStandardItemModel, \
    QStandardItem

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

# Initialize mimetypes
mimetypes.init()

# Style constants - SIVA theme (black & bright red)
COLORS = {
    "window_bg": "#080808",  # Almost black
    "darker_bg": "#0a0a0a",  # Slightly lighter black
    "card_bg": "#111111",  # Dark grey for elements
    "primary": "#ff0000",  # Bright red
    "primary_dark": "#cc0000",  # Darker red
    "accent": "#ff3333",  # Lighter red
    "text_light": "#ffffff",  # White text
    "text_secondary": "#cccccc",  # Light grey text
    "text_red": "#ff3333",  # Red text
    "text_disabled": "#555555",  # Grey text
    "border": "#222222",  # Border color
    "success": "#00cc00",  # Green
    "warning": "#ffcc00",  # Yellow
    "error": "#ff0000",  # Red (same as primary)
    "highlight": "#ff3333",  # Highlight color
}

# Code patterns for background elements (hex pattern)
CODE_PATTERN = """
010011010110100101100111011101000111100100100000
001000000100010001100001011101000110000100100000
010100110110010101100011011101010111001001100101
0101001101001001010101100100000100100000
"""

# Stylesheet for the entire application
STYLESHEET = f"""
QWidget {{
    background-color: {COLORS['window_bg']};
    color: {COLORS['text_light']};
    font-family: 'Consolas', 'Courier New', monospace;
    font-size: 10pt;
}}

QMainWindow {{
    background-color: {COLORS['window_bg']};
}}

QLabel {{
    color: {COLORS['text_light']};
}}

QLabel#titleLabel {{
    font-size: 22pt;
    font-weight: bold;
    color: {COLORS['primary']};
    font-family: 'Consolas', 'Courier New', monospace;
}}

QLabel#subtitleLabel {{
    font-size: 11pt;
    color: {COLORS['text_secondary']};
    font-family: 'Consolas', 'Courier New', monospace;
}}

QLabel#codePatternLabel {{
    color: {COLORS['text_red']};
    opacity: 0.1;
    font-family: 'Consolas', 'Courier New', monospace;
    font-size: 8pt;
}}

QLineEdit {{
    background-color: {COLORS['card_bg']};
    color: {COLORS['text_light']};
    border: 1px solid {COLORS['primary']};
    border-radius: 2px;
    padding: 8px;
    selection-background-color: {COLORS['primary']};
    font-family: 'Consolas', 'Courier New', monospace;
}}

QPushButton {{
    background-color: {COLORS['card_bg']};
    color: {COLORS['primary']};
    border: 1px solid {COLORS['primary']};
    border-radius: 2px;
    padding: 8px 16px;
    font-weight: bold;
    min-height: 36px;
    outline: none;
    font-family: 'Consolas', 'Courier New', monospace;
}}

QPushButton:hover {{
    background-color: {COLORS['primary']};
    color: {COLORS['window_bg']};
}}

QPushButton:pressed {{
    background-color: {COLORS['primary_dark']};
    color: {COLORS['window_bg']};
}}

QPushButton:focus {{
    outline: none;
}}

QPushButton:disabled {{
    background-color: {COLORS['card_bg']};
    color: {COLORS['text_disabled']};
    border: 1px solid {COLORS['text_disabled']};
}}

QPushButton#successButton {{
    border: 1px solid {COLORS['success']};
    color: {COLORS['success']};
}}

QPushButton#successButton:hover {{
    background-color: {COLORS['success']};
    color: {COLORS['window_bg']};
}}

QPushButton#warningButton {{
    border: 1px solid {COLORS['warning']};
    color: {COLORS['warning']};
}}

QPushButton#warningButton:hover {{
    background-color: {COLORS['warning']};
    color: {COLORS['window_bg']};
}}

QPushButton#dangerButton {{
    border: 1px solid {COLORS['error']};
    color: {COLORS['error']};
}}

QPushButton#dangerButton:hover {{
    background-color: {COLORS['error']};
    color: {COLORS['window_bg']};
}}

QTableWidget {{
    background-color: {COLORS['card_bg']};
    alternate-background-color: {COLORS['darker_bg']};
    border: 1px solid {COLORS['border']};
    border-radius: 2px;
    color: {COLORS['text_light']};
    gridline-color: {COLORS['border']};
    outline: none;
}}

QTableWidget::item:selected {{
    background-color: {COLORS['primary']};
    color: {COLORS['window_bg']};
}}

QHeaderView::section {{
    background-color: {COLORS['darker_bg']};
    color: {COLORS['primary']};
    border: 1px solid {COLORS['border']};
    padding: 6px;
    font-weight: bold;
}}

QTableWidget::item {{
    padding: 6px;
}}

QToolBar {{
    background-color: {COLORS['darker_bg']};
    border-bottom: 1px solid {COLORS['primary']};
    spacing: 10px;
}}

QStatusBar {{
    background-color: {COLORS['darker_bg']};
    color: {COLORS['text_secondary']};
    border-top: 1px solid {COLORS['primary']};
}}

QMenu {{
    background-color: {COLORS['card_bg']};
    border: 1px solid {COLORS['primary']};
}}

QMenu::item {{
    padding: 6px 25px 6px 20px;
}}

QMenu::item:selected {{
    background-color: {COLORS['primary']};
    color: {COLORS['window_bg']};
}}

QToolButton {{
    background-color: transparent;
    border: none;
    border-radius: 2px;
    padding: 5px;
    color: {COLORS['primary']};
}}

QToolButton:hover {{
    background-color: rgba(255, 0, 0, 0.2);
}}

QToolButton:pressed {{
    background-color: rgba(255, 0, 0, 0.3);
}}

QToolButton::menu-indicator {{
    image: none;
}}

QSplitter::handle {{
    background-color: {COLORS['primary']};
    height: 1px;
}}

QTreeView {{
    background-color: {COLORS['card_bg']};
    alternate-background-color: {COLORS['darker_bg']};
    border: 1px solid {COLORS['border']};
    border-radius: 2px;
    color: {COLORS['text_light']};
    outline: none;
}}

QTreeView::item {{
    padding: 6px;
}}

QTreeView::item:selected {{
    background-color: {COLORS['primary']};
    color: {COLORS['window_bg']};
}}

QTreeView::branch:has-children:!has-siblings:closed,
QTreeView::branch:closed:has-children:has-siblings {{
    border-image: none;
    image: url(:/icons/branch-closed.png);
}}

QTreeView::branch:open:has-children:!has-siblings,
QTreeView::branch:open:has-children:has-siblings {{
    border-image: none;
    image: url(:/icons/branch-open.png);
}}

QComboBox {{
    background-color: {COLORS['card_bg']};
    color: {COLORS['text_light']};
    border: 1px solid {COLORS['primary']};
    border-radius: 2px;
    padding: 5px;
    min-height: 28px;
}}

QComboBox:hover {{
    border: 1px solid {COLORS['accent']};
}}

QComboBox::drop-down {{
    subcontrol-origin: padding;
    subcontrol-position: top right;
    width: 20px;
    border-left: 1px solid {COLORS['border']};
    border-top-right-radius: 2px;
    border-bottom-right-radius: 2px;
}}

QComboBox QAbstractItemView {{
    background-color: {COLORS['card_bg']};
    border: 1px solid {COLORS['primary']};
    selection-background-color: {COLORS['primary']};
    selection-color: {COLORS['window_bg']};
}}

QScrollBar:vertical {{
    border: none;
    background-color: {COLORS['darker_bg']};
    width: 10px;
    margin: 0px;
}}

QScrollBar::handle:vertical {{
    background-color: {COLORS['primary']};
    min-height: 20px;
    border-radius: 5px;
}}

QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
    height: 0px;
}}

QScrollBar:horizontal {{
    border: none;
    background-color: {COLORS['darker_bg']};
    height: 10px;
    margin: 0px;
}}

QScrollBar::handle:horizontal {{
    background-color: {COLORS['primary']};
    min-width: 20px;
    border-radius: 5px;
}}

QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{
    width: 0px;
}}

QDialog {{
    border: 1px solid {COLORS['primary']};
}}

QDialog QPushButton {{
    min-width: 100px;
}}
"""


class TempFileManager:
    """Manages temporary files opened from the vault"""

    def __init__(self):
        self.temp_dir = tempfile.mkdtemp(prefix="siva_")
        self.opened_files = {}  # Map of original file paths to temp file paths
        self.processes = {}  # Track processes used to open files

    def get_temp_path(self, original_path):
        """Get a temporary path for a file"""
        filename = os.path.basename(original_path)
        temp_path = os.path.join(self.temp_dir, filename)
        return temp_path

    def track_file(self, original_path, temp_path):
        """Track an opened file"""
        self.opened_files[original_path] = temp_path

    def open_file(self, path):
        """Open a file with the default application"""
        try:
            if sys.platform == 'win32':
                os.startfile(path)
                # No easy way to track this process on Windows
            else:
                # For Unix-like systems
                process = subprocess.Popen(['xdg-open', path])
                self.processes[path] = process
            return True
        except Exception as e:
            print(f"Error opening file: {e}")
            return False

    def close_all(self):
        """Close all opened files and clean up temporary directory"""
        # Try to close any processes we're tracking
        for path, process in self.processes.items():
            try:
                process.terminate()
            except:
                pass

        # Clear tracking dictionaries
        self.processes.clear()
        self.opened_files.clear()

        # Remove temporary directory and its contents
        try:
            shutil.rmtree(self.temp_dir)
            # Create a new temp directory for future use
            self.temp_dir = tempfile.mkdtemp(prefix="siva_")
        except Exception as e:
            print(f"Error cleaning up temp files: {e}")


class SecureFileSystem:
    """Handles the encryption and decryption of files"""

    def __init__(self, master_password):
        self.salt = b'SIVASecureSalt_X09'  # Fixed salt for key derivation
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
        """Encrypt a file and save it with .siva extension"""
        if dest_path is None:
            dest_path = str(source_path) + '.siva'

        try:
            with open(source_path, 'rb') as file:
                file_data = file.read()

            # Store filename and file type in the encrypted data
            filename = os.path.basename(source_path).encode()
            filename_len = len(filename).to_bytes(4, byteorder='big')

            # Get and store file type/extension
            _, file_ext = os.path.splitext(source_path)
            file_ext = file_ext.encode()
            ext_len = len(file_ext).to_bytes(4, byteorder='big')

            # Prepare data: [filename length][filename][extension length][extension][file data]
            data_to_encrypt = filename_len + filename + ext_len + file_ext + file_data

            # Encrypt the data
            encrypted_data = self.cipher.encrypt(data_to_encrypt)

            # Create parent directories if they don't exist
            os.makedirs(os.path.dirname(dest_path), exist_ok=True)

            with open(dest_path, 'wb') as file:
                file.write(encrypted_data)

            return dest_path
        except Exception as e:
            print(f"Encryption error: {e}")
            return None

    def decrypt_file(self, encrypted_path, output_dir=None, temp=False):
        """Decrypt a .siva file and restore the original file"""
        try:
            with open(encrypted_path, 'rb') as file:
                encrypted_data = file.read()

            # Decrypt the data
            decrypted_data = self.cipher.decrypt(encrypted_data)

            # Extract filename length (first 4 bytes)
            filename_len = int.from_bytes(decrypted_data[:4], byteorder='big')

            # Extract filename
            filename = decrypted_data[4:4 + filename_len].decode()

            # Extract extension length
            ext_pos = 4 + filename_len
            ext_len = int.from_bytes(decrypted_data[ext_pos:ext_pos + 4], byteorder='big')

            # Extract extension (could be empty)
            file_ext = ""
            if ext_len > 0:
                file_ext = decrypted_data[ext_pos + 4:ext_pos + 4 + ext_len].decode()

            # Extract file contents
            content_pos = ext_pos + 4 + ext_len
            file_data = decrypted_data[content_pos:]

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

    def create_folder(self, folder_path):
        """Create a folder in the vault"""
        try:
            os.makedirs(folder_path, exist_ok=True)
            return True
        except Exception as e:
            print(f"Error creating folder: {e}")
            return False

    def get_file_type(self, encrypted_path):
        """Extract file type information from encrypted file"""
        try:
            with open(encrypted_path, 'rb') as file:
                encrypted_data = file.read()

            # Decrypt the data
            decrypted_data = self.cipher.decrypt(encrypted_data)

            # Extract filename length (first 4 bytes)
            filename_len = int.from_bytes(decrypted_data[:4], byteorder='big')

            # Skip filename
            ext_pos = 4 + filename_len

            # Extract extension length
            ext_len = int.from_bytes(decrypted_data[ext_pos:ext_pos + 4], byteorder='big')

            # Extract extension
            if ext_len > 0:
                file_ext = decrypted_data[ext_pos + 4:ext_pos + 4 + ext_len].decode()
                return file_ext

            return ""
        except Exception as e:
            print(f"Error getting file type: {e}")
            return ""


class KeyboardWatcher(QThread):
    """Thread class to watch for keyboard shortcut"""
    triggered = pyqtSignal()

    def run(self):
        keyboard.add_hotkey('ctrl+alt+v', self.on_hotkey)
        keyboard.wait()

    def on_hotkey(self):
        self.triggered.emit()


class CodePatternLabel(QLabel):
    """Creates a background label with code-like pattern"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("codePatternLabel")
        self.setText(CODE_PATTERN)
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        # Make semi-transparent
        self.setStyleSheet(f"color: rgba(255, 0, 0, 0.1); font-size: 8pt;")


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

        # Background code pattern
        self.code_pattern = CodePatternLabel(self)
        self.code_pattern.setStyleSheet("color: rgba(255, 0, 0, 0.07); font-size: 10pt;")

        # Content container with padding
        content = QWidget()
        content_layout = QVBoxLayout(content)
        content_layout.setContentsMargins(40, 40, 40, 40)
        content_layout.setSpacing(20)

        # Center the login form
        main_layout.addStretch(1)
        main_layout.addWidget(content, alignment=Qt.AlignmentFlag.AlignCenter)
        main_layout.addStretch(1)

        # Logo (if exists)
        if os.path.exists("SIVA.png"):
            logo_layout = QHBoxLayout()
            logo_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

            logo_label = QLabel()
            pixmap = QPixmap("SIVA.png").scaled(80, 80, Qt.AspectRatioMode.KeepAspectRatio,
                                                Qt.TransformationMode.SmoothTransformation)
            logo_label.setPixmap(pixmap)
            logo_label.setFixedSize(80, 80)
            logo_layout.addWidget(logo_label)
            content_layout.addLayout(logo_layout)

        # Title and subtitle
        title_label = QLabel("S I V A")
        title_label.setObjectName("titleLabel")
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        content_layout.addWidget(title_label)

        subtitle_label = QLabel("> SECURE INFORMATION VAULT ACCESS")
        subtitle_label.setObjectName("subtitleLabel")
        subtitle_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        content_layout.addWidget(subtitle_label)

        # Spacer
        content_layout.addSpacing(20)

        # Password field
        password_layout = QVBoxLayout()
        password_label = QLabel("> ENTER AUTHORIZATION KEY:")
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
        button_text = "INITIALIZE" if self.is_new_vault else "ACCESS"
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
        key_info = QLabel("PRESS CTRL+ALT+V TO INITIATE SIVA PROTOCOL")
        key_info.setStyleSheet(f"color: {COLORS['text_secondary']}; font-size: 8pt;")
        key_info.setAlignment(Qt.AlignmentFlag.AlignCenter)
        content_layout.addWidget(key_info)

        # Connect enter key to login
        self.password_field.returnPressed.connect(self.handle_login)

    def handle_login(self):
        password = self.password_field.text()

        if not password:
            self.status_label.setText("ERROR: AUTHORIZATION KEY REQUIRED")
            return

        # Signal that login/creation was successful, pass password to parent
        self.login_successful.emit(password)

    def set_status(self, message, is_error=True):
        """Set status message with appropriate color"""
        color = COLORS['error'] if is_error else COLORS['success']
        self.status_label.setStyleSheet(f"color: {color};")
        self.status_label.setText(message)

    def resizeEvent(self, event):
        """Make the code pattern background resize with the widget"""
        super().resizeEvent(event)
        self.code_pattern.setGeometry(self.rect())


class FolderDialog(QDialog):
    """Dialog for creating a new folder"""

    def __init__(self, parent=None, current_path=""):
        super().__init__(parent)
        self.current_path = current_path
        self.folder_name = ""
        self.setup_ui()

    def setup_ui(self):
        self.setWindowTitle("CREATE NEW FOLDER")
        self.setMinimumWidth(400)

        layout = QVBoxLayout(self)

        # Form layout
        form_layout = QFormLayout()
        form_layout.setSpacing(10)

        # Folder name field
        self.name_input = QLineEdit()
        self.name_input.setMinimumHeight(30)
        form_layout.addRow(QLabel("FOLDER NAME:"), self.name_input)

        layout.addLayout(form_layout)

        # Buttons
        button_layout = QHBoxLayout()
        button_layout.setSpacing(10)

        cancel_btn = QPushButton("CANCEL")
        cancel_btn.clicked.connect(self.reject)

        create_btn = QPushButton("CREATE")
        create_btn.clicked.connect(self.accept_folder)
        create_btn.setObjectName("successButton")

        button_layout.addWidget(cancel_btn)
        button_layout.addWidget(create_btn)

        layout.addSpacing(20)
        layout.addLayout(button_layout)

    def accept_folder(self):
        """Accept the dialog if folder name is valid"""
        folder_name = self.name_input.text().strip()

        if not folder_name:
            QMessageBox.warning(self, "ERROR", "FOLDER NAME CANNOT BE EMPTY")
            return

        if any(c in r'\/:*?"<>|' for c in folder_name):
            QMessageBox.warning(self, "ERROR", "FOLDER NAME CONTAINS INVALID CHARACTERS")
            return

        self.folder_name = folder_name
        self.accept()

    def get_folder_name(self):
        """Return the folder name"""
        return self.folder_name


class MainScreen(QWidget):
    """Main application screen after login"""
    logout_requested = pyqtSignal()

    def __init__(self, parent=None, filesystem=None, vault_path=None):
        super().__init__(parent)
        self.filesystem = filesystem
        self.vault_path = vault_path
        self.current_folder = vault_path
        self.temp_file_manager = TempFileManager()
        self.setup_ui()
        self.load_secured_files()

    def setup_ui(self):
        # Main layout
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # Background code pattern
        self.code_pattern = CodePatternLabel(self)
        self.code_pattern.setGeometry(self.rect())

        # Toolbar
        toolbar = QToolBar()
        toolbar.setMovable(False)
        toolbar.setIconSize(QSize(18, 18))

        # Logo in toolbar if exists
        if os.path.exists("SIVA.png"):
            logo_label = QLabel()
            pixmap = QPixmap("SIVA.png").scaled(24, 24, Qt.AspectRatioMode.KeepAspectRatio,
                                                Qt.TransformationMode.SmoothTransformation)
            logo_label.setPixmap(pixmap)
            logo_label.setContentsMargins(5, 0, 5, 0)
            toolbar.addWidget(logo_label)

        # App title in toolbar
        title_label = QLabel("SIVA")
        title_label.setObjectName("titleLabel")
        title_label.setContentsMargins(10, 0, 20, 0)
        toolbar.addWidget(title_label)

        # Current path label
        self.path_label = QLabel("")
        self.path_label.setStyleSheet(f"color: {COLORS['text_secondary']};")
        toolbar.addWidget(self.path_label)

        # Add spacer to push menu button to the right
        spacer = QWidget()
        spacer.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        toolbar.addWidget(spacer)

        # Menu button (larger)
        self.menu_button = QToolButton()
        self.menu_button.setText("≡")  # More terminal-like hamburger menu
        self.menu_button.setFont(QFont("Consolas", 16))  # Larger font
        self.menu_button.setFixedSize(50, 50)  # Larger button size
        self.menu_button.setStyleSheet(f"color: {COLORS['primary']}; font-size: 16pt;")
        self.menu_button.setToolTip("MENU")
        self.menu_button.clicked.connect(self.show_menu)
        toolbar.addWidget(self.menu_button)

        main_layout.addWidget(toolbar)

        # Content area
        content = QWidget()
        content_layout = QVBoxLayout(content)
        content_layout.setContentsMargins(20, 20, 20, 20)

        # Console header
        console_header = QLabel("> SECURE FILE SYSTEM ACTIVE")
        console_header.setStyleSheet(f"color: {COLORS['primary']}; font-weight: bold;")
        content_layout.addWidget(console_header)

        # Action buttons
        button_layout = QHBoxLayout()
        button_layout.setSpacing(10)

        add_btn = QPushButton("[ADD FILES]")
        add_btn.setObjectName("successButton")
        add_btn.clicked.connect(self.add_files)
        button_layout.addWidget(add_btn)

        new_folder_btn = QPushButton("[NEW FOLDER]")
        new_folder_btn.clicked.connect(self.create_folder)
        button_layout.addWidget(new_folder_btn)

        extract_btn = QPushButton("[EXTRACT]")
        extract_btn.clicked.connect(self.extract_files)
        button_layout.addWidget(extract_btn)

        delete_btn = QPushButton("[DELETE]")
        delete_btn.setObjectName("dangerButton")
        delete_btn.clicked.connect(self.delete_files)
        button_layout.addWidget(delete_btn)

        button_layout.addStretch()
        content_layout.addLayout(button_layout)

        # Files table with header
        table_header = QLabel("> INFECTED FILES:")
        table_header.setStyleSheet(f"color: {COLORS['primary']}; font-weight: bold; margin-top: 10px;")
        content_layout.addWidget(table_header)

        # Files table
        self.files_table = QTableWidget()
        self.files_table.setColumnCount(4)  # Added a column for file type
        self.files_table.setHorizontalHeaderLabels(["FILENAME", "TYPE", "SIZE", "DATE CONSUMED"])
        self.files_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.files_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.files_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.files_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self.files_table.setAlternatingRowColors(True)
        self.files_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.files_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.files_table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.files_table.customContextMenuRequested.connect(self.show_context_menu)
        self.files_table.doubleClicked.connect(self.handle_double_click)

        content_layout.addWidget(self.files_table, 1)  # 1 for stretch factor

        main_layout.addWidget(content, 1)  # 1 for stretch factor

        # Status bar
        self.status_bar = QStatusBar()
        self.status_bar.setSizeGripEnabled(False)
        self.status_bar.showMessage("SIVA PROTOCOL ACTIVE")
        main_layout.addWidget(self.status_bar)

    def resizeEvent(self, event):
        """Make the code pattern background resize with the widget"""
        super().resizeEvent(event)
        self.code_pattern.setGeometry(self.rect())

    def show_menu(self):
        """Show the hamburger menu"""
        menu = QMenu(self)

        # Navigate up action
        navigate_up_action = QAction("UP ONE LEVEL", self)
        navigate_up_action.triggered.connect(self.navigate_up)
        menu.addAction(navigate_up_action)

        # Back to root action
        root_action = QAction("ROOT FOLDER", self)
        root_action.triggered.connect(self.navigate_to_root)
        menu.addAction(root_action)

        menu.addSeparator()

        # Settings action
        settings_action = QAction("SETTINGS", self)
        settings_action.triggered.connect(self.show_settings)
        menu.addAction(settings_action)

        menu.addSeparator()

        # Logout action
        logout_action = QAction("DEACTIVATE", self)
        logout_action.triggered.connect(self.logout)
        menu.addAction(logout_action)

        # Exit action
        exit_action = QAction("TERMINATE", self)
        exit_action.triggered.connect(QApplication.instance().quit)
        menu.addAction(exit_action)

        # Show the menu at button position
        menu.exec(self.menu_button.mapToGlobal(QPoint(0, self.menu_button.height())))

    def show_settings(self):
        """Show settings dialog"""
        QMessageBox.information(self, "SIVA SETTINGS", "Protocol configuration coming soon.")

    def show_context_menu(self, position):
        """Show context menu for files/folders"""
        menu = QMenu(self)

        selected_items = self.files_table.selectedItems()
        if not selected_items:
            return

        # Get the row of the first selected item
        row = selected_items[0].row()

        # Get item type (file or folder)
        item_type = self.files_table.item(row, 1).text()

        if item_type == "Folder":
            # Open folder action
            open_action = QAction("OPEN FOLDER", self)
            open_action.triggered.connect(lambda: self.open_folder(row))
            menu.addAction(open_action)
        else:
            # Open file action
            open_action = QAction("OPEN FILE", self)
            open_action.triggered.connect(lambda: self.open_file(row))
            menu.addAction(open_action)

            # Extract file action
            extract_action = QAction("EXTRACT", self)
            extract_action.triggered.connect(lambda: self.extract_selected_file(row))
            menu.addAction(extract_action)

        menu.addSeparator()

        # Delete action
        delete_action = QAction("DELETE", self)
        delete_action.triggered.connect(lambda: self.delete_selected_file(row))
        menu.addAction(delete_action)

        menu.exec(self.files_table.mapToGlobal(position))

    def handle_double_click(self, index):
        """Handle double click on file or folder"""
        row = index.row()
        item_type = self.files_table.item(row, 1).text()

        if item_type == "Folder":
            self.open_folder(row)
        else:
            self.open_file(row)

    def open_folder(self, row):
        """Open a folder by navigating to it"""
        folder_name = self.files_table.item(row, 0).text()
        new_path = os.path.join(self.current_folder, folder_name)
        self.navigate_to_folder(new_path)

    def open_file(self, row):
        """Open a file with the system's default application"""
        filename = self.files_table.item(row, 0).text()
        file_path = os.path.join(self.current_folder, f"{filename}.siva")

        # Get a temporary path for the file
        temp_path = self.temp_file_manager.get_temp_path(filename)

        # Decrypt the file to the temporary location
        decrypted_path = self.filesystem.decrypt_file(file_path, os.path.dirname(temp_path))

        if decrypted_path:
            # Track the file
            self.temp_file_manager.track_file(file_path, decrypted_path)

            # Open the file
            if self.temp_file_manager.open_file(decrypted_path):
                self.status_bar.showMessage(f"FILE OPENED: {filename}")
            else:
                self.status_bar.showMessage(f"ERROR OPENING FILE: {filename}")
        else:
            self.status_bar.showMessage(f"ERROR DECRYPTING FILE: {filename}")

    def extract_selected_file(self, row):
        """Extract a selected file"""
        filenames = [self.files_table.item(row, 0).text()]
        self.extract_files(filenames)

    def delete_selected_file(self, row):
        """Delete a selected file or folder"""
        items = [self.files_table.item(row, 0).text()]
        self.delete_files(items)

    def navigate_up(self):
        """Navigate up one folder level"""
        if self.current_folder == self.vault_path:
            return  # Already at the root

        parent_dir = os.path.dirname(self.current_folder)
        self.navigate_to_folder(parent_dir)

    def navigate_to_root(self):
        """Navigate to the root folder"""
        self.navigate_to_folder(self.vault_path)

    def navigate_to_folder(self, folder_path):
        """Navigate to a specific folder"""
        if os.path.isdir(folder_path):
            self.current_folder = folder_path
            self.load_secured_files()

            # Update path display
            relative_path = os.path.relpath(folder_path, self.vault_path)
            if relative_path == ".":
                self.path_label.setText("/ (ROOT)")
            else:
                self.path_label.setText(f"/{relative_path}")

    def load_secured_files(self):
        """Load and display secured files in the table"""
        self.files_table.setRowCount(0)  # Clear existing items

        try:
            # List all items in the current folder
            all_items = []

            # First add folders
            folders = [f for f in os.listdir(self.current_folder)
                       if os.path.isdir(os.path.join(self.current_folder, f))
                       and not f.startswith('.')]

            for folder in folders:
                all_items.append({
                    'name': folder,
                    'type': 'Folder',
                    'size': '',
                    'date': datetime.datetime.fromtimestamp(
                        os.path.getmtime(os.path.join(self.current_folder, folder))
                    ).strftime("%Y-%m-%d %H:%M:%S")
                })

            # Then add files
            siva_files = [f for f in os.listdir(self.current_folder)
                          if f.endswith('.siva') and os.path.isfile(os.path.join(self.current_folder, f))]

            for siva_file in siva_files:
                file_path = os.path.join(self.current_folder, siva_file)
                stats = os.stat(file_path)
                size_kb = stats.st_size / 1024

                # Format size display
                if size_kb < 1024:
                    size_display = f"{size_kb:.1f} KB"
                else:
                    size_mb = size_kb / 1024
                    size_display = f"{size_mb:.1f} MB"

                # Extract original filename (without the .siva extension)
                filename = siva_file.replace(".siva", "")

                # Get file type
                file_ext = self.filesystem.get_file_type(file_path)
                file_type = file_ext.upper() if file_ext else "Unknown"

                all_items.append({
                    'name': filename,
                    'type': file_type,
                    'size': size_display,
                    'date': datetime.datetime.fromtimestamp(stats.st_mtime).strftime("%Y-%m-%d %H:%M:%S")
                })

            # Display items in table
            for i, item in enumerate(all_items):
                row_position = self.files_table.rowCount()
                self.files_table.insertRow(row_position)

                # Add item data to table
                self.files_table.setItem(row_position, 0, QTableWidgetItem(item['name']))
                self.files_table.setItem(row_position, 1, QTableWidgetItem(item['type']))
                self.files_table.setItem(row_position, 2, QTableWidgetItem(item['size']))
                self.files_table.setItem(row_position, 3, QTableWidgetItem(item['date']))

                # Color folders differently
                if item['type'] == 'Folder':
                    folder_item = self.files_table.item(row_position, 0)
                    folder_item.setForeground(QColor(COLORS['accent']))

            # Update status bar
            total_files = len(siva_files)
            total_folders = len(folders)
            if total_files == 0 and total_folders == 0:
                self.status_bar.showMessage("FOLDER EMPTY")
            else:
                status = []
                if total_folders > 0:
                    status.append(f"{total_folders} FOLDER(S)")
                if total_files > 0:
                    status.append(f"{total_files} FILE(S)")
                self.status_bar.showMessage(f"INVENTORY: {', '.join(status)}")

        except Exception as e:
            self.status_bar.showMessage(f"ERROR LOADING FILES: {e}")
            print(f"Error loading files: {e}")

    def create_folder(self):
        """Create a new folder in the current location"""
        dialog = FolderDialog(self, self.current_folder)
        if dialog.exec():
            folder_name = dialog.get_folder_name()
            folder_path = os.path.join(self.current_folder, folder_name)

            if os.path.exists(folder_path):
                QMessageBox.warning(self, "ERROR", "FOLDER ALREADY EXISTS")
                return

            if self.filesystem.create_folder(folder_path):
                self.status_bar.showMessage(f"FOLDER CREATED: {folder_name}")
                self.load_secured_files()
            else:
                self.status_bar.showMessage("ERROR CREATING FOLDER")

    def add_files(self):
        """Select and add files to the secure vault"""
        filepaths, _ = QFileDialog.getOpenFileNames(self, "SELECT FILES TO INFECT")

        if not filepaths:
            return

        successful = 0
        for filepath in filepaths:
            # Generate destination path in the current folder
            filename = os.path.basename(filepath)
            dest_path = os.path.join(self.current_folder, f"{filename}.siva")

            # Encrypt and save the file
            if self.filesystem.encrypt_file(filepath, dest_path):
                successful += 1

        # Refresh the file list
        self.load_secured_files()

        if successful:
            self.status_bar.showMessage(f"SUCCESSFULLY INFECTED {successful} OF {len(filepaths)} FILE(S)")
        else:
            self.status_bar.showMessage("FAILED TO INFECT ANY FILES")

    def extract_files(self, selected_filenames=None):
        """Extract selected files from the vault"""
        if selected_filenames is None:
            # Get selected rows from the table
            selected_rows = set(item.row() for item in self.files_table.selectedItems())

            if not selected_rows:
                QMessageBox.information(self, "SELECTION REQUIRED", "SELECT FILES TO EXTRACT")
                return

            # Get filenames from selected rows
            selected_filenames = []
            for row in selected_rows:
                # Check if it's a file or folder
                item_type = self.files_table.item(row, 1).text()
                if item_type != "Folder":  # Only extract files, not folders
                    selected_filenames.append(self.files_table.item(row, 0).text())

        if not selected_filenames:
            QMessageBox.information(self, "NO FILES SELECTED", "NO FILES SELECTED FOR EXTRACTION")
            return

        # Ask for extraction directory
        output_dir = QFileDialog.getExistingDirectory(self, "SELECT OUTPUT DIRECTORY")

        if not output_dir:
            return

        successful = 0
        for filename in selected_filenames:
            encrypted_path = os.path.join(self.current_folder, f"{filename}.siva")

            if self.filesystem.decrypt_file(encrypted_path, output_dir):
                successful += 1

        if successful:
            self.status_bar.showMessage(f"SUCCESSFULLY EXTRACTED {successful} OF {len(selected_filenames)} FILE(S)")
            QMessageBox.information(self, "EXTRACTION COMPLETE",
                                    f"SUCCESSFULLY EXTRACTED {successful} FILE(S) TO SELECTED DIRECTORY")
        else:
            self.status_bar.showMessage("FAILED TO EXTRACT ANY FILES")

    def delete_files(self, selected_items=None):
        """Delete selected secured files and folders"""
        if selected_items is None:
            # Get selected rows from the table
            selected_rows = set(item.row() for item in self.files_table.selectedItems())

            if not selected_rows:
                QMessageBox.information(self, "SELECTION REQUIRED", "SELECT FILES OR FOLDERS TO DELETE")
                return

            # Get names from selected rows
            selected_items = [self.files_table.item(row, 0).text() for row in selected_rows]

        if not selected_items:
            return

        confirm = QMessageBox.question(
            self, "CONFIRM DELETION",
            f"ARE YOU SURE YOU WANT TO DELETE {len(selected_items)} ITEM(S)?\nTHIS ACTION CANNOT BE UNDONE.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )

        if confirm != QMessageBox.StandardButton.Yes:
            return

        deleted = 0
        for item_name in selected_items:
            file_path = os.path.join(self.current_folder, f"{item_name}.siva")
            folder_path = os.path.join(self.current_folder, item_name)

            try:
                # Check if it's a file or folder
                if os.path.isfile(file_path):
                    # It's a file
                    os.remove(file_path)
                    deleted += 1
                elif os.path.isdir(folder_path):
                    # It's a folder
                    shutil.rmtree(folder_path)
                    deleted += 1
            except Exception as e:
                print(f"Error deleting {item_name}: {e}")

        # Refresh the file list
        self.load_secured_files()

        self.status_bar.showMessage(f"PURGED {deleted} OF {len(selected_items)} ITEM(S)")

    def logout(self):
        """Log out of the vault and close any open files"""
        # Close all opened temporary files
        self.temp_file_manager.close_all()

        # Signal logout
        self.logout_requested.emit()


class SivaApplication(QMainWindow):
    """Main application window"""

    def __init__(self):
        super().__init__()

        # Set up window properties
        self.setWindowTitle("SIVA")
        self.setMinimumSize(900, 600)

        # Set window icon
        icon_path = "SIVA.png"
        if os.path.exists(icon_path):
            self.setWindowIcon(QIcon(icon_path))
        else:
            print(f"Warning: Icon file {icon_path} not found")

        # Set up paths
        documents_path = Path.home() / "Documents"
        self.vault_path = str(documents_path / ".siva_data")
        self.config_path = os.path.join(self.vault_path, ".siva_config")

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

        # Main screen will be created after login
        self.main_screen = None

        # Keyboard shortcut watcher
        self.keyboard_watcher = KeyboardWatcher()
        self.keyboard_watcher.triggered.connect(self.show_application)
        self.keyboard_watcher.start()

        # Set up startup registry entry
        self.setup_startup()

        # Initially hide the application
        self.hide()

    def closeEvent(self, event):
        """Override close event to hide instead of close"""
        event.ignore()  # Ignore the close event
        self.hide()  # Hide the window instead

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
                self.login_screen.set_status("ERROR: SYSTEM INITIALIZATION FAILED")
        else:
            # Verify password
            entered_hash = hashlib.sha256(password.encode()).hexdigest()
            if entered_hash == self.password_hash:
                self.show_main_screen(password)
            else:
                self.login_screen.set_status("ERROR: INVALID AUTHORIZATION KEY")

    def show_main_screen(self, password):
        """Show the main application screen"""
        # Create filesystem with password
        filesystem = SecureFileSystem(password)

        # Create or recreate main screen
        if self.main_screen:
            # If it exists, remove it first (in case we're re-logging in)
            self.main_widget.removeWidget(self.main_screen)

        # Create a new main screen
        self.main_screen = MainScreen(filesystem=filesystem, vault_path=self.vault_path)
        self.main_screen.logout_requested.connect(self.logout)
        self.main_widget.addWidget(self.main_screen)

        # Switch to main screen
        self.main_widget.setCurrentWidget(self.main_screen)

    def logout(self):
        """Handle logout request"""
        # Switch back to login screen
        self.main_widget.setCurrentWidget(self.login_screen)

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
                    "SIVA",
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

    # Add monospace font
    QFontDatabase.addApplicationFont("consolas.ttf")  # Optional: add your font if needed

    # Apply stylesheet
    app.setStyleSheet(STYLESHEET)

    # Create main window with renamed class
    window = SivaApplication()

    # Hide the process
    window.hide_process()

    # Run the application
    sys.exit(app.exec())


if __name__ == "__main__":
    main()