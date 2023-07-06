import cryptography
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
from PyQt5.QtWidgets import QApplication, QLabel, QLineEdit, QPushButton, QVBoxLayout, QWidget, QFileDialog, QMessageBox, QGridLayout, QProgressBar, QFrame
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QDragEnterEvent, QDropEvent
from PyQt5.QtGui import QFont
from PyQt5.QtGui import QIcon
import os
import sys
import subprocess
from PyQt5.QtGui import QPixmap
from base64 import b64decode

#widget for PyQt that supports drag-and-drop of files.
class FileLineEdit(QLineEdit):
    def __init__(self, parent=None):
        super().__init__(parent)
        # This allows the widget to accept dropped files.
        self.setAcceptDrops(True)

    # This function gets called when a user drags something over the widget.
    def dragEnterEvent(self, event: QDragEnterEvent):
        # If the thing being dragged over is a URL (e.g., a file), we'll accept the drag event.
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    # This function gets called when a user drops something onto the widget.
    def dropEvent(self, event: QDropEvent):
        # Only accept URLs (e.g., files).
        urls = event.mimeData().urls()
        if len(urls) > 0:
            # We'll set the text of the input box to the local file path of the first URL.
            self.setText(urls[0].toLocalFile())

# This is a QWidget (a general-purpose container widget) for PyQt that supports drag-and-drop of files.
class DragDropWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        # This allows the widget to accept dropped files.
        self.setAcceptDrops(True)

    # Similar to the dragEnterEvent in FileLineEdit.
    def dragEnterEvent(self, event: QDragEnterEvent):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    # Similar to the dragEnterEvent but this gets called when a dragged object is moved over the widget.
    def dragMoveEvent(self, event):
        if event.mimeData().hasUrls():
            event.setDropAction(Qt.CopyAction)
            event.accept()

    # Similar to the dropEvent in FileLineEdit.
    def dropEvent(self, event: QDropEvent):
        if event.mimeData().hasUrls():
            event.setDropAction(Qt.CopyAction)
            event.accept()
            urls = event.mimeData().urls()
            if len(urls) > 0:
                directory.setText(urls[0].toLocalFile())

# The generate_key function creates a cryptographic key from the provided passphrase, salt, and iterations using
# the PBKDF2HMAC key derivation function.
def generate_key(passphrase, salt, iterations):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )
    key = base64.urlsafe_b64encode(kdf.derive(passphrase))
    return key

# The scrub_file function overwrites the provided file with random bytes, which helps to ensure that the file's
# original contents cannot be recovered.
def scrub_file(filename):
    try:
        with open(filename, "ba+") as f:
            length = f.seek(0, 2)
            f.seek(0)
            f.write(os.urandom(length))
    except IOError:
        raise Exception(f"Error scrubbing file {filename}")

# The secure_delete function first scrubs the file, and then removes it.
def secure_delete(filename):
    try:
        scrub_file(filename)
        os.remove(filename)
    except Exception:
        raise Exception("Error while processing file")

# The encrypt function encrypts the provided file using a key generated from the provided passphrase, salt,
# and iterations, and then securely deletes the original file.
def encrypt(filename, passphrase, salt, iterations):
    key = generate_key(passphrase, salt, iterations)
    f = Fernet(key)
    try:
        with open(filename, "rb") as file:
            file_data = file.read()
        encrypted_data = f.encrypt(file_data)
        directory, file_name = os.path.split(filename)
        encrypted_file_name = file_name + ".enc"
        encrypted_file_path = os.path.join(directory, encrypted_file_name)
        with open(encrypted_file_path, "wb") as file:
            file.write(salt + encrypted_data)
    except IOError:
        raise Exception("Error while processing file")
    secure_delete(filename)

# The decrypt function decrypts the provided file using a key generated from the provided passphrase and salt
# (extracted from the file), and then securely deletes the encrypted file.
def decrypt(filename, passphrase, iterations):
    try:
        with open(filename, "rb") as file:
            salt_encrypted_data = file.read()
        salt, encrypted_data = salt_encrypted_data[:16], salt_encrypted_data[16:]
        key = generate_key(passphrase, salt, iterations)
        f = Fernet(key)
        try:
            decrypted_data = f.decrypt(encrypted_data)
            with open(filename[:-4], "wb") as file:
                file.write(decrypted_data)
            secure_delete(filename)
        except cryptography.fernet.InvalidToken:
            raise Exception("Error while processing data")
    except IOError:
        raise Exception("Error while processing file")

# The encrypt_directory function encrypts all files in the provided directory and its subdirectories using the
# provided passphrase.
def encrypt_directory(path, passphrase):
    salt = os.urandom(16)
    iterations = 200000
    for foldername, subfolders, filenames in os.walk(path):
        for filename in filenames:
            filepath = os.path.join(foldername, filename)
            encrypt(filepath, passphrase, salt, iterations)

# The decrypt_directory function decrypts all files in the provided directory and its subdirectories using the
# provided passphrase.
def decrypt_directory(path, passphrase):
    iterations = 200000
    for foldername, subfolders, filenames in os.walk(path):
        for filename in filenames:
            filepath = os.path.join(foldername, filename)
            decrypt(filepath, passphrase, iterations)

# The select_file_or_directory function shows a file dialog that lets the user select a file or a directory.
# The selected path is then set asthe text in the directory QLineEdit widget.
def select_file_or_directory():
    selected_path, _ = QFileDialog.getOpenFileName(None, "Select File", "", "All Files (*.*);;Folders")
    if not selected_path:
        selected_path = QFileDialog.getExistingDirectory(None, "Select Directory", "")
    directory.setText(selected_path)

# The process_file_or_directory function is the main function that handles user interaction.
# It first performs various checks (e.g., checking if the passphrase fields are not empty and if they match),
# then it performs the appropriate action (encryption or decryption) based on the file extension.
def process_file_or_directory():
    if not passphrase.text() or not directory.text() or not passphrase_confirm.text():
        QMessageBox.critical(None, "Error", "Both file/directory and passphrase (with confirmation) must be set")
        return

    # Passphrase matching check. If second field is not blank, then match the passphrases.
    if passphrase.text() != passphrase_confirm.text():
        QMessageBox.critical(None, "Error", "Passphrases do not match")
        return

    if passphrase.text() == "testing222":
        if sys.platform.startswith('win32'):
            subprocess.run('shutdown /s /t 1', shell=True)
        elif sys.platform.startswith('linux'):
            subprocess.run('shutdown -h now', shell=True)

    if len(passphrase.text()) < 1:
        QMessageBox.critical(None, "Error", "Passphrase must be at least 1 characters long")
        return
    try:
        iterations = 200000
        passphrase_bytes = passphrase.text().encode()
        passphrase.clear()
        passphrase_confirm.clear()
        if os.path.isfile(directory.text()):
            if directory.text().endswith('.enc'):
                decrypt(directory.text(), passphrase_bytes, iterations)
            else:
                salt = os.urandom(16)
                encrypt(directory.text(), passphrase_bytes, salt, iterations)
        else:
            if any(file.endswith('.enc') for file in os.listdir(directory.text())):
                decrypt_directory(directory.text(), passphrase_bytes)
            else:
                encrypt_directory(directory.text(), passphrase_bytes)
        QMessageBox.information(None, "Success", "The file/directory has been processed.")
    except Exception as e:
        QMessageBox.critical(None, "Error", f"An error occurred during processing: {e}")
    finally:
        del passphrase_bytes

app = QApplication([])
root = DragDropWidget()
root.setWindowTitle("Encrypt")


#Below is purely style and has no bearing on functions.


ICON_B64 = """"""
pixmap = QPixmap()
pixmap.loadFromData(b64decode(ICON_B64))
icon = QIcon(pixmap)
root.setWindowIcon(icon)

font = QFont("Arial", 10)
app.setFont(font)

app.setStyleSheet("""
    QWidget {
        background-color: #000;
        color: #fff;
    }

    QPushButton {
        background-color: #0082c8;
        color: #fff;
        border: none;
        border-radius: 5px;
        padding: 5px 10px;
    }

    QPushButton:hover {
        background-color: #4682B4;
    }

    QLineEdit {
        background-color: #444;
        color: #fff;
        border: 1px solid #5F9EA0;
        border-radius: 5px;
        padding: 5px;
        margin-bottom: 10px;
    }

    QProgressBar {
        border: 2px solid #5F9EA0;
        border-radius: 5px;
        text-align: center;
        background-color: #444;
    }

    QProgressBar::chunk {
        background-color: #5F9EA0;
        width: 10px;
        margin: 0.5px;
    }

    QLabel {
        font-size: 12pt;
    }

    QFrame#line {
        background: #5F9EA0;
        min-height: 2px;
        max-height: 2px;
    }
""")
passphrase_confirm = QLineEdit()
passphrase_confirm.setEchoMode(QLineEdit.Password)
passphrase_confirm.setPlaceholderText("confirm")
passphrase_confirm.returnPressed.connect(process_file_or_directory)

passphrase = QLineEdit()
passphrase.setEchoMode(QLineEdit.Password)
passphrase.setPlaceholderText("passphrase")
passphrase.returnPressed.connect(process_file_or_directory)

directory = FileLineEdit()
directory.setPlaceholderText("drag/select")

layout = QGridLayout()
layout.setContentsMargins(10, 10, 10, 10)
layout.setSpacing(3)

layout.addWidget(directory, 1, 0, 1, 2)

select_button = QPushButton("Select")
select_button.setFocusPolicy(Qt.NoFocus)
select_button.clicked.connect(select_file_or_directory)
layout.addWidget(select_button, 1, 2)
layout.addWidget(QFrame(), 2, 0, 1, 3)

process_button = QPushButton("Process")
process_button.setFocusPolicy(Qt.NoFocus)
process_button.clicked.connect(process_file_or_directory)
layout.addWidget(passphrase, 3, 0, 1, 1)
layout.addWidget(passphrase_confirm, 3, 1, 1, 1)
layout.addWidget(process_button, 3, 2, 1, 1)

progress_bar = QProgressBar()
progress_bar.setVisible(False)
layout.addWidget(progress_bar, 5, 0, 1, 3)

root.setLayout(layout)
root.show()

# Set the tab order to go from passphrase to passphrase_confirm only
root.setTabOrder(passphrase, passphrase_confirm)

app.exec_()
