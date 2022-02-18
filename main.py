from PyQt6.QtWidgets import QApplication, QWidget, QInputDialog, QMessageBox
from PyQt6.QtWidgets import QTreeView, QGroupBox, QLineEdit, QPushButton, QFrame
from PyQt6.QtWidgets import QHBoxLayout, QVBoxLayout, QGridLayout, QFormLayout
from PyQt6.QtGui import QIcon, QStandardItemModel, QStandardItem

from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives.ciphers.modes import CTR

import hashlib
import base64
import secrets

import json
import string
import sys
import os

last_index = None
account_selected = False

# load encrypted passwords -----------------------------------------------------
try:
    with open("passwords.encrypted", "r") as file:
        password_data = json.load(file)
except FileNotFoundError:
    password_data= {}

# create the application -------------------------------------------------------
app = QApplication(sys.argv)
clipboard = app.clipboard()

# create the password tree -----------------------------------------------------
password_model = QStandardItemModel()
root_node = password_model.invisibleRootItem()

for key, value in sorted(password_data.items(), key=lambda x: x[0]):
    key_node = QStandardItem(key)
    root_node.appendRow(key_node)
    for account in value:
        key_node.appendRow(QStandardItem(account[0]))

# create the application window ------------------------------------------------
class MainWindow(QWidget):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("Password Manager")
        self.setWindowIcon(QIcon("icon.svg"))

        width, height = 600, 600

        # self.setGeometry(400, 200, width, height)

        self.layout = QHBoxLayout(self)

window = MainWindow()

# create window widgets --------------------------------------------------------
# create the password tree view ------------------------------------------------
password_tree_view = QTreeView(window)
password_tree_view.setHeaderHidden(True)
password_tree_view.setModel(password_model)
password_tree_view.expandAll()
password_tree_view.setMinimumWidth(100)
window.layout.addWidget(password_tree_view, 3)

# create right frame -----------------------------------------------------------
right_frame = QFrame()
window.layout.addWidget(right_frame, 4)
right_frame_layout = QVBoxLayout(right_frame)

# create groupbox --------------------------------------------------------------
edit_window = QGroupBox("Kontoinformationen", right_frame)
edit_window.setMinimumWidth(300)
right_frame_layout.addWidget(edit_window)

edit_window_layout = QFormLayout(edit_window)
edit_window.setLayout(edit_window_layout)

name_field = QLineEdit(edit_window)
id_field = QLineEdit(edit_window)
password_field = QLineEdit(edit_window)

edit_window_layout.addRow("Internetseite/Programm", name_field)
edit_window_layout.addRow("Benutzer", id_field)
edit_window_layout.addRow("Passwort", password_field)

# create button grid -----------------------------------------------------------
button_grid = QWidget(right_frame)
right_frame_layout.addWidget(button_grid)

button_grid_layout = QGridLayout(button_grid)

clear_button = QPushButton("Eingabefelder leeren", button_grid)
save_button = QPushButton("Passwort vorschlagen", button_grid)
delete_button = QPushButton("Konto löschen", button_grid)
add_button = QPushButton("Konto hinzufügen", button_grid)

button_grid_layout.addWidget(clear_button, 0, 0)
button_grid_layout.addWidget(save_button, 0, 1)
button_grid_layout.addWidget(delete_button, 1, 0)
button_grid_layout.addWidget(add_button, 1, 1)

# fill right_frame -------------------------------------------------------------
right_frame_layout.addStretch(1)


# function definition ----------------------------------------------------------
def get_master_password():
    return QInputDialog.getText(window, "Master-Passwort", "Bitte geben sie ihr Master-Passwort ein:")

def encrypt(data, key, nonce):
    encr = Cipher(AES(key), CTR(nonce)).encryptor()
    return encr.update(data) + encr.finalize()

def decrypt(data, key, nonce):
    decr = Cipher(AES(key), CTR(nonce)).decryptor()
    return decr.update(data) + decr.finalize()

def update_tree_view():
    global password_model, root_node
    password_model = QStandardItemModel()
    root_node = password_model.invisibleRootItem()

    for key, value in sorted(password_data.items(), key=lambda x: x[0]):
        key_node = QStandardItem(key)
        root_node.appendRow(key_node)
        for account in value:
            key_node.appendRow(QStandardItem(account[0]))

    password_tree_view.setModel(password_model)
    password_tree_view.expandAll()

def clicked_clear_button():
    global last_index, account_selected
    if account_selected:
        password, b = get_master_password()

        if b:
            name = password_model.itemFromIndex(last_index).parent().text()
            user_id = password_data[name][last_index.row()][0]

            key = hashlib.sha256(password.encode("UTF-8")).digest()
            del password

            nonce = password_data[name][last_index.row()][2]
            nonce_bytes = base64.b64decode(nonce)

            encrypted_password = password_data[name][last_index.row()][1]
            encrypted_password_bytes = base64.b64decode(encrypted_password)

            password_bytes = decrypt(encrypted_password_bytes, key, nonce_bytes)

            try:
                password = password_bytes.decode("UTF-8")
            except UnicodeDecodeError:
                del password_bytes
            else:
                name_field.setText(name)
                id_field.setText(user_id)
                password_field.setText(password)

                clipboard.setText(password)
                del password_bytes, password

                clear_button.setText("Eingaben löschen")
                account_selected = False
                last_index = None
    else:
        name_field.clear()
        id_field.clear()
        password_field.clear()
clear_button.clicked.connect(clicked_clear_button)

def clicked_save_button():
    possible_chars = string.ascii_letters + string.digits + string.punctuation
    while True:
        new_password = "".join(secrets.choice(possible_chars) for i in range(16))
        if (sum(c.islower() for c in new_password) > 1
                and sum(c.isupper() for c in new_password) > 1
                and sum(c.isdigit() for c in new_password) > 1):
            break
    password_field.setText(new_password)
save_button.clicked.connect(clicked_save_button)

def clicked_delete_button():
    global last_index, account_selected
    if account_selected:
        name = password_model.itemFromIndex(last_index).parent().text()

        password_data[name].pop(last_index.row())
        password_model.itemFromIndex(last_index).parent().removeRow(last_index.row())

        if not password_data[name]:
            del password_data[name]
            root_node.removeRow(last_index.parent().row())

        with open("passwords.encrypted", "w") as file:
            json.dump(password_data, file, indent=4)
delete_button.clicked.connect(clicked_delete_button)

def clicked_add_button():
    master_password, b = get_master_password()
    if b:
        key = hashlib.sha256(master_password.encode("UTF-8")).digest()
        del master_password
        nonce_bytes = os.urandom(128//8)
        password_bytes = password_field.text().encode("UTF-8")
        encrypted_password_bytes = encrypt(password_bytes, key, nonce_bytes)

        nonce = base64.b64encode(nonce_bytes).decode("UTF-8")
        encrypted_password = base64.b64encode(encrypted_password_bytes).decode("UTF-8")

        del nonce_bytes, password_bytes

        name = name_field.text()
        user_id = id_field.text()

        password_data.setdefault(name, []).append((user_id, encrypted_password, nonce))

        update_tree_view()

        with open("passwords.encrypted", "w") as file:
            json.dump(password_data, file, indent=4)

        name_field.clear()
        id_field.clear()
        password_field.clear()



add_button.clicked.connect(clicked_add_button)

def click_password_tree(index):
    global last_index, account_selected
    if password_model.itemFromIndex(index).parent():
        clear_button.setText("Konto anzeigen")
        last_index = index
        account_selected = True
    else:
        password_tree_view.setExpanded(index, not password_tree_view.isExpanded(index))
password_tree_view.clicked.connect(click_password_tree)

# show the window and start the main loop --------------------------------------
window.show()
sys.exit(app.exec())
