import os
import sqlite3
import base64
from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.button import Button
from kivy.uix.label import Label
from kivy.uix.textinput import TextInput
from kivy.uix.popup import Popup
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

def generate_master_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())


def verify_master_key(password, salt, key):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
        backend=default_backend()
    )
    kdf.verify(password.encode(), key)

def encrypt(key, plaintext, associated_data):
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), associated_data)
    return base64.b64encode(nonce + ciphertext).decode('utf-8')

def decrypt(key, encrypted_data, associated_data):
    aesgcm = AESGCM(key)
    data = base64.b64decode(encrypted_data)
    nonce = data[:12]
    ciphertext = data[12:]
    return aesgcm.decrypt(nonce, ciphertext, associated_data).decode('utf-8')


def create_connection(db_file):
    conn = None
    try:
        conn = sqlite3.connect(db_file, timeout=10)
    except Exception as e:
        print(f"An error occurred: {e}")
    return conn

def create_table(conn):
    try:
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS passwords 
                     (service TEXT NOT NULL, username TEXT NOT NULL, password TEXT NOT NULL);''')
    except Exception as e:
        print(f"An error occurred: {e}")

def add_password(conn, service, username, password, key):
    encrypted_password = encrypt(key, password, service.encode())
    try:
        sql = ''' INSERT INTO passwords(service,username,password) VALUES(?,?,?) '''
        cur = conn.cursor()
        cur.execute(sql, (service, username, encrypted_password))
        conn.commit()
    except Exception as e:
        print(f"An error occurred while adding the password: {e}")

def get_password(conn, service, key):
    try:
        cur = conn.cursor()
        cur.execute("SELECT username, password FROM passwords WHERE service=?", (service,))
        rows = cur.fetchall()
        for row in rows:
            username, encrypted_password = row
            password = decrypt(key, encrypted_password, service.encode())
            print(f"Service: {service}, Username: {username}, Password: {password}")
    except Exception as e:
        print(f"An error occurred while retrieving the password: {e}")


class PasswordManagerApp(App):

    def build(self):
        self.conn = create_connection("pythonsqlite.db")
        with self.conn:
            create_table(self.conn)
        self.layout = BoxLayout(orientation='vertical')
        self.add_button = Button(text='Add New Password')
        self.add_button.bind(on_press=self.add_password_gui)
        self.get_button = Button(text='Retrieve a Password')
        self.get_button.bind(on_press=self.get_password_gui)
        self.layout.add_widget(self.add_button)
        self.layout.add_widget(self.get_button)
        return self.layout

    def add_password_gui(self, instance):
        self.popup_layout = BoxLayout(orientation='vertical')
        self.service_input = TextInput(hint_text='Service')
        self.username_input = TextInput(hint_text='Username')
        self.password_input = TextInput(hint_text='Password', password=True)
        submit_button = Button(text='Submit')
        submit_button.bind(on_press=self.submit_new_password)
        self.popup_layout.add_widget(self.service_input)
        self.popup_layout.add_widget(self.username_input)
        self.popup_layout.add_widget(self.password_input)
        self.popup_layout.add_widget(submit_button)
        self.popup = Popup(title='Add Password', content=self.popup_layout)
        self.popup.open()

    def submit_new_password(self, instance):
        service = self.service_input.text
        username = self.username_input.text
        password = self.password_input.text

    def on_dismiss(_):
        master_password = master_password_input.text
        if master_password:
            try:
                with open("salt.key", "rb") as salt_file:
                    salt = salt_file.read()
                    master_key = generate_master_key(master_password, salt)
                    add_password(self.conn, service, username, password, master_key)
            except IOError as e:
                print(f"An error occurred while loading the salt: {e}")
            except Exception as e:
                print(f"An error occurred: {e}")
        self.popup.dismiss()

    master_password_input = TextInput(password=True)
    popup = Popup(title='Enter Master Password',
                  content=master_password_input,
                  size_hint=(None, None), size=(400, 200))

    popup.bind(on_dismiss=on_dismiss)
    popup.open()

    def get_password_gui(self, instance):
        self.popup_layout = BoxLayout(orientation='vertical')
        self.service_input = TextInput(hint_text='Service')
        submit_button = Button(text='Submit')
        submit_button.bind(on_press=self.submit_get_password)
        self.popup_layout.add_widget(self.service_input)
        self.popup_layout.add_widget(submit_button)
        self.popup = Popup(title='Retrieve Password', content=self.popup_layout)
        self.popup.open()

    def submit_get_password(self, instance):
       service = self.service_input.text

    def on_dismiss(_):
        master_password = master_password_input.text
        if master_password:
            try:
                with open("salt.key", "rb") as salt_file:
                    salt = salt_file.read()
                    master_key = generate_master_key(master_password, salt)
                    try:
                        cur = self.conn.cursor()
                        cur.execute("SELECT username, password FROM passwords WHERE service=?", (service,))
                        row = cur.fetchone()
                        if row:
                            username, encrypted_password = row
                            password = decrypt(master_key, encrypted_password, service.encode())
                            print(f"Username: {username}, Password: {password}")
                        else:
                            print("No password found for this service.")
                    except Exception as e:
                        print(f"An error occurred while retrieving the password: {e}")
            except IOError as e:
                print(f"An error occurred while loading the salt: {e}")
            except Exception as e:
                print(f"An error occurred: {e}")
        self.popup.dismiss()

    master_password_input = TextInput(password=True)
    popup = Popup(title='Enter Master Password',
                  content=master_password_input,
                  size_hint=(None, None), size=(400, 200))

    popup.bind(on_dismiss=on_dismiss)
    popup.open()



if __name__ == '__main__':
    PasswordManagerApp().run()
