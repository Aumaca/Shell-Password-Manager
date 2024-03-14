import sqlite3, os, bcrypt, base64
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from prettytable import PrettyTable
from peewee import *
from model import Password
from utils import colors

def custom_input(input_name: str, label: str):
    new_input = input(label)
    while len(new_input) == 0:
        print(f"Invalid input for {input_name}.")
        new_input = input(label)
    return new_input


class Program:
    def __init__(self):
        self.initialize_database()
        self.show_menu()


    def initialize_database(self):
        try:
            db = SqliteDatabase('passwords.db')
            if not db.table_exists('password'):
                print("CREATING DATABASE....")
                db.create_tables([Password])
        except:
            raise Exception("An error occurred when trying to create table 'passwords'.")
            

    def show_menu(self):
        if os.name == 'posix':  # Unix/Linux/MacOS
            os.system('clear')
        elif os.name == 'nt':  # Windows
            os.system('cls')
    
        options = [
            "Show passwords",
            "Create new password",
            "Reveal password",
            "Edit password title",
            "Delete password",
        ]

        print(colors.OKGREEN + "PASSWORD KEEPER" + colors.ENDC)
        print("===============")
        for i, option in enumerate(options, 1):
            print(f"{i} - {option}")
        
        while True:
            user_option = input(f"{colors.OKGREEN}>{colors.ENDC} Your option: ")
            if len(user_option) != 1 or not user_option.isdigit() or user_option == '0':
                print(colors.FAIL + "Invalid option. Try again." + colors.ENDC)
            else:
                print("\n")
                break

        user_option = int(user_option)
        functions = [self.show_passwords, self.create_password, self.reveal_password, self.edit_password_title, self.delete_password]
        function = functions[user_option - 1]
        function()


    def show_passwords(self):
        table = PrettyTable()
        table.field_names = [
            f"{colors.WARNING}ID{colors.ENDC}",
            f"{colors.WARNING}TITLE{colors.ENDC}",
            f"{colors.WARNING}EMAIL{colors.ENDC}",
            f"{colors.WARNING}NOTES{colors.ENDC}",
            f"{colors.WARNING}URL{colors.ENDC}",
            f"{colors.WARNING}PASSWORD{colors.ENDC}",
            f"{colors.WARNING}SAFE PASSWORD{colors.ENDC}",
        ]
        for row in Password.select().order_by(Password.title.desc()):
            tab_row = [f"{colors.WARNING}{row.id}{colors.ENDC}", row.title, row.email, row.notes, row.url, "********", "********"]
            table.add_row(tab_row)

        print(table)

        input("Type anything to return to menu...")
        self.show_menu()

    
    def create_password(self):
        try:
            password_title = custom_input("password title", "Password title: ")
            password_email = custom_input("password email", "Password email: ")
            password_notes = custom_input("password notes", "Password notes: ")
            password_url = custom_input("password url", "Password url: ")

            while True:
                password = custom_input("password to keep", "Password to keep: ")
                password_again = custom_input("password to keep again", "Password to keep again: ")
                if password != password_again:
                    print(f"{colors.FAIL}Passwords to keep don't match. Please, try again.{colors.ENDC}")
                else:
                    break

            while True:
                safe_password = custom_input("safe password", "Safe password to unlock password: ")
                safe_password_again = custom_input("safe password again ", "Safe password unlock to password again: ")
                if safe_password != safe_password_again:
                    print(f"{colors.FAIL}Safe passwords don't match. Please, try again.{colors.ENDC}")
                else:
                    break

            # Process passwords and save them
            processed_passwords: dict = self.process_passwords(safe_password, password)
            new_data = Password.create(
                title=password_title,
                email=password_email,
                notes=password_notes,
                url=password_url,
                safe_password=processed_passwords['hashed_safe_password'],
                password=processed_passwords['encrypted_password'],
            )
            new_data.save()

            self.show_menu()
        except Exception as e:
            print(f"{colors.FAIL}Error while trying to save new password to database.{colors.ENDC}")
            print(e)
            input("Type anything to return to menu...")
            self.show_menu()


    def reveal_password(self):
        try:
            # Get password title and the data from db
            while True:
                pwd_title = input(f"{colors.OKGREEN}>{colors.ENDC} Password title: ")
                password_data = Password.get(Password.title == pwd_title)
                if not pwd_title or not password_data:
                    print(f"{colors.FAIL}Invalid password title.{colors.ENDC}")
                else:
                    break
            
            # Get safe password and check
            while True:
                input_pwd_safe = input(f"{colors.OKGREEN}>{colors.ENDC} Insert Safe Password of {password_data.title}: ")
                isPwdCorrect = bcrypt.checkpw(input_pwd_safe.encode('utf-8'), password_data.safe_password.encode('utf-8'))
                if isPwdCorrect is not True:
                    print(f"{colors.FAIL}Incorrect password.{colors.ENDC}") 
                else:
                    break

            decrypted_password = self.decrypt_password(input_pwd_safe.encode('utf-8'), password_data.password)
            print(f"{colors.OKGREEN}{pwd_title}'s password:{colors.ENDC} {decrypted_password}")
            input("Type anything to return to menu...")
            self.show_menu()
        except:
            print(f"{colors.FAIL}Password {pwd_title} don't exist.{colors.ENDC}")
            input("Type anything to return to menu...")
            self.show_menu()
        

    def edit_password_title(self):
        try:
            old_password_title = input(f"{colors.OKGREEN}>{colors.ENDC} Password title to edit: ")
            new_password_title = input(f"{colors.OKGREEN}>{colors.ENDC} New password title: ")
            Password.update(title=new_password_title).where(Password.title == old_password_title).execute()
            self.show_menu()
        except:
            print(f"{colors.FAIL}Error while editing password's title.{colors.ENDC}")
            input("Type anything to return to menu...")
            self.show_menu()
        

    def delete_password(self):
        try:
            password_title = input(f"{colors.OKGREEN}>{colors.ENDC} Password title to remove: ")
            Password.delete().where(Password.title == password_title).execute()
            self.show_menu()
        except:
            print(f"{colors.FAIL}Error while deleting password.{colors.ENDC}")
            input("Type anything to return to menu...")
            self.show_menu()
    

    # Hash the safe password
    # Create key based on safe password
    # Encrypt password
    def process_passwords(self, safe_password: str, password: str) -> dict:
        try:
            safe_password_bytes: bytes = safe_password.encode('utf-8')
            password_bytes: bytes = password.encode('utf-8')

            hashed_safe_password: bytes = bcrypt.hashpw(safe_password_bytes, bcrypt.gensalt())

            # Encrypt password to keep
            key: bytes = self.generate_fernet_key(safe_password_bytes)
            encrypted_password = Fernet(key).encrypt(password_bytes)

            passwords = {
                'hashed_safe_password': hashed_safe_password,
                'encrypted_password': encrypted_password,
            }
            return passwords
        except:
            print(f"{colors.FAIL}Error while processing passwords.{colors.ENDC}")
            input("Type anything to return to menu...")
            self.show_menu()
        

    def generate_fernet_key(self, safe_pwd: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=safe_pwd,
            iterations=100000,
        )
        key: bytes = base64.urlsafe_b64encode(kdf.derive(safe_pwd))
        return key
    

    def decrypt_password(self, safe_pwd: bytes, encrypted_pwd: bytes) -> str:
        try:
            key = self.generate_fernet_key(safe_pwd)
            decrypted_pwd: bytes = Fernet(key).decrypt(encrypted_pwd)
            return decrypted_pwd.decode("utf-8")
        except Exception as e:
            raise Exception("Error while decrypting password.") from e

teste = Program()