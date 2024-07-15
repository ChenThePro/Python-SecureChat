import socket
import threading
import rsa
import pyaes
import sqlite3
import smtplib
import random
import bcrypt
import json
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import base64
import zlib
import time
from collections import defaultdict
from datetime import datetime

SERVER_EMAIL = "max_shor@yahoo.com"
PASS = "bvyx rpsb lfsl ursr"
active_clients = {}
IP = '0.0.0.0'
PORT = 8200
RATE_LIMIT = 100
BLACKLIST_TIMEOUT = 60 * 60
request_counts = defaultdict(int)
blacklist = {}
DOMAINS = ["gmail.com", "yahoo.com"]


class DataBase:
    """ Handles database interactions """

    @staticmethod
    def execute_query(query, params=(), fetchone=False, fetchall=False):
        """ Executes an SQL query with the provided parameters """
        with sqlite3.connect('DataBase.db') as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            conn.commit()
            if fetchone:
                return cursor.fetchone()
            if fetchall:
                return cursor.fetchall()
            return None

    @staticmethod
    def sign_in(username, password):
        """ Signs in a user by validating their credentials """
        user = DataBase.execute_query("SELECT * FROM Users WHERE username = ?", (username,), fetchone=True)
        if user and bcrypt.checkpw(password.encode("utf-8"), user[2].encode("utf-8")):
            return "OK"
        return "username or password wrong"

    @staticmethod
    def sign_up(username, password, email):
        """ Registers a new user """
        if DataBase.validate_user(username) or DataBase.get_group_id(username):
            return "user or group with this name already exists"
        password_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
        flag = bool(DataBase.execute_query("SELECT * FROM Verified_Emails WHERE email = ?", (email,), fetchone=True))
        if flag:
            DataBase.execute_query("INSERT INTO Users (username, password, email) VALUES (?, ?, ?)",
                                   (username, password_hash, email))
            user_id = DataBase.get_user_id(username)
            DataBase.execute_query("INSERT INTO Volumes (id) VALUES (?)", (user_id,))
            DataBase.execute_query("INSERT INTO Sounds (id) VALUES (?)", (user_id,))
            DataBase.execute_query("INSERT INTO Backgrounds (id) VALUES (?)", (user_id,))
            return "OK"
        return "not a verified email"

    @staticmethod
    def validate_user(username):
        """ Validates if a user exists """
        return DataBase.execute_query("SELECT 1 FROM Users WHERE username = ?", (username,), fetchone=True) is not None

    @staticmethod
    def get_email(username):
        """ Retrieves the email for a given username """
        email = DataBase.execute_query("SELECT email FROM Users WHERE username = ?", (username,), fetchone=True)
        return email[0] if email else None

    @staticmethod
    def change_password(username, new_password):
        """ Changes a user's password """
        password_hash = bcrypt.hashpw(new_password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
        DataBase.execute_query("UPDATE Users SET password = ? WHERE username = ?", (password_hash, username))

    @staticmethod
    def check_contact(id1, id2):
        """ Checks if two users are contacts """
        return bool(DataBase.execute_query(
            "SELECT * FROM Contacts WHERE (user_id = ? AND contact_id = ?) OR (user_id = ? AND contact_id = ?)",
            (id1, id2, id2, id1), fetchone=True))

    @staticmethod
    def add_contact(username1, username2):
        """ Adds a contact for a user """
        email1, email2 = DataBase.get_email(username1), DataBase.get_email(username2)
        if email1.split("@")[1] in DOMAINS or email2.split("@")[1] in DOMAINS or \
                email1.split("@")[1].split(".")[0] == email2.split("@")[1].split(".")[0]:
            user_id1, user_id2 = DataBase.get_user_id(username1), DataBase.get_user_id(username2)
            if DataBase.check_contact(user_id1, user_id2):
                return "already a contact"
            DataBase.execute_query("INSERT INTO Contacts (user_id, contact_id) VALUES (?, ?)", (user_id1, user_id2))
            return "OK"
        return "cannot add a user from another company"

    @staticmethod
    def get_user_id(username):
        """ Retrieves the user ID for a given username """
        user = DataBase.execute_query("SELECT id FROM Users WHERE username = ?", (username,), fetchone=True)
        return user[0] if user else None

    @staticmethod
    def get_contacts(username):
        """ Gets a user's contacts """
        user_id = DataBase.get_user_id(username)
        contacts = DataBase.execute_query("""
            SELECT contact_id FROM Contacts WHERE user_id = ? 
            UNION 
            SELECT user_id FROM Contacts WHERE contact_id = ?""", (user_id, user_id), fetchall=True)
        return [DataBase.execute_query("SELECT username FROM Users WHERE id = ?", (c[0],), fetchone=True)[0] for c in
                contacts] or [""]

    @staticmethod
    def send_private(sender, receiver, msg, file, filename, timestamp):
        """ Sends a private message or file """
        sender_id = DataBase.get_user_id(sender)
        receiver_id = DataBase.get_user_id(receiver)
        if receiver_id:
            table_name = "Messages"
            receiver_type = "receiver_id"
            flag = True
        else:
            flag = False
            receiver_id = DataBase.get_group_id(receiver)
            table_name = "Groups_Messages"
            receiver_type = "group_id"
        query = f"INSERT INTO {table_name} (sender_id, {receiver_type}, msg, file, path, time) VALUES (?, ?, ?, ?, ?, ?)"
        params = (sender_id, receiver_id, msg, file, filename, timestamp)
        DataBase.execute_query(query, params)
        if flag:
            if receiver in active_clients:
                active_clients[receiver].send_message(sender, msg, file, filename, timestamp)
        else:
            participants = DataBase.get_group_participants(receiver_id)
            for participant in participants:
                if participant in active_clients and participant != sender:
                    active_clients[participant].send_message(sender, msg, file, filename, timestamp, receiver)

    @staticmethod
    def get_group_participants(group_id):
        """ Retrieves participants of a group """
        participants = DataBase.execute_query("""SELECT U.username FROM Participants P JOIN Users U ON P.user_id = U.id
            WHERE P.group_id = ?""", (group_id,), fetchall=True)
        return [participant[0] for participant in participants] if participants else []

    @staticmethod
    def get_chat(sender, receiver):
        """ Retrieves chat history between two users """
        sender_id, receiver_id = DataBase.get_user_id(sender), DataBase.get_user_id(receiver)
        return DataBase.execute_query("""
            SELECT U.username, M.msg, M.file, M.path, M.time 
            FROM Messages M
            JOIN Users U ON M.sender_id = U.id
            WHERE (M.sender_id = ? AND M.receiver_id = ?) 
               OR (M.sender_id = ? AND M.receiver_id = ?)""",
                                      (sender_id, receiver_id, receiver_id, sender_id), fetchall=True) or []

    @staticmethod
    def get_volume(username):
        """ Retrieves a user's volume setting """
        user_id = DataBase.get_user_id(username)
        volume = DataBase.execute_query("SELECT volume FROM Volumes WHERE id = ?", (user_id,), fetchone=True)
        return volume[0] if volume else ""

    @staticmethod
    def get_sound(username):
        """ retrieves a user's sound path and file """
        user_id = DataBase.get_user_id(username)
        sound = DataBase.execute_query("SELECT path, file FROM Sounds WHERE id = ?", (user_id,), fetchone=True)
        return sound if sound else ""

    @staticmethod
    def change_volume(volume, username):
        """ Changes a user's volume setting """
        DataBase.execute_query("UPDATE Volumes SET volume = ? WHERE id = ?", (volume, DataBase.get_user_id(username)))

    @staticmethod
    def change_background(path, file, username):
        """ Changes a user's background """
        DataBase.execute_query(
            "UPDATE Backgrounds SET path = ?, file = ? WHERE id = ?", (path, file, DataBase.get_user_id(username)))

    @staticmethod
    def get_background(username):
        """ Retrieves a user's background """
        background = DataBase.execute_query("SELECT path, file FROM Backgrounds WHERE id = ?",
                                            (DataBase.get_user_id(username),), fetchone=True)
        return background if background else ""

    @staticmethod
    def get_group_id(group_name):
        """ gets the group's id """
        group_id = DataBase.execute_query("SELECT id FROM Groups WHERE name = ?", (group_name,), fetchone=True)
        return group_id[0] if group_id else None

    @staticmethod
    def create_group(data, user):
        """ creates a group with given participants """
        group_name = data[0]
        participants = data[1:]
        flag = True
        company = None
        for participant in participants:
            email = DataBase.get_email(participant).split("@")[1]
            if email not in DOMAINS:
                if not company:
                    company = email
                elif company != email:
                    active_clients[user].send_notification("Can't create a group with workers from different companies")
                    flag = False
                    break
        if flag:
            DataBase.execute_query("INSERT INTO Groups (name) VALUES (?)", (group_name,))
            group_id = DataBase.get_group_id(group_name)
            for participant in participants:
                user_id = DataBase.get_user_id(participant)
                DataBase.execute_query("INSERT INTO Participants (group_id, user_id) VALUES (?, ?)", (group_id, user_id,))
                if participant in active_clients and participant != user:
                    active_clients[participant].send_group(group_name, [])
            DataBase.make_admin(group_name, user)
            active_clients[user].send_notification("OK")

    @staticmethod
    def validate_group(group_name):
        """ checks if the group name exists """
        if DataBase.get_group_id(group_name) or DataBase.validate_user(group_name):
            return "Group name or username already exists"
        return "OK"

    @staticmethod
    def get_groups_chats(group, username):
        """ Gets all group chats """
        user_id = DataBase.get_user_id(username)
        group_id = DataBase.get_group_id(group)
        return DataBase.execute_query("""
            SELECT U.username AS sender_name, GM.msg, GM.file, GM.path, GM.time 
            FROM Groups_Messages GM
            JOIN Participants P ON GM.group_id = P.group_id 
            JOIN Users U ON U.id = GM.sender_id
            WHERE P.user_id = ? AND GM.group_id = ?
            ORDER BY GM.time""", (user_id, group_id), fetchall=True)

    @staticmethod
    def get_groups(username):
        """ Gets all groups of a user """
        user_id = DataBase.get_user_id(username)
        groups = DataBase.execute_query("""
            SELECT name FROM Groups G
            JOIN Participants P ON G.id = P.group_id
            WHERE P.user_id = ?""", (user_id,), fetchall=True)
        return [group[0] for group in groups] if groups else []

    @staticmethod
    def change_sound(path, file, user):
        """ changes user's sound """
        user_id = DataBase.get_user_id(user)
        DataBase.execute_query("UPDATE Sounds SET path = ?, file = ? WHERE id = ?", (path, file, user_id,))

    @staticmethod
    def add_participant(group, username):
        """ Adds a participant to a group """
        validation = DataBase.check_add_participant(group, username)
        if validation == "OK":
            group_id = DataBase.get_group_id(group)
            user_id = DataBase.get_user_id(username)
            DataBase.execute_query("INSERT INTO Participants (group_id, user_id) VALUES (?, ?)", (group_id, user_id))
        return validation

    @staticmethod
    def check_add_participant(group, username):
        """ Adds a participant to a group """
        user_email = DataBase.get_email(username).split("@")[1]
        if user_email not in DOMAINS:
            participants = DataBase.get_participants(group)
            for participant in participants:
                email = DataBase.get_email(participant).split("@")[1]
                if email not in DOMAINS:
                    if user_email != email:
                        return "Can't add a user from another company"
        return "OK"

    @staticmethod
    def remove_participant(group, username):
        """ Removes a participant from a group """
        group_id = DataBase.get_group_id(group)
        user_id = DataBase.get_user_id(username)
        DataBase.execute_query("DELETE FROM Participants WHERE group_id = ? AND user_id = ?", (group_id, user_id))

    @staticmethod
    def make_admin(group, username):
        """ Makes a participant an admin of a group """
        group_id = DataBase.get_group_id(group)
        admin_id = DataBase.get_user_id(username)
        DataBase.execute_query("INSERT INTO Admins (group_id, admin_id) VALUES (?, ?)", (group_id, admin_id))

    @staticmethod
    def get_admin_groups(username):
        """ Retrieves all groups where the user is an admin """
        user_id = DataBase.get_user_id(username)
        admin_groups = DataBase.execute_query("""
            SELECT G.name 
            FROM Groups G
            JOIN Admins A ON G.id = A.group_id
            WHERE A.admin_id = ?""", (user_id,), fetchall=True)
        return [group[0] for group in admin_groups] if admin_groups else []

    @staticmethod
    def get_participants(group):
        """Gets the participants of a group"""
        group_id = DataBase.get_group_id(group)
        query = """
        SELECT U.username
        FROM Participants P
        JOIN Users U ON P.user_id = U.id
        WHERE P.group_id = ?
        """
        results = DataBase.execute_query(query, (group_id,), fetchall=True)
        if results:
            return [row[0] for row in results]
        return []

    @staticmethod
    def is_admin(group, user):
        """Checks if the user is an admin of the given group"""
        group_id = DataBase.get_group_id(group)
        admin_id = DataBase.get_user_id(user)
        return bool(DataBase.execute_query("SELECT * FROM Admins WHERE group_id = ? AND admin_id = ?",
                                           (group_id, admin_id,), fetchone=True))

    @staticmethod
    def get_domains(username):
        """ gets the domains of the user's contacts """
        lst = []
        contacts = DataBase.get_contacts(username)
        for contact in contacts:
            domain = DataBase.get_email(contact).split("@")[1]
            if domain not in lst:
                lst.append(domain)
        return lst


class ClientThread(threading.Thread):
    """ Handles communication with a connected client """

    def __init__(self, client_socket):
        """ the constructor """
        super().__init__()
        self.client_socket = client_socket
        self.public_key, self.private_key = rsa.newkeys(512)
        self.aes_key = self.aes = self.num = self.username = None
        self.message_queue = []

    def handle_client(self):
        """ Handles client requests """
        self.client_socket.send(self.public_key.save_pkcs1(format='DER'))
        self.aes_key = rsa.decrypt(self.client_socket.recv(1024), self.private_key)
        self.aes = pyaes.AESModeOfOperationCTR(self.aes_key)
        while data := self.client_socket.recv(1024):
            decrypted_data = self.aes.decrypt(data).decode("utf-8").split("|")
            try:
                match decrypted_data[0]:
                    case 'o':
                        self.username = decrypted_data[1]
                        active_clients[self.username] = self
                    case 'u':
                        self.process_u(decrypted_data[1:])
                    case 'v':
                        self.process_v(decrypted_data[1:])
                    case 'c':
                        DataBase.change_password(decrypted_data[1], decrypted_data[2])
                    case 'a':
                        self.process_a(decrypted_data[1:])
                    case 'p':
                        DataBase.send_private(self.username, decrypted_data[2], decrypted_data[3], None, None,
                                              decrypted_data[4])
                    case 'e':
                        DataBase.change_volume(decrypted_data[1], self.username)
                        self.process_e(decrypted_data[2], decrypted_data[3])
                        active_clients.pop(self.username, None)
                    case 'f':
                        self.process_f(decrypted_data[1:])
                    case 'vg':
                        validate = DataBase.validate_group(decrypted_data[1])
                        self.client_socket.send(self.aes.encrypt(validate.encode("utf-8")))
                    case 'cg':
                        DataBase.create_group(decrypted_data[1:], self.username)
                    case 'ga':
                        add_participant_to_group(decrypted_data[1:])
                    case 'gr':
                        remove_participant_from_group(decrypted_data[1:])
                    case 'gm':
                        make_admin(decrypted_data[1:])
                    case 'gp':
                        data = DataBase.get_participants(decrypted_data[1])
                        data.remove(self.username)
                        response = {}
                        for participant in data:
                            response[participant] = DataBase.is_admin(decrypted_data[1], participant)
                        data = json.dumps(response)
                        self.client_socket.send(self.aes.encrypt(data.encode("utf-8")))
                    case 'g':
                        self.client_socket.send(self.aes.encrypt(json.dumps(DataBase.get_participants(decrypted_data[1])
                                                                            ).encode("utf-8")))
                    case _:
                        self.process_auth(decrypted_data)
            except Exception as e:
                print(f"Error processing command {decrypted_data}: {e}")

    def send_notification(self, message):
        """ Send a notification to the client """
        try:
            self.client_socket.send(self.aes.encrypt(message.encode("utf-8")))
        except Exception as e:
            print(f"Error sending notification: {e}")

    def process_e(self, b_path, s_path):
        """ receives background and saves id database """
        b_file = self.receive_file()
        s_file = self.receive_file()
        DataBase.change_background(b_path, b_file, self.username)
        DataBase.change_sound(s_path, s_file, self.username)

    def process_u(self, data):
        """ Handles user validation request """
        response = "OK" if DataBase.validate_user(data[0]) else "NOT OK"
        self.num = random.randint(100000, 99999999) if response == "OK" else None
        self.client_socket.send(self.aes.encrypt(response.encode("utf-8")))
        if response == "OK":
            self.change_password(data[0])

    def process_v(self, data):
        """ Handles verification request """
        response = "OK" if int(data[0]) == self.num else "NOT OK"
        self.num = None if response == "OK" else self.num
        self.client_socket.send(self.aes.encrypt(response.encode("utf-8")))

    def process_a(self, data):
        """ Handles add contact request """
        response = DataBase.add_contact(data[0], data[1]) if DataBase.validate_user(data[0]) else "No such user"
        self.client_socket.send(self.aes.encrypt(response.encode("utf-8")))
        if data[0] in active_clients and response == "OK":
            active_clients[data[0]].send_c(self.username)

    def send_c(self, name):
        """ sends a new contact to user live """
        self.client_socket.send(self.aes.encrypt(f"c|{name}".encode("utf-8")))

    def process_f(self, data):
        """ Handles file transfer request """
        receiver, timestamp, filename = data
        self.client_socket.send(self.aes.encrypt(filename.encode("utf-8")))
        file_data = self.receive_file()
        DataBase.send_private(self.username, receiver, None, file_data, filename, timestamp)

    def receive_file(self):
        """ receives a file """
        file_data = b''
        while True:
            chunk = self.aes.decrypt(self.client_socket.recv(1024))
            if chunk[-3:] == b"END":
                file_data += chunk[:-3]
                break
            else:
                file_data += chunk
                if file_data[-3:] == b"END":
                    file_data = file_data[:-3]
                    break
        return file_data

    def process_auth(self, data):
        """ Handles authentication requests (sign in/sign up) """
        if data[0] == "sign in":
            contacts = DataBase.get_contacts(data[1])
            response = {0: DataBase.sign_in(data[1], data[2])}
            for contact in contacts:
                response[contact] = DataBase.get_chat(contact, data[1])
            response["s"] = ""
            groups = DataBase.get_groups(data[1])
            for group in groups:
                response[group] = DataBase.get_groups_chats(group, data[1])
        else:
            response = {0: DataBase.sign_up(data[1], data[2], data[3])}
        if response[0] == "OK":
            if data[1] in active_clients:
                response[0] = "already connected"
        response.update({"volume": DataBase.get_volume(data[1]), "background": DataBase.get_background(data[1]),
                         "sound": DataBase.get_sound(data[1]), "admin": DataBase.get_admin_groups(data[1])})
        response = encode_file_content1(response)
        compressed_response = zlib.compress(json.dumps(response).encode("utf-8"))
        encrypted_response = self.aes.encrypt(compressed_response)
        self.send_data_in_chunks(encrypted_response)

    def send_data_in_chunks(self, chat):
        """ sends chat history in chunks """
        start = 0
        chat += self.aes.encrypt(b"END")
        while start < len(chat):
            end = start + 16384
            self.client_socket.send(chat[start:end])
            start = end

    def change_password(self, username):
        """ Sends a password change email """
        email = DataBase.get_email(username)
        body = f"Do not forget your password anymore you kuku!!! Your verification code is: {self.num}"
        message = MIMEMultipart()
        message['From'] = SERVER_EMAIL
        message['To'] = email
        message['Subject'] = "Change Password"
        message.attach(MIMEText(body, 'plain'))
        with smtplib.SMTP('smtp.mail.yahoo.com', 587) as server:
            server.starttls()
            server.login(SERVER_EMAIL, PASS)
            server.sendmail(SERVER_EMAIL, email, message.as_string())

    def send_message(self, sender, message, file, filename, time, group=""):
        """ Sends a message to the client """
        try:
            if filename:
                metadata = f"{sender}|{time}|{filename}|{group}|{'f'}"
                self.client_socket.send(self.aes.encrypt(metadata.encode("utf-8")))
                self.client_socket.sendall(self.aes.encrypt(file))
                self.client_socket.send(self.aes.encrypt(b"END"))
            else:
                self.client_socket.send(self.aes.encrypt(f"{sender}|{message}|{time}|{group}".encode("utf-8")))
        except Exception as e:
            print(f"Error sending message: {e}")

    def send_group(self, name, chat):
        self.client_socket.send(self.aes.encrypt(f"g|{name}|{chat}".encode("utf-8")))

    def run(self):
        """ Runs the client thread """
        try:
            self.handle_client()
        except Exception as e:
            print(f"Error handling client: {e}")
        finally:
            active_clients.pop(self.username, None)
            self.client_socket.close()


def check_rate_limit(ip):
    """Check the number of requests from an IP within a certain time frame."""
    if ip in blacklist:
        if time.time() - blacklist[ip] < BLACKLIST_TIMEOUT:
            return False
        else:
            del blacklist[ip]

    if request_counts[ip] > RATE_LIMIT:
        blacklist[ip] = time.time()
        del request_counts[ip]
        return False

    request_counts[ip] += 1
    return True


def reset_request_counts():
    """Reset request counts every minute."""
    while True:
        time.sleep(60)
        request_counts.clear()


def handle_client_connection(client_socket, addr):
    print(f"Accepted connection from {addr}")
    try:
        while True:
            message = client_socket.recv(1024)
            if not message:
                break
            print(f"Received message from {addr}: {message.decode('utf-8')}")
            client_socket.sendall(b'ACK')
    except socket.error as e:
        print(f"Socket error: {e}")
    finally:
        client_socket.close()
        print(f"Connection with {addr} closed")


def setup_server_socket():
    """ sets up a socket """
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((IP, PORT))
    server_socket.listen()
    print(f"Server listening on port {PORT}")
    return server_socket


def main():
    """ the main function """
    server_socket = setup_server_socket()
    reset_thread = threading.Thread(target=reset_request_counts)
    reset_thread.daemon = True
    reset_thread.start()
    while True:
        client_socket, addr = server_socket.accept()
        ip = addr[0]
        if check_rate_limit(ip):
            ClientThread(client_socket).start()
        else:
            print(f"Connection from {ip} rejected due to rate limiting")
            client_socket.close()


def encode_file_content1(data):
    """ faze one of encoding with base64 for files """
    for key, value in data.items():
        if isinstance(value, list):
            for index, item in enumerate(value):
                if isinstance(item, tuple) and isinstance(item[2], bytes):
                    data[key][index] = encode_file_content2(item)
    data["background"] = encode_file_content2(data["background"])
    data["sound"] = encode_file_content2(data["sound"])
    return data


def encode_file_content2(data):
    """ faze two of encoding with base64 for files """
    encoded_data = []
    for item in data:
        if isinstance(item, bytes):
            encoded_data.append(base64.b64encode(item).decode("utf-8"))
        else:
            encoded_data.append(item)
    return tuple(encoded_data)


def add_participant_to_group(data):
    """ adds a user to a given group """
    group, username, admin = data
    response = DataBase.check_add_participant(group, username)
    if response == "OK":
        DataBase.send_private(admin, group, f"{admin} added {username}", None, None,
                              datetime.now().strftime("%Y-%m-%d %H:%M"))
        DataBase.add_participant(group, username)
        if username in active_clients:
            chat = DataBase.get_groups_chats(group, username)
            active_clients[username].send_group(group, chat)
    active_clients[admin].send_notification(response)


def remove_participant_from_group(data):
    """ removes a participant from a given group """
    group, username, admin = data
    DataBase.remove_participant(group, username)
    if username in active_clients:
        active_clients[username].send_notification(f"You|have|been|removed|from|{group}")
    DataBase.send_private(admin, group, f"{admin} removed {username}", None, None,
                          datetime.now().strftime("%Y-%m-%d %H:%M"))


def make_admin(data):
    """ makes participant an admin in a given group """
    group, username, admin = data
    DataBase.make_admin(group, username)
    DataBase.send_private(admin, group, f"{admin} made {username} admin", None, None,
                          datetime.now().strftime("%Y-%m-%d %H:%M"))


if __name__ == "__main__":
    main()
