import socket
import time
import customtkinter as ctk
from PIL import Image, ImageTk
import rsa
import pyaes
import os
from tkinter import messagebox, filedialog
from functools import partial
import tkinter
import json
from datetime import datetime
import threading
import pygame
import tkinter as tk
import sys
from os.path import expanduser
import base64
import zlib
import ast
import queue

PORT = 8200
IP = "127.0.0.1"
COLOR_BACKGROUND = "#2B2B2B"
COLOR_BUTTON_ACTIVE = "#80AAFF"
COLOR_BUTTON_INACTIVE = "#FFFFFF"
KNOWN_EMAILS = ["gmail.com", "yahoo.com"]
USER = None
CHATS = {}
SOUND = ""
SOUND_FILE = b""
VOLUME = None
BACKGROUND = ""
GROUPS = []
CONTACTS = []
BACKGROUND_FILE = b""
ADMIN = []
QUEUE = queue.Queue()


class LimitedEntry(ctk.CTkEntry):
    """ class for entry widgets """

    def __init__(self, master=None, max_chars=30, paste_enabled=True, **kwargs):
        """ constructor """
        self.max_chars = max_chars
        self.paste_enabled = paste_enabled
        super().__init__(master, **kwargs)
        validate_cmd = (self.register(self.validate_input), '%S', '%P')
        self.configure(validate='key', validatecommand=validate_cmd)
        if self.paste_enabled:
            self.bind("<Control-v>", self.handle_paste)
        else:
            self.unbind("<Control-v>")

    def validate_input(self, char, current_value):
        """ validates input """
        if len(current_value) >= self.max_chars:
            return False
        return True

    def handle_paste(self, event):
        """ validates input in scenario of ctrl v """
        try:
            text = self.clipboard_get()
            current_value = self.get()
            remaining_space = self.max_chars - len(current_value)
            if len(text) > remaining_space:
                text = text[:remaining_space]
                self.bell()
            self.insert(tk.INSERT, text)
            return 'break'
        except Exception as e:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            print(f"Error receiving message: {e}, line {exc_traceback.tb_lineno}")
            return 'break'


class ReceiveMessagesThread(threading.Thread):
    """ thread waiting for messages/responses from server """

    def __init__(self, client_socket, aes, message_callback1, message_callback2, get_volume_callback, main):
        """ constructor """
        super().__init__()
        self.main = main
        self.client_socket = client_socket
        self.aes = aes
        self.message_callback1 = message_callback1
        self.message_callback2 = message_callback2
        self.get_volume_callback = get_volume_callback
        self.running = True
        self.daemon = True

    def run(self):
        global CONTACTS, GROUPS, CHATS, QUEUE
        """ the thread """
        pygame.mixer.init()
        pygame.mixer.music.load(SOUND)
        self.client_socket.settimeout(1.0)
        while self.running:
            try:
                encrypted_message = self.client_socket.recv(1024)
                if not encrypted_message:
                    break
                message = self.aes.decrypt(encrypted_message).decode("utf-8")
                lst = message.split("|")
                match len(lst):
                    case 1:
                        if lst[0] == "OK" or lst[0] == "Can't add a user from another company":
                            QUEUE.put(lst[0])
                        else:
                            self.message_callback2(lst[0])
                    case 2:
                        CONTACTS.append(lst[1])
                        CHATS[lst[1]] = []
                        self.main.show_content("Home")
                        self.main.show_floating_label(f"{lst[1]} added you as a contact")
                    case 3:
                        GROUPS.append(lst[1])
                        CHATS[lst[1]] = ast.literal_eval(lst[2])
                        self.main.show_content("Home")
                        self.main.show_floating_label(f"you were added to {lst[1]}")
                    case 4:
                        self.message_callback1([lst[0], lst[1], None, None, lst[2]], lst[3])
                        current_volume = self.get_volume_callback()
                        pygame.mixer.music.set_volume(current_volume)
                        pygame.mixer.music.play()
                    case 5:
                        self.receive_file(lst[:-1])
                        current_volume = self.get_volume_callback()
                        pygame.mixer.music.set_volume(current_volume)
                        pygame.mixer.music.play()
                    case _:
                        if lst[4] != "admin":
                            GROUPS.remove(lst[-1])
                            del CHATS[lst[-1]]
                        self.main.show_content("Home")
                        self.main.show_floating_label(" ".join(lst))
            except socket.timeout:
                continue
            except Exception as e:
                exc_type, exc_value, exc_traceback = sys.exc_info()
                print(f"Error sending closing message to server: {e}, line {exc_traceback.tb_lineno}")
                self.main.response_label.configure(text="Server shut down, close the app and try again", fg_color="red")
                break
        pygame.mixer.quit()

    def receive_file(self, data):
        """Receives a file live"""
        sender, timestamp, file_name, group = data
        file_name = os.path.basename(file_name)
        done = False
        file_data = b''
        while not done:
            file_data += self.aes.decrypt(self.client_socket.recv(1024))
            if file_data[-3:] == b"END":
                done = True
        file_data = file_data[:-3]
        desktop_path = os.path.join(expanduser("~"), "Desktop")
        file_path = os.path.join(desktop_path, file_name)
        with open(file_path, 'wb') as file:
            file.write(file_data)
        self.message_callback1([sender, None, file_data, file_path, timestamp], group)

    def stop(self):
        """ stops the thread """
        self.running = False


class Application(ctk.CTk):
    """ the screen """

    def __init__(self):
        """ constructor """
        super().__init__()
        self.protocol("WM_DELETE_WINDOW", self.on_close)
        self.title("Secure Chat")
        self.geometry("1200x800")
        self.client_socket, self.public_key = create_client_socket_and_get_public_key()
        self.aes_key = os.urandom(16)
        self.encrypt_and_send_aes_key()
        self.aes = pyaes.AESModeOfOperationCTR(self.aes_key)
        self.login_window = LoginWindow(self, self.client_socket, self.show_main_frame, self.aes)
        self.login_window.pack(fill="both", expand=True)
        self.main_frame = None
        self.receive_thread = None
        self.change_password_window = None

    def on_close(self):
        """ logic after closing the app to change the volume """
        try:
            data = f"e|{VOLUME}|{BACKGROUND}|{SOUND}"
            self.client_socket.send(self.aes.encrypt(data.encode("utf-8")))
            background_data = get_file(BACKGROUND)
            self.send_file(background_data)
            time.sleep(1)
            sound_data = get_file(SOUND)
            self.send_file(sound_data)
        except Exception as e:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            print(f"Error sending closing message to server: {e}, line {exc_traceback.tb_lineno}")
            self.main_frame.response_label.configure(text="Server shut down, close the app and try again",
                                                     fg_color="red")
            return
        self.client_socket.close()
        self.destroy()

    def send_file(self, file_data):
        """ Sends a file to the server """
        chunk_size = 1024
        for i in range(0, len(file_data), chunk_size):
            chunk = file_data[i:i + chunk_size]
            self.client_socket.send(self.aes.encrypt(chunk))
        self.client_socket.send(self.aes.encrypt(b"END"))

    def encrypt_and_send_aes_key(self):
        """ sends the encryption key """
        encrypted_aes_key = rsa.encrypt(self.aes_key, self.public_key)
        self.client_socket.send(encrypted_aes_key)

    def show_main_frame(self):
        """ creates a new main frame """
        if self.change_password_window:
            self.change_password_window.close_window()
        self.login_window.pack_forget()
        self.main_frame = MainFrame(self, self.client_socket, self.aes)
        self.main_frame.receive_thread = ReceiveMessagesThread(self.client_socket, self.aes,
                                                               self.main_frame.display_message,
                                                               self.main_frame.send_file2, get_current_volume,
                                                               self.main_frame)
        self.main_frame.receive_thread.start()
        self.main_frame.pack(fill="both", expand=True)


class LoginWindow(ctk.CTkFrame):
    """ sign in/up screen """

    def __init__(self, parent, client_socket, on_login_success, aes):
        """ constructor """
        super().__init__(parent)
        self.client_socket = client_socket
        self.on_login_success = on_login_success
        self.aes = aes
        self.configure_gui_elements()
        self.pack(fill="both", expand=True)
        self.parent = parent
        self.parent.protocol("WM_DELETE_WINDOW", self.on_parent_close)
        self.show_password = False

    def configure_gui_elements(self):
        """ gui """
        ctk.set_appearance_mode("Dark")
        self.master.resizable(True, True)
        self.load_background_image("assets/background1.webp")
        btn_width = 120
        btn_height = 40
        self.sign_in_button = ctk.CTkButton(self, text="Sign In", command=self.sign_in, width=btn_width,
                                            height=btn_height, fg_color="cyan", text_color="black",
                                            font=("papyrus", 20))
        self.sign_in_button.place(relx=0.4, rely=0.4, anchor=ctk.CENTER)
        self.sign_up_button = ctk.CTkButton(self, text="Sign Up", command=self.sign_up, width=btn_width,
                                            height=btn_height, fg_color="cyan", text_color="black",
                                            font=("papyrus", 20))
        self.sign_up_button.place(relx=0.6, rely=0.4, anchor=ctk.CENTER)
        self.enter_button = ctk.CTkButton(self, text="Enter", command=self.pass_action, width=btn_width,
                                          height=btn_height, fg_color="cyan", text_color="black", font=("papyrus", 20))
        self.username_entry = LimitedEntry(self, placeholder_text="Username", fg_color="black")
        self.password_entry = LimitedEntry(self, placeholder_text="Password", show="*", fg_color="black",
                                           paste_enabled=False)
        self.confirm_password_entry = None
        self.entries_placed = False
        self.welcome_label = ctk.CTkLabel(self, text="Welcome to Secure Chat", text_color="black", fg_color="cyan",
                                          font=("papyrus", 40))
        self.welcome_label.place(relx=0.5, rely=0.1, anchor=ctk.CENTER)
        self.response_label = ctk.CTkLabel(self, text="", text_color="black", fg_color="transparent",
                                           font=("papyrus", 20))
        self.response_label.place(relx=0.5, rely=0.7, anchor=ctk.CENTER)
        self.toggle_pw_btn = ctk.CTkButton(self, text="Show", command=self.toggle_password_visibility,
                                           width=60, height=25, fg_color="cyan", text_color="black")
        self.toggle_pw_btn.place(relx=0.8, rely=0.55, anchor=ctk.CENTER)
        self.forgot_password_button = ctk.CTkButton(self, text="Forgot Password",
                                                    command=self.open_change_password_window,
                                                    width=btn_width, height=btn_height, fg_color="cyan",
                                                    text_color="black", font=("papyrus", 20))

        self.email_entry = None

    def on_parent_close(self):
        """ logic after closing the parent (main application) window """
        if self.parent.change_password_window:
            self.parent.change_password_window.close_window()
        self.parent.on_close()

    def open_change_password_window(self):
        self.parent.change_password_window = ChangePassword(self.client_socket, self.aes, self.parent)

    def toggle_password_visibility(self):
        """ widget adjustments in the first screen """
        if self.show_password:
            self.password_entry.configure(show="*")
            self.toggle_pw_btn.configure(text="Show")
            if self.confirm_password_entry is not None:
                self.confirm_password_entry.configure(show="*")
        else:
            self.password_entry.configure(show="")
            self.toggle_pw_btn.configure(text="Hide")
            if self.confirm_password_entry is not None:
                self.confirm_password_entry.configure(show="")
        self.show_password = not self.show_password

    def pass_action(self):
        global USER, CHATS, VOLUME, BACKGROUND, GROUPS, CONTACTS, BACKGROUND_FILE, SOUND_FILE, SOUND, ADMIN
        """ checks and validations, response from server after sending a final statement """
        email = None
        username = self.username_entry.get()
        if username:
            password = self.password_entry.get()
            if self.confirm_password_entry and password != self.confirm_password_entry.get():
                self.response_label.configure(text="passwords do not match, try again", fg_color="red")
                return
            elif password == "":
                self.response_label.configure(text="password can't be None, try again", fg_color="red")
                return
            if self.email_entry:
                if self.email_entry.get() != "":
                    email = self.email_entry.get()
                    parts = email.split('@')
                    if len(parts) != 2:
                        self.response_label.configure(text="invalid email", fg_color="red")
                        return
                else:
                    self.response_label.configure(text="invalid email", fg_color="red")
                    return
            action = "sign up" if self.confirm_password_entry else "sign in"
            data = f"{action}|{username}|{password}|{email}"
            encrypted_data = self.aes.encrypt(data.encode("utf-8"))
            try:
                self.client_socket.send(encrypted_data)
                response = self.receive_data_in_chunks()
                response = json.loads(response.decode("utf-8"))
            except Exception as e:
                exc_type, exc_value, exc_traceback = sys.exc_info()
                print(f"Error sending closing message to server: {e}, line {exc_traceback.tb_lineno}")
                self.response_label.configure(text="Server shut down, close the app and try again", fg_color="red")
                return
            if response['0'] == "OK":
                USER = username
                ADMIN = response["admin"]
                VOLUME = response["volume"]
                BACKGROUND = response["background"][0]
                BACKGROUND_FILE = base64.b64decode(response["background"][1].encode("utf-8"))
                SOUND = response["sound"][0]
                SOUND_FILE = base64.b64decode(response["sound"][1].encode("utf-8"))
                if not os.path.exists(SOUND):
                    desktop_path = os.path.join(expanduser("~"), "Desktop")
                    SOUND = os.path.join(desktop_path, os.path.basename(SOUND))
                    with open(SOUND, 'wb') as f:
                        f.write(SOUND_FILE)
                del response['0']
                del response["admin"]
                del response["volume"]
                del response["background"]
                del response["sound"]
                if 's' in response.keys():
                    is_group_section = False
                    for key in response.keys():
                        if key == 's':
                            is_group_section = True
                            continue
                        if is_group_section:
                            GROUPS.append(key)
                        else:
                            CONTACTS.append(key)
                    del response['s']
                CHATS = decode_file_content1(response)
                self.username_entry.delete(0, ctk.END)
                self.password_entry.delete(0, ctk.END)
                if self.confirm_password_entry:
                    self.confirm_password_entry.delete(0, ctk.END)
                    self.email_entry.delete(0, ctk.END)
                if self.response_label:
                    self.response_label.configure(text="", fg_color="transparent")
                if self.forgot_password_button:
                    self.forgot_password_button.place_forget()
                self.on_login_success()
            else:
                self.response_label.configure(text=response["0"], fg_color="red")
                if response["0"] == "username or password wrong":
                    self.forgot_password_button.place(relx=0.5, rely=0.8, anchor=ctk.CENTER)
        else:
            self.response_label.configure(text="please enter a username", fg_color="red")

    def receive_data_in_chunks(self):
        """ receives chat history in chunks """
        self.client_socket.settimeout(10)
        file_data = b""
        while True:
            chunk = self.aes.decrypt(self.client_socket.recv(16384))
            if chunk[-3:] == b"END":
                file_data += chunk[:-3]
                break
            else:
                file_data += chunk
                if file_data[-3:] == b"END":
                    file_data = file_data[:-3]
                    break
        return zlib.decompress(file_data)

    def resize_background_image(self, event):
        """ resize background to the screens current width """
        new_width = self.winfo_width()
        new_height = self.winfo_height()
        resized_img = self.original_img.resize((new_width, new_height), Image.LANCZOS)
        self.photo = ImageTk.PhotoImage(resized_img)
        self.label.configure(image=self.photo)
        self.label.image = self.photo

    def load_background_image(self, image_path):
        """ load background """
        self.original_img = Image.open(image_path)
        self.photo = ImageTk.PhotoImage(self.original_img)
        self.label = ctk.CTkLabel(self, image=self.photo, text="")
        self.label.image = self.photo
        self.label.place(relwidth=1, relheight=1)
        self.bind("<Configure>", self.resize_background_image)

    def sign_in(self):
        """ adjustments after pressing sign in """
        self.place_entries()
        self.enter_button.place(relx=0.5, rely=0.9, anchor=ctk.CENTER)
        if self.confirm_password_entry and self.email_entry:
            self.confirm_password_entry.destroy()
            self.email_entry.destroy()
            self.confirm_password_entry = None
            self.email_entry = None

    def sign_up(self):
        """ adjustments after pressing sign up """
        self.place_entries()
        self.enter_button.place(relx=0.5, rely=0.9, anchor=ctk.CENTER)
        if not self.confirm_password_entry and not self.email_entry:
            self.confirm_password_entry = LimitedEntry(self, placeholder_text="Confirm Password", show="*",
                                                       fg_color="black", paste_enabled=False)
            self.confirm_password_entry.place(relx=0.5, rely=0.6, anchor=ctk.CENTER)
            self.email_entry = LimitedEntry(self, placeholder_text="Email Account", fg_color="black")
            self.email_entry.place(relx=0.5, rely=0.65, anchor=ctk.CENTER)

    def place_entries(self):
        """ first interaction with the sign in/up buttons """
        if not self.entries_placed:
            self.username_entry.place(relx=0.5, rely=0.5, anchor=ctk.CENTER)
            self.password_entry.place(relx=0.5, rely=0.55, anchor=ctk.CENTER)
            self.entries_placed = True


class ChangePassword:
    """ change password window """

    def __init__(self, client_socket, aes, parent):
        """ constructor """
        self.show_password = False
        self.app = ctk.CTk()
        self.client_socket = client_socket
        self.aes = aes
        self.parent = parent
        self.parent.change_password_window = self
        self.app.title("Change Password")
        self.app.geometry("800x600")
        self.lbl = ctk.CTkLabel(self.app, text="Change your password", text_color="black", fg_color="cyan",
                                font=("papyrus", 40))
        self.lbl.place(relx=0.5, rely=0.1, anchor=ctk.CENTER)
        self.entry = LimitedEntry(self.app, placeholder_text="Username")
        self.entry.place(relx=0.5, rely=0.5, anchor=ctk.CENTER)
        self.enter = ctk.CTkButton(self.app, text="Enter", command=partial(self.change_password_1),
                                   width=60, height=25, fg_color="cyan", text_color="black")
        self.enter.place(relx=0.5, rely=0.6, anchor=ctk.CENTER)
        self.app.protocol("WM_DELETE_WINDOW", self.on_close)
        self.response_label = ctk.CTkLabel(self.app, text="", text_color="black", fg_color="transparent",
                                           font=("papyrus", 20))
        self.response_label.place(relx=0.5, rely=0.7, anchor=ctk.CENTER)
        self.app.mainloop()

    def on_close(self):
        """ logic after closing the app """
        self.parent.change_password_window = None
        self.app.destroy()

    def close_window(self):
        """ Close the window programmatically """
        self.parent.change_password_window = None
        self.app.destroy()

    def change_password_1(self):
        """ validation and response """
        username = self.entry.get()
        if not username:
            self.lbl.configure(text="Please enter a username")
            return
        data = f"u|{username}"
        encrypted_username = self.aes.encrypt(data.encode("utf-8"))
        try:
            self.client_socket.send(encrypted_username)
            encrypted_response = self.client_socket.recv(1024)
        except Exception as e:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            print(f"Error sending closing message to server: {e}, line {exc_traceback.tb_lineno}")
            self.response_label.configure(text="Server shut down, close the app and try again", fg_color="red")
            return
        response = self.aes.decrypt(encrypted_response).decode("utf-8")
        if response == "OK":
            self.entry.delete(0, ctk.END)
            validate_cmd = self.app.register(validate_number)
            self.entry.configure(validate="key", validatecommand=(validate_cmd, '%S'))
            self.enter.configure(command=partial(self.verify, username))
            self.lbl.configure(text="Wait for an email with the pass code")
        else:
            self.lbl.configure(text="Wrong username")

    def verify(self, username):
        """ verifies with the server whether the code is correct """
        num = self.entry.get()
        if not num:
            self.lbl.configure(text="Please enter a number")
        else:
            data = f"v|{num}"
            encrypted_num = self.aes.encrypt(data.encode("utf-8"))
            try:
                self.client_socket.send(encrypted_num)
                encrypted_response = self.client_socket.recv(1024)
            except Exception as e:
                exc_type, exc_value, exc_traceback = sys.exc_info()
                print(f"Error sending closing message to server: {e}, line {exc_traceback.tb_lineno}")
                self.response_label.configure(text="Server shut down, close the app and try again", fg_color="red")
                return
            response = self.aes.decrypt(encrypted_response).decode("utf-8")
            if response == "OK":
                self.entry.delete(0, ctk.END)
                self.lbl.configure(text="Write your new password")
                self.enter.configure(command=partial(self.final_faze, username))
                self.entry.configure(validate="none", validatecommand=None)
                self.entry.configure(show="*")
                self.toggle_pw_btn = ctk.CTkButton(self.app, text="Show", command=self.toggle_password_visibility,
                                                   width=60, height=25, fg_color="cyan", text_color="black")
                self.toggle_pw_btn.place(relx=0.8, rely=0.55, anchor=ctk.CENTER)
            else:
                self.lbl.configure(text="wrong verification code")

    def toggle_password_visibility(self):
        """ widget adjustments in the first screen """
        if self.show_password:
            self.entry.configure(show="*")
            self.toggle_pw_btn.configure(text="Show")
        else:
            self.entry.configure(show="")
            self.toggle_pw_btn.configure(text="Hide")
        self.show_password = not self.show_password

    def final_faze(self, username):
        """ change password """
        if self.entry.get() != "":
            data = f"c|{username}|{self.entry.get()}"
            encrypted_pass = self.aes.encrypt(data.encode("utf-8"))
            try:
                self.client_socket.send(encrypted_pass)
            except Exception as e:
                exc_type, exc_value, exc_traceback = sys.exc_info()
                print(f"Error sending closing message to server: {e}, line {exc_traceback.tb_lineno}")
                self.response_label.configure(text="Server shut down, close the app and try again", fg_color="red")
                return
            self.lbl.configure(text="you can close this window and sign in\n if you do not like your new password, "
                                    "you can change it here again")
        else:
            self.lbl.configure(text="a password cannot be empty")


class MainFrame(ctk.CTkFrame):
    """ The main application frame. """

    def __init__(self, parent, client_socket, aes):
        global BACKGROUND
        """ constructor """
        super().__init__(parent)
        self.check = None
        self.open_file_btn = None
        self.client_socket = client_socket
        self.aes = aes
        self.sidebar = ctk.CTkFrame(self, width=200, corner_radius=0, fg_color="#3377FF")
        self.sidebar.pack(side='left', fill='y')
        self.content_area = ctk.CTkFrame(self, fg_color=COLOR_BACKGROUND)
        self.content_area.pack(side='right', expand=True, fill='both')
        if not os.path.exists(BACKGROUND):
            desktop_path = os.path.join(expanduser("~"), "Desktop")
            BACKGROUND = os.path.join(desktop_path, os.path.basename(BACKGROUND))
            with open(BACKGROUND, 'wb') as f:
                f.write(BACKGROUND_FILE)
        self.load_background_image(BACKGROUND)
        menu_buttons = [
            ("Home", "assets/home.webp", "Home"),
            ("Contacts", "assets/user.webp", "Contacts"),
            ("Settings", "assets/settings.webp", "Settings"),
            ("Change Background", "assets/change_background.webp", "Change Background"),
            ("Help", "assets/help.webp", "Help"),
            ("Logout", "assets/logout.jpg", "Logout"),
            ("Manage Groups", "assets/groups.png", "Manage Groups")
        ]
        for text, icon, content in menu_buttons:
            self.create_menu_button(text, icon, partial(self.show_content, content))
        self.group_management_window = None
        self.response_label = ctk.CTkLabel(self.content_area, text="", text_color="black", fg_color="transparent",
                                           font=("papyrus", 20))
        self.response_label.place(relx=0.5, rely=0.2, anchor=ctk.CENTER)
        self.show_content("Home")
        self.receive_thread = None
        self.previous_contact = None
        self.client_socket.send(self.aes.encrypt(f"o|{USER}".encode("utf-8")))

    def show_floating_label(self, message):
        """ Display a floating label with the given message """
        self.floating_label = ctk.CTkLabel(self.content_area, text=message, font=("Helvetica", 12), fg_color="red")
        self.floating_label.place(relx=0.5, rely=0.1, anchor='center')
        threading.Timer(3.0, self.hide_floating_label).start()

    def hide_floating_label(self):
        """ Hide the floating label """
        self.floating_label.place_forget()

    def display_message(self, lst, group_name=None):
        """ Display a received message """
        pygame.mixer.music.play()
        sender, msg, file, path, timestamp = lst
        if group_name:
            is_sender = self.var and self.var.get() == group_name
        else:
            is_sender = self.var and self.var.get() == sender
        if is_sender:
            if path:
                self.create_clickable_link(path, timestamp, False, f"{sender}: ")
                self.text_widget.config(height=25, width=85)
            else:
                self.text_widget.config(state="normal")
                self.text_widget.insert(ctk.END, f"{sender}: {msg}\n{timestamp}\n")
                self.text_widget.config(state="disabled")
                self.text_widget.yview_moveto(1.0)
        if group_name:
            CHATS[group_name].append(tuple(lst))
            message = group_name
        else:
            CHATS[sender].append(tuple(lst))
            message = sender
        self.show_floating_label(f"message received from {message}")

    def create_option_menu(self, lst):
        """ Create an option menu widget """
        self.var = tkinter.StringVar(value=lst[0])
        self.option_menu = tkinter.OptionMenu(self.content_area, self.var, *lst)
        self.option_menu.config(width=20)
        self.option_menu.pack(side='top', padx=20, pady=10, fill='x')
        self.var.trace('w', self.on_contact_selected)

    def on_contact_selected(self, *args):
        """ Change the chat display when a contact is selected """
        selected_contact = self.var.get()
        if selected_contact != "Choose who to write to":
            if selected_contact != self.previous_contact:
                self.previous_contact = selected_contact
                chat = CHATS[selected_contact]
                self.text_widget.config(state="normal")
                self.text_widget.delete('1.0', ctk.END)
                self.text_widget.config(state="disabled")
                for widget in self.text_widget.winfo_children():
                    widget.destroy()
                for message in chat:
                    user, msg, file, path, timestamp = message
                    user_display = "You" if user == USER else user
                    if msg:
                        self.text_widget.config(state="normal")
                        self.text_widget.insert(ctk.END, f"{user_display}: {msg}\n{timestamp}\n")
                        self.text_widget.config(state="disabled")
                        self.text_widget.yview_moveto(1.0)
                    else:
                        if not os.path.exists(path):
                            desktop_path = os.path.join(expanduser("~"), "Desktop")
                            path = os.path.join(desktop_path, os.path.basename(path))
                            with open(path, 'wb') as f:
                                f.write(file)
                        self.create_clickable_link(path, timestamp, False, f"{user_display}: ")
        else:
            self.previous_contact = selected_contact
            for widget in self.text_widget.winfo_children():
                widget.destroy()
            self.text_widget.config(state="normal")
            self.text_widget.delete('1.0', ctk.END)
            self.text_widget.config(state="disabled")

    def create_menu_button(self, text, icon_path, command, where=None):
        """ Create a menu button with an icon """
        where, x, y = (self.sidebar, 70, 70) if where is None else (self.content_area, 50, 50)
        img = Image.open(icon_path).resize((x, y))
        photo = ImageTk.PhotoImage(img)
        btn = ctk.CTkButton(where, text=text, image=photo, compound="left",
                            fg_color=COLOR_BUTTON_INACTIVE, hover_color=COLOR_BUTTON_ACTIVE,
                            command=command, text_color="black", height=y)
        if x == 50:
            btn.place(relx=0.1, rely=0.78)
        else:
            btn.pack(padx=10, pady=20)
        btn.image = photo

    def logout(self):
        global BACKGROUND, VOLUME, CHATS, USER, GROUPS, CONTACTS, BACKGROUND_FILE
        """ Handle user logout """
        try:
            data = f"e|{VOLUME}|{BACKGROUND}|{SOUND}"
            self.client_socket.send(self.aes.encrypt(data.encode("utf-8")))
            background_data = get_file(BACKGROUND)
            self.send_file(background_data)
            time.sleep(1)
            sound_data = get_file(SOUND)
            self.send_file(sound_data)
        except Exception as e:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            print(f"Error sending closing message to server: {e}, line {exc_traceback.tb_lineno}")
            self.response_label.configure(text="Server shut down, close the app and try again", fg_color="red")
            return
        self.receive_thread.stop()
        self.receive_thread.join()
        self.pack_forget()
        VOLUME = None
        BACKGROUND = ""
        CHATS = {}
        CONTACTS = []
        USER = None
        GROUPS = []
        BACKGROUND_FILE = ""
        self.master.login_window.pack(fill="both", expand=True)

    def send_file(self, file_data):
        """ Sends a file to the server """
        chunk_size = 1024
        for i in range(0, len(file_data), chunk_size):
            chunk = file_data[i:i + chunk_size]
            self.client_socket.send(self.aes.encrypt(chunk))
        self.client_socket.send(self.aes.encrypt(b"END"))

    def show_content(self, content):
        """ Display the appropriate content based on the selected menu item """
        self.clear_content_area()
        self.previous_contact = None
        match content:
            case "Change Background":
                open_file_btn = ctk.CTkButton(self.content_area, text="Open Image",
                                              command=partial(self.open_file_dialog, (
                                              "Image files", "*.jpg *.jpeg *.png *.gif *.bmp *.tiff *.tif *.webp"),
                                                              "Open Image"))
                open_file_btn.place(relx=0.5, rely=0.1, anchor=ctk.CENTER)
            case "Settings":
                self.setup_settings()
            case "Contacts":
                self.setup_contacts(content)
                self.setup_groups()
            case "Home":
                self.setup_home()
            case "Help":
                help_label = ctk.CTkLabel(self.content_area, text="Home is where the messages are, you can choose who\n"
                                                                  "to write to and send him/them texts and files\n"
                                                                  "Contacts is where you can add your co workers, "
                                                                  "managers\nand clients, you can also create groups "
                                                                  "and see their participants by clicking them\nThe "
                                                                  "settings menu is where you can adjust the volume\nof"
                                                                  " notifications and change the sound\nIn change "
                                                                  "background you can change your background for the "
                                                                  "app\nThis is help:)\nIf you don't want to close the "
                                                                  "application, just logout!\nIn manage groups you can "
                                                                  "add/remove, or make other\nparticipants admins in "
                                                                  "groups you are admin in", font=("papyrus", 35))
                help_label.place(relx=0.5, rely=0.5, anchor=ctk.CENTER)
            case "Logout":
                self.logout()
            case "Manage Groups":
                self.open_group_management()

    def setup_settings(self):
        """ set up the settings page """
        pygame.mixer.init()
        self.sound = pygame.mixer.Sound(SOUND)
        self.volume_frame = ctk.CTkFrame(self.content_area, height=180)
        self.volume_frame.pack(expand=True)
        volume_control_size = 40
        self.volume_label = ctk.CTkLabel(self.volume_frame, text="Volume:")
        self.volume_label.place(relx=0.5, anchor=ctk.CENTER, rely=0.3)
        self.volume_slider = tk.Scale(self.volume_frame, from_=0, to=1, resolution=0.01, orient=tk.HORIZONTAL,
                                      command=self.change_volume, length=volume_control_size * 5)
        self.volume_slider.place(relx=0.5, anchor=ctk.CENTER, rely=0.5)
        self.volume_slider.bind("<Motion>", self.update_volume)
        self.volume_value_label = ctk.CTkLabel(self.volume_frame, text=str(VOLUME))
        self.volume_value_label.place(relx=0.5, anchor=ctk.CENTER, rely=0.7)
        self.play_button = ctk.CTkButton(self.content_area, text="Play Sound", command=self.play_sound,
                                         height=volume_control_size)
        self.play_button.pack(pady=(10, 20))
        self.volume_slider.set(VOLUME)
        open_file_btn = ctk.CTkButton(self.content_area, text="Open Sound",
                                      command=partial(self.open_file_dialog,
                                                      ("Sound files", "*.mp3 *.wav *.ogg *.flac *.aac"), "Open Sound"))
        open_file_btn.place(relx=0.5, rely=0.1, anchor=ctk.CENTER)

    def setup_contacts(self, content):
        global CONTACTS
        """ set up the contacts page """
        contacts_label = ctk.CTkLabel(self.content_area, text="See/Add Contacts", font=("papyrus", 40))
        contacts_label.place(relx=0.13, rely=0.05, anchor=ctk.W)
        entry_frame = ctk.CTkFrame(self.content_area, fg_color=COLOR_BACKGROUND)
        entry_frame.place(relx=0.15, rely=0.55, anchor=ctk.W)
        entry_widget = LimitedEntry(entry_frame)
        entry_widget.pack(side="left", padx=5)
        enter_button = ctk.CTkButton(entry_frame, text="Enter", command=partial(self.enter_contacts, entry_widget))
        enter_button.pack(side="left", padx=5)
        lst = [content]
        lst += CONTACTS
        self.create_contacts_list(lst)

    def setup_groups(self):
        """ sets up the groups page """
        groups_label = ctk.CTkLabel(self.content_area, text="See/Create Groups", font=("papyrus", 40))
        groups_label.place(relx=0.87, rely=0.05, anchor=ctk.E)
        group_frame = ctk.CTkFrame(self.content_area, fg_color=COLOR_BACKGROUND)
        group_frame.place(relx=0.75, rely=0.6, anchor=ctk.CENTER)
        self.group_entry = LimitedEntry(group_frame)
        self.group_entry.pack(side="top", padx=5, pady=5)
        create_group_btn = ctk.CTkButton(group_frame, text="Create Group", command=self.create_group)
        create_group_btn.pack(side="bottom", padx=5, pady=5)
        self.group_participants_label = ctk.CTkLabel(group_frame, text="Group Participants:", font=("papyrus", 12))
        self.group_participants_label.pack(side="bottom", padx=5, pady=5)
        scrollbar = tkinter.Scrollbar(self.content_area)
        scrollbar.pack(side='right', fill='y')
        self.groups_listbox = tkinter.Listbox(self.content_area, yscrollcommand=scrollbar.set, selectmode='browse',
                                              bg=COLOR_BACKGROUND, fg='white', font=("papyrus", 12))
        self.groups_listbox.pack(side='right', fill='both', expand=True)
        self.populate_groups_list()
        scrollbar.config(command=self.groups_listbox.yview)
        self.groups_listbox.place(relx=0.82, rely=0.18, anchor='ne')
        scrollbar.place(relx=0.99, rely=0.3, relheight=0.5, anchor='ne')

        self.groups_listbox.bind('<<ListboxSelect>>', self.show_group_participants)

    def populate_groups_list(self):
        """ Populate the groups list with existing groups """
        self.groups_listbox.delete(0, tkinter.END)
        self.groups_listbox.insert(tkinter.END, "Groups")
        for group in GROUPS:
            self.groups_listbox.insert(tkinter.END, group)

    def show_group_participants(self, event):
        """ Show group participants when a group is selected """
        selected_group_index = self.groups_listbox.curselection()
        if selected_group_index:
            selected_group = self.groups_listbox.get(selected_group_index)
            if selected_group != "Groups":
                self.client_socket.send(self.aes.encrypt(f"g|{selected_group}".encode("utf-8")))
                participants = json.loads(self.aes.decrypt(self.client_socket.recv(1024)).decode("utf-8"))
                messagebox.showinfo("Group Participants", f"Participants:\n{', '.join(participants)}")

    def create_group(self):
        """ Finalize group creation and manage group participants """
        group_name = self.group_entry.get()
        if group_name in GROUPS:
            self.response_label.configure(text="Group already exists", fg_color="red")
            return
        if group_name:
            try:
                self.client_socket.send(self.aes.encrypt(f"vg|{group_name}".encode("utf-8")))
                response = self.aes.decrypt(self.client_socket.recv(1024)).decode("utf")
            except Exception as e:
                exc_type, exc_value, exc_traceback = sys.exc_info()
                print(f"Error sending closing message to server: {e}, line {exc_traceback.tb_lineno}")
                self.response_label.configure(text="Server shut down, close the app and try again", fg_color="red")
                return
            if response != "OK":
                self.response_label.configure(text=response, fg_color="red")
                return
            self.response_label.configure(text="", fg_color="transparent")
            self.manage_group_participants(group_name)
            self.populate_groups_list()
            self.group_entry.delete(0, ctk.END)
        else:
            self.response_label.configure(text="Please enter a name for your group", fg_color="red")

    def manage_group_participants(self, group_name):
        """ Create a GUI tool to manage group participants """
        participants = []
        participants_frame = ctk.CTkFrame(self.content_area, fg_color=COLOR_BACKGROUND)
        participants_frame.place(relx=0.85, rely=0.65, anchor=ctk.CENTER)
        group_name_label = ctk.CTkLabel(participants_frame, text=f"Group: {group_name}", font=("papyrus", 12))
        group_name_label.pack(side="top", padx=5, pady=5)
        group_participants_label = ctk.CTkLabel(participants_frame, text="Group Participants:", font=("papyrus", 12))
        group_participants_label.pack(side="top", padx=5, pady=5)
        scrollbar = tkinter.Scrollbar(participants_frame)
        scrollbar.pack(side='right', fill='y')
        group_participants_listbox = tkinter.Listbox(participants_frame, yscrollcommand=scrollbar.set,
                                                     selectmode='browse',
                                                     bg=COLOR_BACKGROUND, fg='white', font=("papyrus", 12))
        group_participants_listbox.pack(side='left', fill='both', expand=True)
        scrollbar.config(command=group_participants_listbox.yview)

        def add_participant():
            """ add participant event """
            contact = var.get()
            if contact != "Choose contact":
                group_participants_listbox.insert(tkinter.END, contact)
                contacts.remove(contact)
                contacts_option_menu['menu'].delete(0, tkinter.END)
                for new_contact in contacts:
                    contacts_option_menu['menu'].add_command(label=new_contact,
                                                             command=tkinter._setit(var, new_contact))
                var.set(contacts[0])
                participants.append(contact)

        def remove_participant():
            """ remove participant event """
            selected_index = group_participants_listbox.curselection()
            if selected_index:
                selected_contact = group_participants_listbox.get(selected_index)
                contacts_option_menu["menu"].add_command(label=selected_contact,
                                                         command=tkinter._setit(var, selected_contact))
                group_participants_listbox.delete(selected_index)
                contacts.append(selected_contact)
                participants.remove(selected_contact)

        contacts = ["Choose contact"]
        contacts += CONTACTS
        var = tkinter.StringVar(value=contacts[0])
        contacts_option_menu = tkinter.OptionMenu(participants_frame, var, *contacts)
        contacts_option_menu.pack(side='top', padx=5, pady=5)
        add_participant_button = ctk.CTkButton(participants_frame, text="Add Participant", command=add_participant)
        add_participant_button.pack(side="top", padx=5, pady=5)
        remove_participant_button = ctk.CTkButton(participants_frame, text="Remove Participant",
                                                  command=remove_participant)
        remove_participant_button.pack(side="top", padx=5, pady=5)
        finalize_button = ctk.CTkButton(participants_frame, text="Finalize Group",
                                        command=lambda: self.finalize_group(group_name, participants_frame,
                                                                            participants))
        finalize_button.pack(side="bottom", padx=5, pady=5)

    def finalize_group(self, group_name, frame, participants):
        global GROUPS, CHATS, ADMIN
        """ Finalize group creation and send group information to the server """
        if len(participants) > 1:
            self.response_label.configure(text="", fg_color="transparent")
            participants.append(USER)
            participants_str = "|".join(participants)
            data = f"cg|{group_name}|{participants_str}"
            encrypted_data = self.aes.encrypt(data.encode("utf-8"))
            try:
                self.client_socket.send(encrypted_data)
                response = self.aes.decrypt(self.client_socket.recv(1024)).decode("utf-8")
            except Exception as e:
                exc_type, exc_value, exc_traceback = sys.exc_info()
                print(f"Error sending closing message to server: {e}, line {exc_traceback.tb_lineno}")
                self.response_label.configure(text="Server shut down, close the app and try again", fg_color="red")
                return
            if response == "OK":
                frame.destroy()
                CHATS[group_name] = []
                GROUPS.append(group_name)
                ADMIN.append(group_name)
                self.populate_groups_list()
            else:
                participants.remove(USER)
                self.response_label.configure(text=response, fg_color="red")
        else:
            self.response_label.configure(text="not enough participants", fg_color="red")

    def open_contacts_menu(self):
        """ Open a menu to select contacts to add to the group """
        self.contacts_var = tkinter.StringVar()
        self.contacts_var.set("Select Contacts")
        contacts_menu = tkinter.OptionMenu(self.content_area, self.contacts_var, *CONTACTS)
        contacts_menu.place(relx=0.85, rely=0.6, anchor=ctk.CENTER)

    def setup_home(self):
        """Set up the home page."""
        entry_frame = ctk.CTkFrame(self.content_area, fg_color=COLOR_BACKGROUND)
        entry_frame.place(relx=0.5, rely=0.8, anchor=ctk.CENTER, relwidth=0.5)
        self.create_menu_button("Choose file", "assets/file.webp", partial(self.choose_file_dialog), True)
        self.entry_widget = LimitedEntry(entry_frame, max_chars=200)
        self.entry_widget.pack(side="left", fill="both", expand=True, padx=(5, 0), pady=5)
        lst = list(CHATS.keys())
        lst.insert(0, "Choose who to write to")
        self.create_option_menu(lst)
        self.text_widget = tkinter.Text(self.content_area, wrap='word', height=25, width=85, state="disabled")
        self.text_widget.place(relx=0.5, rely=0.5, anchor="center")
        scrollbar = tkinter.Scrollbar(self.content_area, command=self.text_widget.yview)
        scrollbar.place(relx=0.95, rely=0.5, relheight=0.8, anchor='e')
        self.text_widget.config(yscrollcommand=scrollbar.set)
        enter_button = ctk.CTkButton(entry_frame, text="Enter",
                                     command=partial(self.send_messages))
        enter_button.pack(side="right", padx=(0, 5), pady=5)

    def choose_file_dialog(self):
        """ opens the file dialog for choosing a file """
        file_path = filedialog.askopenfilename(filetypes=[("All files", "*.*")])
        if file_path:
            self.entry_widget.delete(0, tk.END)
            self.entry_widget.insert(tk.END, file_path)

    def update_volume(self, event):
        global VOLUME
        """ Update the volume value when the volume slider is moved """
        new_volume = self.volume_slider.get()
        VOLUME = new_volume

    def play_sound(self):
        """ playes the sound """
        self.play_button.configure(state=ctk.DISABLED)
        self.sound.set_volume(self.volume_slider.get())
        self.sound.play()
        self.master.after(100, self.check_sound_status)

    def check_sound_status(self):
        """ if the sound is played, the button will be unclickable """
        if pygame.mixer.get_busy():
            self.master.after(100, self.check_sound_status)
        else:
            try:
                self.play_button.configure(state=ctk.NORMAL)
            except Exception as e:
                exc_type, exc_value, exc_traceback = sys.exc_info()
                print(f"Error sending closing message to server: {e}, line {exc_traceback.tb_lineno}")

    def change_volume(self, value):
        """ changes the volume """
        if pygame.mixer.get_busy():
            self.sound.set_volume(float(value))
        self.volume_value_label.configure(text=value)

    def send_messages(self):
        """ sends private messages """
        contact = self.var.get()
        msg = self.entry_widget.get()
        self.entry_widget.delete(0, ctk.END)
        if msg and contact != "Choose who to write to":
            if self.response_label:
                self.response_label.configure(text="", fg_color="transparent")
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M")
            if os.path.exists(msg):
                self.create_clickable_link(msg, timestamp)
                CHATS[contact].append((USER, None, get_file(msg), msg, timestamp))
            else:
                try:
                    CHATS[contact].append((USER, msg, None, None, timestamp))
                    data = f"p|{USER}|{contact}|{msg}|{timestamp}"
                    encrypted_username = self.aes.encrypt(data.encode("utf-8"))
                    self.client_socket.send(encrypted_username)
                    message = f"You: {msg}\n{timestamp}\n"
                    self.text_widget.config(state="normal")
                    self.text_widget.insert(ctk.END, message)
                    self.text_widget.config(state="disabled")
                    self.text_widget.yview_moveto(1.0)
                except Exception as e:
                    exc_type, exc_value, exc_traceback = sys.exc_info()
                    print(f"Error sending closing message to server: {e}, line {exc_traceback.tb_lineno}")
                    self.response_label.configure(text="Server shut down, close the app and try again", fg_color="red")
                    return
        else:
            self.response_label.configure(text="please enter a message or choose a contact", fg_color="red")

    def create_clickable_link(self, file_path, timestamp, flag=True, sender="You: "):
        """ creates a clickable link for the file """
        label = tk.Label(self.text_widget, text=sender + file_path + " (File)\n" + timestamp,
                         fg="blue",
                         cursor="hand2")
        label.pack()
        label.bind("<Button-1>", lambda event, path=file_path: open_file(path))
        self.text_widget.window_create(tk.END, window=label)
        self.text_widget.config(state="normal")
        self.text_widget.insert(tk.END, "\n")
        self.text_widget.config(state="disabled")
        self.text_widget.yview_moveto(1.0)
        if flag:
            self.send_file1(file_path, timestamp)

    def send_file1(self, file_path, timestamp):
        """ Sends the file metadata to the server """
        metadata = f"f|{self.var.get()}|{timestamp}|{file_path}"
        try:
            self.client_socket.send(self.aes.encrypt(metadata.encode("utf-8")))
        except Exception as e:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            print(f"Error sending closing message to server: {e}, line {exc_traceback.tb_lineno}")
            self.response_label.configure(text="Server shut down, close the app and try again", fg_color="red")
            return

    def send_file2(self, file_path):
        """ Reads and sends the file data """
        data = get_file(file_path)
        encrypted_data = self.aes.encrypt(data)
        try:
            self.client_socket.sendall(encrypted_data)
            self.client_socket.send(self.aes.encrypt(b"END"))
        except Exception as e:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            print(f"Error sending closing message to server: {e}, line {exc_traceback.tb_lineno}")
            self.response_label.configure(text="Server shut down, close the app and try again", fg_color="red")
            return

    def create_contacts_list(self, contacts):
        """ Create a scrolled listbox widget for contacts """
        scrollbar = tkinter.Scrollbar(self.content_area)
        scrollbar.pack(side='right', fill='y')
        listbox = tkinter.Listbox(self.content_area, yscrollcommand=scrollbar.set, selectmode='browse',
                                  bg=COLOR_BACKGROUND, fg='white', font=("papyrus", 12))
        listbox.pack(side='left', fill='both', expand=True)
        for contact in contacts:
            listbox.insert('end', contact)
        scrollbar.config(command=listbox.yview)
        listbox.place(relx=0.18, rely=0.18, anchor='nw')
        scrollbar.place(relx=0.99, rely=0.3, relheight=0.5, anchor='ne')

    def enter_contacts(self, widget):
        """ adds contacts """
        contact = widget.get()
        if contact:
            if contact == USER:
                self.response_label.configure(text="Bruv trying to crash my app, that ain't happening you silly kuku",
                                              fg_color="red")
            elif contact not in CONTACTS:
                data = f"a|{widget.get()}|{USER}"
                encrypted_message = self.aes.encrypt(data.encode("utf-8"))
                try:
                    self.client_socket.send(encrypted_message)
                    self.client_socket.settimeout(10)
                    encrypted_response = self.client_socket.recv(1024)
                except Exception as e:
                    exc_type, exc_value, exc_traceback = sys.exc_info()
                    print(f"Error sending closing message to server: {e}, line {exc_traceback.tb_lineno}")
                    self.response_label.configure(text="Server shut down, close the app and try again", fg_color="red")
                    return
                response = self.aes.decrypt(encrypted_response).decode("utf-8")
                if response == "OK":
                    CONTACTS.append(widget.get())
                    CHATS[widget.get()] = []
                    self.show_content("Contacts")
                else:
                    self.response_label.configure(text=response, fg_color="red")
            else:
                self.response_label.configure(text="already a contact", fg_color="red")
        else:
            self.response_label.configure(text="Please enter a username", fg_color="red")

    def clear_content_area(self):
        """ clears the screen each time a different icon is pressed """
        for widget in self.content_area.winfo_children():
            if widget is not self.label and widget is not self.response_label:
                widget.destroy()
        self.var = None
        if self.group_management_window:
            self.group_management_window.destroy()

    def open_file_dialog(self, data, name):
        global BACKGROUND, SOUND
        """ Open a file dialog to choose a background image """
        file_path = filedialog.askopenfilename(filetypes=[data])
        if file_path:
            self.clear_content_area()
            if name[-5:] == "Image":
                BACKGROUND = file_path
                self.load_background_image(BACKGROUND)
                self.show_content("Change Background")
            else:
                SOUND = file_path
                self.show_content("Settings")

    def resize_background_image(self, event=None):
        """ resize background to the screens current width """
        new_width = self.winfo_width()
        new_height = self.winfo_height()
        resized_img = self.original_img.resize((new_width, new_height), Image.LANCZOS)
        self.photo = ImageTk.PhotoImage(resized_img)
        self.label.configure(image=self.photo)
        self.label.image = self.photo

    def load_background_image(self, image_path):
        """ loads a background image """
        self.original_img = Image.open(image_path)
        self.photo = ImageTk.PhotoImage(self.original_img)
        self.label = ctk.CTkLabel(self.content_area, image=self.photo, text="")
        self.label.image = self.photo
        self.label.place(relwidth=1, relheight=1)
        self.resize_background_image()
        self.bind("<Configure>", self.resize_background_image)

    def open_group_management(self):
        """ Open the group management window """
        self.group_management_window = GroupManagementWindow(self, self.aes, self.client_socket, USER)
        self.group_management_window.pack(fill="both", expand=True)


class GroupManagementWindow(ctk.CTkFrame):
    """ class for handle groups """

    def __init__(self, master, aes, client_socket, username, *args, **kwargs):
        """ constructor """
        super().__init__(master, *args, **kwargs)
        self.aes = aes
        self.client_socket = client_socket
        self.username = username
        self.group_label = ctk.CTkLabel(self, text="Select Group to Manage:")
        self.group_label.pack(padx=10, pady=5)
        self.group_listbox = tk.Listbox(self)
        self.group_listbox.pack(padx=10, pady=5)
        self.load_groups()
        self.select_button = ctk.CTkButton(self, text="Select Group", command=self.select_group)
        self.select_button.pack(padx=10, pady=5)
        self.add_participant_button = ctk.CTkButton(self, text="Add Participant", command=self.add_participant)
        self.add_participant_button.pack(padx=10, pady=5)
        self.remove_participant_button = ctk.CTkButton(self, text="Remove Participant", command=self.remove_participant)
        self.remove_participant_button.pack(padx=10, pady=5)
        self.make_admin_button = ctk.CTkButton(self, text="Make Admin", command=self.make_admin)
        self.make_admin_button.pack(padx=10, pady=5)
        self.participants = []
        self.contacts = []
        self.admins = []

    def load_groups(self):
        """ insets to the listbox all groups you are admin in """
        self.group_listbox.insert(tk.END, "Admin Groups")
        for group in ADMIN:
            self.group_listbox.insert(tk.END, group)

    def select_group(self):
        """ chooses on which group to do the actions available in class """
        selected_group = self.group_listbox.get(tk.ACTIVE)
        self.selected_group = selected_group
        if self.selected_group != "Admin Groups":
            self.load_participants()
            messagebox.showinfo("Group Selected", f"Selected group: {selected_group}")

    def load_participants(self):
        """ for the group pressed, saves the participants, contacts and admins """
        self.client_socket.send(self.aes.encrypt(f"gp|{self.selected_group}".encode("utf-8")))
        participants = json.loads(self.aes.decrypt(self.client_socket.recv(1024)).decode("utf-8"))
        self.participants = [participant for participant in participants.keys() if not participants[participant]]
        self.contacts = [contact for contact in CONTACTS if contact not in participants.keys()]
        self.admins = [participant for participant in participants.keys() if participants[participant]]

    def add_participant(self):
        """ add participant little window """
        if not self.contacts:
            messagebox.showinfo("No Contacts", "There are no contacts to add\nOr no group selected.")
            return
        add_window = tk.Toplevel(self)
        add_window.title("Add Participant")
        tk.Label(add_window, text="Select the username of the new participant:").pack(padx=10, pady=5)
        participant_var = tk.StringVar(add_window)
        lst = ["Choose friend to add"]
        lst += self.contacts
        participant_var.set(lst[0])
        tk.OptionMenu(add_window, participant_var, *lst).pack(padx=10, pady=5)

        def add():
            global QUEUE
            """ add participant event """
            new_participant = participant_var.get()
            if new_participant != "Choose friend to add":
                data = f"ga|{self.selected_group}|{new_participant}|{USER}"
                self.client_socket.send(self.aes.encrypt(data.encode("utf-8")))
                response = QUEUE.get()
                if response == "OK":
                    messagebox.showinfo("Success", f"Added {new_participant} to {self.selected_group}")
                    add_window.destroy()
                    self.participants.append(new_participant)
                    self.contacts.remove(new_participant)
                    CHATS[self.selected_group].append(("You", f"{USER} added {new_participant}", None, None,
                                                       datetime.now().strftime("%Y-%m-%d %H:%M")))
                else:
                    messagebox.showinfo(response)

        tk.Button(add_window, text="Add", command=add).pack(padx=10, pady=5)

    def remove_participant(self):
        """ remove participant little window """
        if not self.participants:
            messagebox.showinfo("No group selected", "Please select a group.")
            return
        if len(self.participants) + len(self.admins) == 2:
            messagebox.showinfo("Minimum Participants", "Group can't have less than three participants.")
            return
        remove_window = tk.Toplevel(self)
        remove_window.title("Remove Participant")
        tk.Label(remove_window, text="Select the username of the participant to remove:").pack(padx=10, pady=5)
        participant_var = tk.StringVar(remove_window)
        lst = ["Choose participant to remove"]
        lst += self.participants
        participant_var.set(lst[0])
        tk.OptionMenu(remove_window, participant_var, *lst).pack(padx=10, pady=5)

        def remove():
            """ remove participant event """
            participant_to_remove = participant_var.get()
            if participant_to_remove != "Choose participant to remove":
                data = f"gr|{self.selected_group}|{participant_to_remove}|{USER}"
                self.client_socket.send(self.aes.encrypt(data.encode("utf-8")))
                messagebox.showinfo("Success", f"Removed {participant_to_remove} from {self.selected_group}")
                remove_window.destroy()
                self.participants.remove(participant_to_remove)
                self.contacts.append(participant_to_remove)
                CHATS[self.selected_group].append(("You", f"{USER} removed {participant_to_remove}", None, None,
                                                   datetime.now().strftime("%Y-%m-%d %H:%M")))

        tk.Button(remove_window, text="Remove", command=remove).pack(padx=10, pady=5)

    def make_admin(self):
        """ make admin little window """
        if not self.participants:
            messagebox.showinfo("No Participants", "There are no participants to make admin\nOr not group selected.")
            return
        admin_window = tk.Toplevel(self)
        admin_window.title("Make Admin")
        tk.Label(admin_window, text="Select the username of the new admin:").pack(padx=10, pady=5)
        participant_var = tk.StringVar(admin_window)
        lst = ["Choose who to make admin"]
        lst += self.participants
        participant_var.set(lst[0])
        tk.OptionMenu(admin_window, participant_var, *lst).pack(padx=10, pady=5)

        def make_admin():
            """ make admin event """
            new_admin = participant_var.get()
            if new_admin != "Choose who to make admin":
                data = f"gm|{self.selected_group}|{new_admin}|{USER}"
                self.client_socket.send(self.aes.encrypt(data.encode("utf-8")))
                messagebox.showinfo("Success", f"Made {new_admin} an admin of {self.selected_group}")
                admin_window.destroy()
                self.admins.append(new_admin)
                self.participants.remove(new_admin)
                CHATS[self.selected_group].append(("You", f"{USER} made {new_admin} admin", None, None,
                                                   datetime.now().strftime("%Y-%m-%d %H:%M")))

        tk.Button(admin_window, text="Make Admin", command=make_admin).pack(padx=10, pady=5)


def open_file(file_path):
    """ opens the selected file """
    if os.name == 'nt':
        os.startfile(file_path)
    elif os.name == 'posix':
        os.system("xdg-open " + file_path)


def get_file(path):
    """ gets the file  """
    with open(path, "rb") as file:
        data = file.read()
    return data


def validate_number(text):
    """ makes only numbers available in the entry widget """
    return True if text.isdigit() or text == "" else False


def get_current_volume():
    """ Return the current volume level """
    return VOLUME


def create_client_socket_and_get_public_key():
    """ the connection """
    while True:
        try:
            client_socket = socket.socket()
            client_socket.connect((IP, PORT))
            public_key_der = client_socket.recv(1024)
            public_key = rsa.PublicKey.load_pkcs1(public_key_der, format='DER')
            return client_socket, public_key
        except Exception as e:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            print(f"Error sending closing message to server: {e}, line {exc_traceback.tb_lineno}")


def decode_file_content1(data):
    """ faze one of decoding with base64 for files """
    for key, value in data.items():
        data[key] = [decode_file_content2(item) for item in value]
    return data


def decode_file_content2(data):
    """ faze two of decoding with base64 for files """
    decoded_data = []
    counter = 0
    for item in data:
        if counter == 2 and item:
            decoded_data.append(base64.b64decode(item.encode("utf-8")))
        else:
            decoded_data.append(item)
        counter += 1
    return decoded_data


if __name__ == "__main__":
    app = Application()
    app.mainloop()
