# Secure Chat

> **A Secure Encrypted Communication System for Organizations**

---

## 🧭 Table of Contents

- [Introduction](#-introduction)
- [Features](#-features)
- [Technology Stack](#-technology-stack)
- [Project Structure](#-project-structure)
- [Installation](#-installation)
- [Usage](#%EF%B8%8F-usage)
- [System Architecture](#-system-architecture)
- [Communication Protocol](#-communication-protocol)
- [Database Schema](#-database-schema)
- [Examples](#-examples)
- [Security](#-security)
- [Testing](#-testing)
- [Known Limitations](#-known-limitations)
- [Development Timeline](#-development-timeline)
- [Troubleshooting](#-troubleshooting)
- [Contributors](#-contributors)
- [License](#-license)

---

## 📘 Introduction

Secure Chat is a custom-built secure communication system designed for private companies and organizations. It enables encrypted messaging and file sharing between employees, managers, and clients while prioritizing cybersecurity, usability, and performance.

The project was developed as part of a final year software engineering specialization in Cybersecurity and Operating Systems at Ben Gurion High School.

---

## ✨ Features

- 🔐 Encrypted text messaging (AES + RSA)
- 📁 Secure file sharing with compression
- 👥 Group and contact management
- 🔔 Notifications and updates
- 📊 Admin user controls and permissions
- 🔊 User volume and sound settings
- 🌄 Custom backgrounds and GUI customization
- 📃 Chat history management

---

## 🛠 Technology Stack

| Component         | Technology Used         |
|------------------|-------------------------|
| Programming Lang | Python 3                |
| GUI Framework    | CustomTkinter           |
| Networking       | Python `socket`, `threading` |
| Encryption       | RSA, AES, bcrypt        |
| Database         | SQLite (`sqlite3`)      |
| Multimedia       | Pygame (for sound)      |
| Compression      | zlib                    |
| Email Service    | `smtplib`, `email.mime` |
| File Handling    | `base64`, `os`, `PIL`   |

---

## 🧱 Project Structure

```
/client
  ├── login_window.py
  ├── main_frame.py
  ├── group_management.py
  └── ...
/server
  ├── server_main.py
  ├── database.py
  ├── client_thread.py
  └── ...
/assets
  └── images, sounds, background files
```

---

## 💾 Installation

### Prerequisites

- Python 3.10+
- OS: Windows/Linux/macOS
- Python packages:
  - `customtkinter`
  - `rsa`, `pyaes`
  - `pygame`
  - `bcrypt`, `sqlite3`
  - `PIL`, `smtplib`, `email`, `zlib`

### Setup

```bash
git clone https://github.com/your-username/secure-chat
cd secure-chat
pip install -r requirements.txt
python server/server_main.py  # Start the server
python client/login_window.py # Run the client
```

---

## 🖥️ Usage

1. Launch the server.
2. Each user opens the client application and logs in or signs up.
3. Users can:
   - Chat privately or in groups
   - Send/receive files
   - Manage contacts and groups
   - Adjust sound and background settings

---

## 🏗 System Architecture

- **Client-Server Model**
- Server handles:
  - Authentications
  - Message routing
  - File transfers
  - Group management
- Clients handle:
  - UI interactions
  - AES encryption
  - Sending/receiving data

---

## 📡 Communication Protocol

Messages between client and server use a custom text-based protocol:

- **User Auth**: `u|username|password`
- **Password Change**: `c|username|new_password`
- **Send File**: `f|recipient|timestamp|filename`
- **Group Management**: `cg|group|participant1|...`

Responses:
- `ok`, `not ok`, `no such user`, etc.

---

## 🗃 Database Schema

Includes tables like:

- `Users(id, username, password, email)`
- `Messages(sender_id, receiver_id, msg, file, path, time)`
- `Groups(id, name)`
- `Participants(group_id, user_id)`
- `Admins(group_id, admin_id)`
- `Contacts(user_id, contact_id)`
- `Volumes`, `Sounds`, `Backgrounds`

---


---

## 🖼️ Examples

You can include screenshots or GIFs of the application here to showcase functionality such as:

- Login screen
- Main chat window
- Group management interface
- File transfer in action

To add images to this section, place your image files in a folder (e.g., `/assets/images/`) and use the following Markdown syntax:

```markdown
![Login Screen](assets/images/login.png)
![Group Management](assets/images/group_management.png)
```

---

## 🔐 Security

Secure Chat incorporates multiple layers of security to ensure confidentiality, integrity, and availability of communication:

### 🔒 Encryption

- **AES (Advanced Encryption Standard)**: Used for symmetric encryption of messages and files during transmission.
- **RSA**: Asymmetric encryption used to securely exchange AES keys between client and server.
- **bcrypt**: For secure password hashing with salt before storage in the database.

### 📜 Authentication & Validation

- Custom protocol with secure credential verification.
- Input validation against injection attacks (SQL injection mitigated using parameterized queries).
- Password recovery with multi-step verification via email.

### 🛡️ Network & Data Integrity

- **MITM Protection**: All messages are encrypted to prevent man-in-the-middle attacks.
- **End-to-End File Encryption**: Files are encrypted and compressed before transfer.
- **Chunked Transfers**: Files are transferred in chunks to reduce risk of interruption or buffer overflow.

### 🧠 DoS/DDoS Mitigation

- Rate limiting based on IP address.
- Basic CAPTCHA (optional) for login interfaces.
- Request throttling and logging for suspicious activity.

### ⚠️ Other Threats Addressed

- File validation to prevent uploading malicious or oversized files.
- Continuous audit of logs and client-server events for anomaly detection.

> Security was a core motivation behind this project, and it adheres to modern best practices in network communication and secure software design.

## 🧪 Testing

Black-box testing includes:

- Message length validation
- File integrity & encryption
- Login edge cases (empty input, bad email)
- Stress tests (multiple users, video streaming)
- Password reset flow

---

## 🚧 Known Limitations

- Dependent on internet quality
- No integration with complex enterprise platforms
- Basic protection against DDoS only

---

## 📅 Development Timeline

| Phase               | Dates         |
|---------------------|---------------|
| Planning & Design   | Apr 27 – May 4 |
| Core Development    | May 5 – May 12 |
| Integration & Tests | May 13 – May 20 |
| Optimization        | May 21 – May 28 |
| Final Touches       | May 29 – June 1 |

---

## 🩺 Troubleshooting

| Issue                       | Solution                                  |
|----------------------------|-------------------------------------------|
| Can't connect to server    | Ensure server is running and IP is valid  |
| File transfer fails        | Check network & file path validity        |
| GUI not loading properly   | Verify `customtkinter` is installed       |

---

## 👨‍💻 Contributors

- **Chen Shor** – Developer, Designer  
  > Ben Gurion High School – Cybersecurity Track  
  Guided by **Lina Schmidt**

---

## 📄 License

MIT License.  
You are free to use, modify, and distribute this project with attribution.
