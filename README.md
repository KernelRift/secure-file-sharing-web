# secure-file-sharing-web
# Secure File Sharing Application

A Python-based secure file-sharing application developed as part of a CODSOFT internship task.

The application provides authenticated file upload and download functionality, encryption before storage, role-based access control, and temporary download links.

## Features

* User registration and authentication
* Secure password hashing
* Secure file uploads
* File encryption before storage
* Role-based access control
* File ownership validation
* Secure filename handling
* Randomized encrypted storage filenames
* Temporary download links
* Automatic link expiration
* SQLite database
* Basic web interface

## Technologies

* Python
* Flask
* SQLite
* Cryptography
* Werkzeug
* HTML
* CSS

## Security Architecture

The application follows a basic secure file-storage workflow:

```text
User
  |
  v
Authentication
  |
  v
Authorization / RBAC
  |
  v
File Upload
  |
  v
File Encryption
  |
  v
Encrypted Storage
```

For downloads:

```text
User
  |
  v
Authentication
  |
  v
Authorization
  |
  v
Encrypted File
  |
  v
Decryption
  |
  v
Secure Download
```

## Installation

Clone the repository:

```bash
git clone https://github.com/KernelRift/secure-file-sharing-web
cd secure-file-sharing
```

Create a virtual environment:

```bash
python3 -m venv venv
source venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Run the application:

```bash
python3 app.py
```

Open:

```text
http://127.0.0.1:5000
```

## Encryption

Files are encrypted before being written to the server's storage directory.

The application uses the Python `cryptography` library and Fernet symmetric encryption.

The original filename is not used as the encrypted storage filename.

## Role-Based Access Control

Users can access files according to their permissions.

File ownership is checked before allowing a download.

Administrators can be given broader access than standard users.

## Temporary Download Links

The application can generate temporary download links.

The generated token:

* Is cryptographically random
* Is associated with a specific file
* Has an expiration time
* Cannot be used after expiration

The demonstration implementation uses a 10-minute expiration period.

## Security Considerations

This project is intended as an educational demonstration.


## Other CODSOFT Project

➡️ [Network Packet Sniffer & Analyzer](https://github.com/KernelRift/network-packet-sniffer)
