
# ICMP Command & Control

## Overview

This project demonstrates a simple **HTTPS-based command and control (C2) channel** implemented in Python.

The system consists of:

- **Server** – Flask server runs on the host, stages your commands in a queue, and issues them by returning the task in an encrypted HTTPS POST response whenever an agent beacons.
- **Agent** – Runs on the target; periodically performs an HTTPS POST to the Flask server to check for new tasks and then executes the received command locally. 

## Features

- Interactive CLI on the server
- Command execution on the agent
- Multi-agent capabilities
- Stealth-oriented with service creation and jitter

## Requirements

- Linux system
- Python 3
- Root privileges (`sudo`)
- requests library on client
- flask library on server

---

## Setup & Usage

### 1. **Generate SSL Certificates** Generate self-signed certificates to enable encrypted communication:

```bash
   openssl req -x509 -newkey rsa:4096 -nodes -out cert.pem -keyout key.pem -days 365
```

### 2. **Install dependencies**

```bash
   pip3 install flask
```

### 3. **Run the server**

```bash
   sudo python3 server.py
```

### 4. **Edit server URL to include the server's IP**

```python
   URL = "https://<Server_IP>:443"
```

### 5. **Configure Inventory** Add your target IPs to your Ansible hosts.ini

### 6. Run `ansible-playbook -i inventory.ini deploy.yml`





