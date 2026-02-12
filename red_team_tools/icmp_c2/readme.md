# ICMP Command & Control

## Overview

This project demonstrates a **basic ICMP-based Command & Control (C2) channel** implemented in Python for educational and defensive security purposes.

The system consists of:

- **ICMP Server** – runs on the host and issues commands via ICMP Echo Replies  
- **ICMP Agent** – runs on the target and executes commands received via ICMP  

Communication uses **ICMP Echo Request/Reply packets** with application-layer payloads.  
Command and output data are **Base64-encoded** to provide light obfuscation from casual packet inspection.

## Features

- ICMP Echo Request/Reply transport
- Interactive CLI on the server
- Command execution on the agent
- Base64 encoding for payload obfuscation
- Stateless, simple protocol
- Uses Python standard library only

## Requirements

- Linux system (raw sockets required)
- Python 3
- Root privileges (`sudo`)
- ICMP allowed between host and target

---

## Setup & Usage

### 1. Configure Server IP

Edit `icmp_agent.py`:

```python
SERVER_IP = "100.65.6.1"

### 2. Configure Ansible

Edit `inventory.ini`:
