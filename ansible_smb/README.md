# Ansible SMB Setup

**Author:** Jupiter Howard
**Email:** jjh2865@rit.edu
**Date:** 2/4/2026

---

## Overview
This playbook sets up SMB on a Windows server. It enables signing, enables auditing, and creates a template file.

---

## Setup
- Add IP address, username, and password to `win-inventory.ini`

## Run
- Run the playbook: `ansible-playbook -i win-inventory.ini smb-setup.yml`
