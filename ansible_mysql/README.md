# Ansible MySQL installation

**Author:** Shane Russell
**Email:** smr7408@rit.edu
**Date:** 2026-02-04

---

## Overview
This Ansible playbook installs MySQL and creates a database, a user with viewing privileges, and a table.

---

## Setup
- Add IP address to `inventory.ini`

## Run

- Run the playbook:
`ansible-playbook -i inventory.ini install_mysql.yml`

