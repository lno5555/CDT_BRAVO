# NetHack Docker with Ansible

**Author:** Shawn Fuchs
**Email:** smf8314@rit.edu
**Date:** 2026-02-03

---

## Overview
This Ansible playbook installs Docker on Ubuntu and runs a NetHack (a medieval texted based RPG) container. Your game progress is saved on the host machine.

---

## Requirements
- Ubuntu 20.04
- Sudo user
- Ansible installed on your control machine
- Internet access to install Docker and pull the NetHack image

---

## Setup
- Add IP address and user name to `inventory.ini`

## Run

1. Run the playbook:
```bash
ansible-playbook -i inventory.ini install_docker.yml```

## Play game
Log on to the target and run:
```docker attach medieval_nethack```
