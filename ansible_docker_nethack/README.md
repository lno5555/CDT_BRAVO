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

## Quick Start

1. Run the playbook:
```bash
ansible-playbook -i inventory install_docker.yml -K

