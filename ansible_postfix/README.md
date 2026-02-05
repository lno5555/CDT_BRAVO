# ansible_postfix

Lightweight Ansible playbook to install and configure Postfix.

.
├── group_vars
│   └── mailservers.yaml
├── inventory.ini
├── main.yaml
├── README.md
└── templates
    └── main.cf.j2

## Contents
- group_vars/
    - mailservers.yaml - variables 
- vars/ - role variables
- templates/ - Postfix config template (main.cf.j2)
- inventory.yaml - hosts to run this playbook on
- README.md - this file

## Requirements
- Ansible 2.9+
- Target hosts: Debian/Ubuntu

## Usage
1. Update inventory (inventory.ini) with IP address of target host
2. Review variables in group_vars/mailservers.yaml and update as needed based on service configuration and topo
3. Run:
     ansible-playbook -i inventory.ini main.yaml