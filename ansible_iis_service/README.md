## author:
Aman Patel
## email: 
anp7713@rit.edu
## date: 
2026-02-03

---

## Overview
This is the ansible playbook with IIS service features and functions
---

## Setup
- Just edit IP address and username and password in `win-inventory.ini`

## Run

- Run the playbook:
`ansible-playbook -i win-inventory.ini hw2_iis.yml`
- Go to windows and type this:
`http://<WIN_IP_ADDRESS>`
- or type `curl http://WIN_IP_ADDRESS` to see its working 

