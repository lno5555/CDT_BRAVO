# Blue Team 5-Minute Script

## Overview

This script is a **quick-response hardening tool** for Ubuntu, designed for blue team scenarios such as competitions, incident response, or initial compromise containment.

It performs:

* System updates
* Firewall configuration
* Basic service and process inspection
* Nginx hardening
* Persistence checks
* Optional backups and restores

---

## Requirements

* Ubuntu-based system
* Root privileges (`sudo`)
* Internet access (for package updates)

---

## Usage

### Run normally (hardening mode)

```bash
sudo ./script.sh
```

---

### Enable backup before hardening

Creates compressed backups of key directories:

* `/etc/nginx`
* `/var/www`

```bash
sudo ./script.sh --backup
```

Backups are stored in:

```
/opt/turf_backups
```

---

### Restore full backup

```bash
sudo ./script.sh --restore <backup_file>
```

---

### Restore Nginx only

Restores and safely validates configuration before restarting:

```bash
sudo ./script.sh --restore-nginx <backup_file>
```

---

## What the Script Does

### 1. Root Check

Ensures the script is run with administrative privileges.

---

### 2. System Update

Updates and upgrades all packages:

* `apt update`
* `apt upgrade`

---

### 3. Installs Security Tools

Installs essential utilities:

* `ufw` (firewall)
* `net-tools`
* `lsof`
* `curl`

---

### 4. Firewall Hardening (UFW)

* Resets existing rules
* Allows:

  * SSH (22)
  * HTTP (80)
  * HTTPS (443)
* Denies all other incoming traffic

---

### 5. Network Inspection

Displays:

* Listening ports (`ss`)
* Active connections (`lsof`)

---

### 6. Process Inspection

Shows top CPU-consuming processes for manual review.

---

### 7. Nginx Hardening

* Disables directory listing (`autoindex off`)
* Tests configuration before restart
* Prevents restart if config is invalid

---

### 8. Web Directory Monitoring

Lists files modified in the last 24 hours in:

```
/var/www
```

---

### 9. Persistence Checks

Checks for common persistence mechanisms:

* User cron jobs
* System cron directories
* Enabled services

---

### 10. User Review

Lists all system users for manual auditing.

---

## Backup System

Backups are:

* Timestamped
* Stored in `/opt/turf_backups`
* Compressed as `.tar.gz`

---


This script is designed for **speed over completeness** — it gives defenders a fast starting point, not a full security solution.
