# Nginx with cool features (Ansible)

A small Ansible playbook for deploying Nginx on Debian-based Linux hosts with features: service persistence, a simple per-IP rate limit zone definition, log directory sanity, and config validation before reload.

## Files
- `nginx.yml` — the playbook
- `inventory.ini` — your host list (example below)

## What the playbook does
- Installs `nginx` via `apt`
- Enables and starts the `nginx` service (survives reboots)
- Adds a rate limit zone config at `/etc/nginx/conf.d/greyteam-ratelimit.conf`
- Ensures `/var/log/nginx` exists with sane permissions
- Runs `nginx -t` to validate config, then reloads nginx

## Requirements
- Ansible on the control machine
- SSH access to the target host(s)
- Targets are Debian/Ubuntu (uses `apt`)
- Privilege escalation available (sudo)

## Example `inventory.ini`
```ini
[all]
<IP>
