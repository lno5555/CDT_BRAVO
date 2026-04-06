#!/bin/bash

INPUT_FILE="users.txt"

# Check if file exists
if [[ ! -f "$INPUT_FILE" ]]; then
    echo "Input file not found!"
    exit 1
fi

# Loop through each line
while IFS=: read -r username password
do
    # Check if user exists
    if id "$username" &>/dev/null; then
        echo "Changing password for $username"
        echo "$username:$password" | sudo chpasswd
    else
        echo "User $username does not exist"
    fi
done < "$INPUT_FILE"

echo "Done."
