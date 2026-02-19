sshKeyPlacer


What does this tool do: Connects into a service to run persistantly even after restart. It will check that the red team ssh key is in the authorized_keys file and replace it if it isnt.
                        If the key is being blocked or is unsuable, it can be ran with flags to generatge a new keypair that the red team can use

How to use this tool: run the ansible, a C2 is needed to edit/troubleshoot if needed and grab the replacement keys if needed. This tool will need to be paired with a C2 to be used effectivly 

