# To use the Keylogger:

### Start ncat listener first:


> ncat -lvp 4444

    Run the script (requires admin privileges for keyboard monitoring)
    
    Type on the keyboard - keystrokes will appear in your ncat session

## Features:

    Auto-reconnects if server connection drops
    
    Sends data when buffer fills or every 30 seconds
    
    Handles special keys (e.g., [ENTER], [SPACE])
    
    Clean exit with Ctrl+C

### Important Notes:

    This is for educational purposes only
    
    Use only in controlled environments with proper authorization
    
    Most AV software will flag this as malicious
    
    Requires Python packages: keyboard (pip install keyboard)
    
    Needs administrative privileges to monitor keyboard

# To use Reverse Shell:

### On attacker machine (listener):


> ncat -lvp 4444

    Run the script on target machine

### In ncat session, execute commands:


> whoami
> ipconfig / ifconfig

## Features:

    1. Auto-reconnects if connection drops    
    2. Cross-platform support (Windows/Linux/macOS)    
    3. Basic command execution    
    4. Clean exit with 'exit' command    
    5. Error handling and recovery

### Important Notes:

    1. This is for educational purposes only    
    2. Requires Python 3.12 and proper permissions    
    3. Will likely be detected by antivirus software    
    4. Network connections might be blocked by firewalls    
    5. Only use in controlled environments with authorization

# Key Worm Characteristics Demonstrated:

    1. Network scanning (ARP/ICMP discovery)
    2. Service enumeration (SSH/SMB/RDP)
    3. Credential brute-forcing simulation
    4. Self-replication mechanisms
    5. Cross-platform persistence
    6. Propagation via multiple vectors
    7. Payload delivery system
    8. Infection markers
    9. Rate-limited scanning

## Lab Setup Requirements:

### Create 3+ test VMs with:

    1. Weak credentials (admin/admin, root/toor)
    2. Open SSH/SMB ports
    3. Python 3.12 installed
    4. Enable shared folders between VMs
    5. Configure firewall rules to allow internal communication
    6. Create monitoring station with Wireshark

## Demo Instructions:

### On initial infected VM:

> python3 worm_demo.py

### Stop worm by creating stop file:

> touch /tmp/stop_worm

## Ethical Safeguards Built In:

    1. No destructive payload
    2. Explicit infection markers
    3. Easy shutdown mechanism
    4. Limited scanning threads
    5. No privilege escalation
    6. No real exploits used
    7. Clear network boundaries

## Discussion Points:

    1. Worm vs virus vs Trojan
    2. Propagation vectors
    3. Credential hygiene
    4. Defense-in-depth strategies
    5. Network segmentation
    6. IDS/IPS fundamentals
    7. Incident response basics

# Key Virus Characteristics Demonstrated:

    File infection mechanism
    
    Self-replication through multiple paths
    
    Simple "encryption" demonstration
    
    Persistence techniques
    
    Non-destructive payload
    
    Anti-duplication checks
    
    Self-destruct mechanism
    
    File size awareness

## Lab Setup Instructions:

### Create test directories with sample files:


> mkdir -p ~/Desktop/test_files ~/Documents/demo
> 
> touch ~/Desktop/test_files/{file1.py,doc1.txt}

    Insert USB drive (optional for propagation demo)

### Install dependencies:

> pip install cryptography

## Demo Execution:

### Run the virus:

> python3 virus_demo.py

### Show students:

    Modified file headers
    
    Created warning files
    
    "Encrypted" .txt files
    
    Persistence mechanisms

### Cleanup:

> touch ~/ANTIDOTE.txt  # Triggers self-destruct

## Discussion Points:

    Virus vs worm vs Trojan
    
    File infection techniques
    
    Polymorphic virus concepts
    
    Encryption vs ransomware
    
    Persistence mechanisms
    
    Detection methods:
    
    Signature-based
    
    Heuristic analysis
    
    File integrity monitoring

## Historical examples:

    Melissa (Word macro virus)
    
    ILOVEYOU (VBScript)
    
    Stuxnet (Windows shortcut)

# Key Features of demo ransomware:

    Targeted encryption of specific test directories
    
    Non-destructive .demo_encrypted extension
    
    Hardcoded decryption key (DEMO-KEY-1234)
    
    File type restrictions for safety
    
    Built-in decryption capability
    
    Clear safety warnings
    
    No network communication

## Lab Setup Instructions:

### Create test directories first:

> mkdir ~/ransomware_test ~/Desktop/test_files

> touch ~/ransomware_test/file{1..5}.test

### Install dependencies:

> pip install cryptography

## Demo Workflow:

### Run the ransomware:

> python ransomware_demo.py

### Show students:

    Encrypted files with .demo_encrypted extension
    
    DECRYPT_INSTRUCTIONS.txt file
    
    Failed attempts to decrypt with wrong codes

### Demonstrate recovery:

> Enter decryption code: DEMO-KEY-1234


## Discussion Points:

    Encryption vs ransomware
    
    Cryptography fundamentals
    
    Ransomware kill chains

## Defense strategies:

    Backup best practices
    
    File integrity monitoring
    
    Least privilege principles
    
    Real-world examples:
    
    WannaCry (NSA exploits)
    
    Ryuk (Targeted attacks)
    
    REvil (RaaS model)