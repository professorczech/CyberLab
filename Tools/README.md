# LabSetup.ps1
## Features:

    Creates isolated lab directory structure
    
    Installs Python 3.12 with required packages
    
    Configures Windows Firewall for lab ports
    
    Sets up test files and directories

## Includes safety scripts for:
    
    Network monitoring
    
    Lab cleanup
    
    Defender management
    
    Generates example malware files
    
    Installs analysis tools (Wireshark, Nmap)

## Usage:

    Run PowerShell as Administrator

## Execute the setup script:


> .\LabSetup.ps1

## Post-Setup Checklist:

### Validate Python installation:

> python --version

> pip list

## Test network monitoring:

> .\Tools\StartMonitoring.ps1

## Verify test directories:

> Get-ChildItem -Recurse C:\CyberLab

## Security Notes:

    Automatically disables Windows Defender (re-enable with LabReset.ps1)
    
    Creates explicit firewall rules for lab ports
    
    Contains all dangerous operations within isolated directory
    
    Includes automatic cleanup script

## Recommended Lab Configuration:

    Use VMware/VirtualBox with Host-Only networking
    
    Allocate 2-4GB RAM per VM
    
    Use Windows 11 Enterprise Evaluation licenses
    
    Disable unnecessary Windows services
    
    Create snapshot before experiments

