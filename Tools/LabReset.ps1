<#
.SYNOPSIS
Resets the cybersecurity lab environment to a clean state

.DESCRIPTION
- Removes all lab files and directories
- Restores Windows Defender settings
- Cleans firewall rules
- Removes Python packages
#>

#Requires -RunAsAdministrator

Write-Warning "THIS WILL DESTROY ALL LAB ARTIFACTS AND CONFIGURATIONS!"
$confirmation = Read-Host "Are you sure you want to reset the lab? (YES/no)"
if ($confirmation -ne "YES") {
    Write-Host "Aborting reset operation"
    exit
}

# Lab Configuration
$labBase = "C:\CyberLab"
$pythonPackages = @("keyboard", "paramiko", "cryptography", "pyautogui", "psutil")

try {
    # Remove lab directories
    if (Test-Path $labBase) {
        Write-Host "Removing lab directory..."
        Remove-Item -Path $labBase -Recurse -Force -ErrorAction Stop
    }

    # Restore Windows Defender
    Write-Host "Re-enabling Windows Defender..."
    Set-MpPreference -DisableRealtimeMonitoring $false

    # Remove firewall rules
    Write-Host "Cleaning firewall rules..."
    Get-NetFirewallRule -DisplayName "Lab_*" | Remove-NetFirewallRule

    # Remove Python packages
    Write-Host "Cleaning Python environment..."
    foreach ($pkg in $pythonPackages) {
        pip uninstall -y $pkg | Out-Null
    }

    # Optional: Reset Python installation
    # choco uninstall python -y

    Write-Host "[+] Lab environment reset complete!" -ForegroundColor Green
}
catch {
    Write-Host "[!] Error during cleanup: $_" -ForegroundColor Red
}