<#
.SYNOPSIS
Starts network traffic monitoring for lab activities

.DESCRIPTION
- Captures traffic on lab ports (443, 4444, 1337)
- Saves output to PCAPNG format
- Requires Wireshark/tshark
#>

# Configuration
$outputDir = "C:\CyberLab\Network_Traffic"
$captureFile = "$outputDir\lab_capture_$(Get-Date -Format 'yyyyMMdd-HHmmss').pcapng"
$filter = "tcp port 443 or tcp port 4444 or tcp port 1337"

try {
    # Verify Wireshark installation
    $tsharkPath = "$env:ProgramFiles\Wireshark\tshark.exe"

    if (-not (Test-Path $tsharkPath)) {
        Write-Host "Wireshark not found! Installing via Chocolatey..."
        choco install wireshark -y --force
        refreshenv
    }

    # Create output directory
    if (-not (Test-Path $outputDir)) {
        New-Item -Path $outputDir -ItemType Directory | Out-Null
    }

    # Get network interfaces
    Write-Host "Available network interfaces:"
    & $tsharkPath -D

    # Start capture
    Write-Host "`nStarting network capture..." -ForegroundColor Cyan
    Write-Host "Capture filter: $filter"
    Write-Host "Output file: $captureFile`n"

    & $tsharkPath -i "Ethernet0" -f $filter -w $captureFile

}
catch {
    Write-Host "[!] Monitoring error: $_" -ForegroundColor Red
}