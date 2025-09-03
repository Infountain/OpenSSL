#!/usr/bin/env python3

import os
import base64
import warnings
from datetime import datetime, timedelta
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from cryptography import x509
from cryptography.x509.oid import NameOID
import time

import tkinter as tk
from tkinter import scrolledtext, messagebox

warnings.filterwarnings("ignore", category=DeprecationWarning)

print("="*70)
print("AUTOMOTIVE CYBERSECURITY TRAINING - SESSION 1")
print("RSA 2048 Public-Private Key Cryptography Demonstration")
print("="*70)

class AutomotiveCryptoDemo:
    def __init__(self):
        self.private_key = None
        self.public_key = None
        self.certificate = None

    def generate_key_pair(self):

        # Generate private key
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,

        )


        # Get public key from private key
        self.public_key = self.private_key.public_key()
 
        print("Key pair generated successfully!")
        print(f"   Private Key Size: 2048 bits")
        print(f"   Public Exponent: {self.private_key.public_key().public_numbers().e}")

        print(self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8'))

        print(self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8'))

        return self.private_key, self.public_key

    def create_digital_certificate(self, common_name="Automotive ECU Demo"):

        if not self.private_key:
            raise ValueError("Must generate keys first!")

        # Certificate details
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "IN"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Karnataka"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Bengaluru"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Automotive Training Center"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ])

        # Create certificate
        cert_builder = x509.CertificateBuilder()
        cert_builder = cert_builder.subject_name(subject)
        cert_builder = cert_builder.issuer_name(issuer)
        cert_builder = cert_builder.public_key(self.public_key)
        cert_builder = cert_builder.serial_number(x509.random_serial_number())
        cert_builder = cert_builder.not_valid_before(datetime.utcnow())
        cert_builder = cert_builder.not_valid_after(datetime.utcnow() + timedelta(days=365))

        # Sign certificate with private key
        self.certificate = cert_builder.sign(self.private_key, hashes.SHA256())

        print("Digital Certificate created successfully!")

        time.sleep(3)  # Simulate some processing time 
        print(self.certificate.public_bytes(serialization.Encoding.PEM).decode('utf-8'))

        return self.certificate

    def demonstrate_encryption(self, message):

        # Convert message to bytes
        message_bytes = message.encode('utf-8')

        # Encrypt using public key (RSA with OAEP padding for security)
        encrypted_message = self.public_key.encrypt(
            message_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Convert to base64 for display
        encrypted_base64 = base64.b64encode(encrypted_message).decode('utf-8')

        print("Encryption completed!")
        print(f"Encrypted message (Base64): {encrypted_base64[:60]}")
        print(f"Encrypted message size: {len(encrypted_message)} bytes")

        return encrypted_message

    def demonstrate_decryption(self, encrypted_message):

        # Decrypt using private key
        decrypted_message = self.private_key.decrypt(
            encrypted_message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Convert back to string
        original_message = decrypted_message.decode('utf-8')

        print("Decryption completed!")
        print(f"Decrypted message: '{original_message}'")

        return original_message

    def demonstrate_digital_signature(self, message):

        # Convert message to bytes
        message_bytes = message.encode('utf-8')

        # Create digital signature
        signature = self.private_key.sign(
            message_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        # Convert to base64 for display
        signature_base64 = base64.b64encode(signature).decode('utf-8')

        print("Digital signature created!")
        print(f"Signature (Base64): {signature_base64[:60]}")
        print(f"Signature size: {len(signature)} bytes")

        return signature

    def verify_digital_signature(self, message, signature):
        try:
            # Convert message to bytes
            message_bytes = message.encode('utf-8')

            # Verify signature
            self.public_key.verify(
                signature,
                message_bytes,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )

            print("Signature verification SUCCESSFUL!")
            print("Message is authentic and hasn't been tampered with")
            print("Message definitely came from the private key owner")

            return True

        except Exception as e:
            print("Signature verification FAILED!")
            print("  Message may have been tampered with")
            print("  Message may not be from the claimed sender")
            return False

    def demonstrate_tampering_detection(self, signature):
        """Demonstrate how signature verification catches tampering"""
        print(f"\nBONUS: TAMPERING DETECTION DEMO")
        print("Let's see what happens when someone tampers with our message")

        tampered_message = "ENGINE_TEMP:99C;BRAKE_PRESSURE:FAIL;FIRMWARE_VERSION:HACKED"
        print(f"Tampered message: '{tampered_message}'")

        # Try to verify the original signature against tampered message
        is_valid = self.verify_digital_signature(tampered_message, signature)

        if not is_valid:
            print("\nSECURITY SUCCESS:")
            print("  Digital signature detected the tampering!")
            print("  This proves why cryptography is essential in vehicles")
            print("  Prevents malicious firmware or fake ECU messages")

        return is_valid

def interactive_demo():
    """Run an interactive demonstration"""
    print("\n" + "="*50)
    print("INTERACTIVE DEMONSTRATION")
    print("="*50)

    demo = AutomotiveCryptoDemo()

    # Generate keys and certificate
    demo.generate_key_pair()
    demo.create_digital_certificate("Vehicle_ECU_Training_Module")

    # Get user input for message
    print("\nEnter a message to encrypt (or press Enter for default):")
    user_message = input("> ").strip()
    if not user_message:
        user_message = "ENGINE_STATUS:OK;BRAKE_TEMP:65C;GPS:12.9716,77.5946"

    # Demonstrate full encryption cycle
    encrypted = demo.demonstrate_encryption(user_message)
    decrypted = demo.demonstrate_decryption(encrypted)

    # Demonstrate digital signatures
    signature = demo.demonstrate_digital_signature(user_message)
    demo.verify_digital_signature(user_message, signature)


    demo.demonstrate_tampering_detection(signature)

    return demo

class AutomotiveCryptoGUI:
    def __init__(self, root):
        self.demo = AutomotiveCryptoDemo()
        self.root = root
        self.root.title("Automotive Crypto Demo")
        self.setup_gui()

    def setup_gui(self):
        # Key Generation
        tk.Button(self.root, text="Generate Key Pair", command=self.generate_keys).pack(fill='x')
        tk.Button(self.root, text="Create Certificate", command=self.create_certificate).pack(fill='x')

        # Message Entry
        tk.Label(self.root, text="Message:").pack()
        self.message_entry = tk.Entry(self.root, width=80)
        self.message_entry.pack(fill='x')
        self.message_entry.insert(0, "ENGINE_STATUS:OK;BRAKE_TEMP:65C;GPS:12.9716,77.5946")

        # Encrypt/Decrypt
        tk.Button(self.root, text="Encrypt Message", command=self.encrypt_message).pack(fill='x')
        tk.Button(self.root, text="Decrypt Message", command=self.decrypt_message).pack(fill='x')

        # Digital Signature
        tk.Button(self.root, text="Sign Message", command=self.sign_message).pack(fill='x')
        tk.Button(self.root, text="Verify Signature", command=self.verify_signature).pack(fill='x')
        tk.Button(self.root, text="Tampering Detection", command=self.tamper_detection).pack(fill='x')

        # Output
        self.output = scrolledtext.ScrolledText(self.root, height=20)
        self.output.pack(fill='both', expand=True)

        # Internal state
        self.encrypted_message = None
        self.signature = None

    def generate_keys(self):
        self.demo.generate_key_pair()
        self.output.insert(tk.END, "Key pair generated.\n")

    def create_certificate(self):
        self.demo.create_digital_certificate("Vehicle_ECU_Training_Module")
        self.output.insert(tk.END, "Certificate created.\n")

    def encrypt_message(self):
        msg = self.message_entry.get()
        self.encrypted_message = self.demo.demonstrate_encryption(msg)
        self.output.insert(tk.END, "Message encrypted.\n")

    def decrypt_message(self):
        if self.encrypted_message:
            decrypted = self.demo.demonstrate_decryption(self.encrypted_message)
            self.output.insert(tk.END, f"Decrypted: {decrypted}\n")
        else:
            messagebox.showerror("Error", "No encrypted message found.")

    def sign_message(self):
        msg = self.message_entry.get()
        self.signature = self.demo.demonstrate_digital_signature(msg)
        self.output.insert(tk.END, "Message signed.\n")

    def verify_signature(self):
        msg = self.message_entry.get()
        if self.signature:
            valid = self.demo.verify_digital_signature(msg, self.signature)
            self.output.insert(tk.END, f"Signature valid: {valid}\n")
        else:
            messagebox.showerror("Error", "No signature found.")

    def tamper_detection(self):
        if self.signature:
            valid = self.demo.demonstrate_tampering_detection(self.signature)
            self.output.insert(tk.END, f"Tampering detected: {not valid}\n")
        else:
            messagebox.showerror("Error", "No signature found.")

# Main execution
if __name__ == "__main__":
    print("Starting the Automotive Crypto Demo GUI...")
    root = tk.Tk()
    app = AutomotiveCryptoGUI(root)
    root.mainloop()