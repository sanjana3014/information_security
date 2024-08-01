import streamlit as st
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
import hashlib
 
# 1. Key Generation
class KeyGeneration:
    def __init__(self):
        self.private_key = None
        self.public_key = None
 
    def generate_keys(self):
        # Generate a private key
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        # Generate the corresponding public key
        self.public_key = self.private_key.public_key()
 
    def save_keys(self):
        # Save the private key to a file
        with open("private_key.pem", "wb") as f:
            f.write(self.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
 
        # Save the public key to a file
        with open("public_key.pem", "wb") as f:
            f.write(self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
 
    def load_private_key(self, private_key_data):
        self.private_key = serialization.load_pem_private_key(
            private_key_data,
            password=None,
            backend=default_backend()
        )
 
    def load_public_key(self, public_key_data):
        self.public_key = serialization.load_pem_public_key(
            public_key_data,
            backend=default_backend()
        )
         
 
# 2. File Encryption
class FileEncryption:
    def __init__(self, public_key):
        self.public_key = public_key
 
    def encrypt_file(self, file_data):
        # Encrypt the file data
        encrypted_data = self.public_key.encrypt(
            file_data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return encrypted_data
 
 
 
# 3. File Decryption
class FileDecryption:
    def __init__(self, private_key):
        self.private_key = private_key
 
    def decrypt_file(self, encrypted_data):
        try:
            # Decrypt the encrypted data
            decrypted_data = self.private_key.decrypt(
                encrypted_data,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            return decrypted_data
        except Exception as e:
            st.error(f"Decryption failed: {e}")
            return None
 
 
 
# 4. Hashing
class Hashing:
    def generate_hash(self, file_data):
        # Generate a SHA-256 hash of the file data
        hasher = hashlib.sha256()
        hasher.update(file_data)
        return hasher.hexdigest()
  
 
# 5. Integrity Verification
class IntegrityVerification:
    def verify_integrity(self, original_hash, file_data):
        # Verify the integrity by comparing hashes
        current_hash = hashlib.sha256(file_data).hexdigest()
        return original_hash == current_hash
 
 
 
# 6. User Interface
def main():
    st.title("Secure File Transfer System")
 
    # Key Generation
    st.subheader("1. Key Generation")
    key_gen = KeyGeneration()
 
    if st.button("Generate RSA Key Pair"):
        key_gen.generate_keys()
        key_gen.save_keys()
        st.success("RSA key pair generated and saved in the same folder as this .py file.")
 
    # File Encryption
    st.subheader("2. File Encryption")
    public_key_file = st.file_uploader("Upload public key (.pem)", type=["pem"])
    file_to_encrypt = st.file_uploader("Upload file to encrypt", type=["txt", "pdf", "docx"])
 
    if public_key_file and file_to_encrypt and st.button("Encrypt"):
        public_key_data = public_key_file.read()
        key_gen.load_public_key(public_key_data)
        encrypter = FileEncryption(key_gen.public_key)
        file_data = file_to_encrypt.read()
        encrypted_data = encrypter.encrypt_file(file_data)
        st.download_button("Download Encrypted File", encrypted_data, file_name="encrypted_file.bin")
        st.success("File encrypted successfully.")
 
    # File Decryption
    st.subheader("3. File Decryption")
    private_key_file = st.file_uploader("Upload private key (.pem)", type=["pem"])
    file_to_decrypt = st.file_uploader("Upload encrypted file", type=["bin"])
 
    if private_key_file and file_to_decrypt and st.button("Decrypt"):
        private_key_data = private_key_file.read()
        key_gen.load_private_key(private_key_data)
        decrypter = FileDecryption(key_gen.private_key)
        encrypted_data = file_to_decrypt.read()
        decrypted_data = decrypter.decrypt_file(encrypted_data)
        if decrypted_data:
            st.download_button("Download Decrypted File", decrypted_data, file_name="decrypted_file.txt")
            st.success("File decrypted successfully.")
 
    # File Hashing
    st.subheader("4. File Hashing")
    file_to_hash = st.file_uploader("Upload original message file to hash", type=["txt", "pdf", "docx"])
 
    if file_to_hash and st.button("Generate Hash"):
        hasher = Hashing()
        file_data = file_to_hash.read()
        file_hash = hasher.generate_hash(file_data)
        st.text_area("File Hash", file_hash)
        st.success("File hash generated successfully.")
 
    # Integrity Verification
    st.subheader("5. Integrity Verification")
    original_hash = st.text_input("Enter original file hash:")
    file_to_verify = st.file_uploader("Upload decrypted file to verify", type=["txt", "pdf", "docx"])
 
    if original_hash and file_to_verify and st.button("Verify Integrity"):
        verifier = IntegrityVerification()
        file_data = file_to_verify.read()
        if verifier.verify_integrity(original_hash, file_data):
            st.success("The hash value of original message file and the received decrypted file match. Thus, file integrity is valid.")
        else:
            st.error("File integrity is compromised.")
 
if __name__ == "__main__":
    main()