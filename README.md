### Secure File Transfer with RSA and Hashing

This project implements a secure file transfer system in Python that utilizes RSA encryption and hashing algorithms to ensure data confidentiality and integrity. The project includes functionality for generating RSA key pairs, encrypting and decrypting files, generating and verifying file hashes, and providing a simple user interface using Streamlit.

**Features**

**RSA Key Generation:** Generates and saves RSA public and private keys.

**File Encryption:** Encrypts a file using the recipient's public key.

**File Decryption:** Decrypts an encrypted file using the corresponding private key.

**Hashing:** Generates a hash (e.g., SHA-256) of the original file.

**Integrity Verification:** Verifies the integrity of the received file using the original hash.

**User Interface:** A simple UI created with Streamlit for interacting with the system.

**Requirements**
Python 3.6+
Streamlit
Cryptography library

**Installation**
1. Clone the repository:

`git clone https://github.com/your-username/secure-file-transfer.git
cd secure-file-transfer`

2. Create and activate a virtual environment (optional but recommended):

`python -m venv venv
source venv/bin/activate  # On Windows, use `venv\Scripts\activate`

3. Install the required packages:

`pip install -r requirements.txt`

**Usage**
1. Run the Streamlit application:
`streamlit run rsa_algorithm.py`

2. Open your browser and navigate to http://localhost:8501 to access the application.

3. Use the application to generate RSA keys, encrypt and decrypt files, and verify file integrity.

**File Structure**
rsa_algorithm.py: The only python file containing all the classes along with the the main function for running the Streamlit application.
message.txt: Test encryption message
requirements.txt: Lists the dependencies required for the project.

**Example**

**Key Generation**
The application generates RSA key pairs and saves them as public_key.pem and private_key.pem.

**File Encryption**
Upload a file to be encrypted. The encrypted file can be downloaded and stored securely.

**File Decryption**
Upload the private_key.pem and the encrypted file to decrypt and retrieve the original file.

**Hashing and Integrity Verification**
The application generates a SHA-256 hash of the original file. To verify integrity, upload the original hash and the file to be checked.

**Contributing**
Contributions are welcome! Please open an issue or submit a pull request for any improvements or bug fixes.

**License**
This project is licensed under the MIT License. See the LICENSE file for details.

**Acknowledgments**
Streamlit
Cryptography










