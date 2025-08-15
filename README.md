Encrypted Cloud Sync Tool
A Python-based data encryption and cloud synchronization tool designed to safeguard sensitive files before uploading them to cloud storage. This project demonstrates practical cybersecurity skills, secure key management, and API integration with Google Drive for automated encrypted backups.
Features
•	AES Encryption: Uses Fernet symmetric encryption to encrypt and decrypt files securely.
•	Key Management: Implements a Key Encryption Key (KEK) & Master Key system for secure handling of file encryption keys.
•	Automatic Key Rotation: Supports scheduled rotation of master keys to improve security over time.
•	Google Drive Integration: Securely uploads encrypted files to Google Drive and allows downloading and decryption when needed.
•	Selective Sync: Only encrypts and uploads files that haven’t been uploaded before.
•	Secure Configuration: Sensitive files like API credentials are excluded via .gitignore.

How It Works
1.	The tool monitors an input folder for new files.
2.	Each file is encrypted locally using a unique file key, which is itself encrypted with the master key.
3.	The encrypted files are uploaded to Google Drive using the Drive API.
4.	Encrypted files can be downloaded and decrypted on demand using the master key.
5.	The master key can be rotated periodically to enhance security.

Setup & Installation
1.	Clone the repository (without secrets):
git clone https://github.com/medhakhosla17/encrytion_tool.git
cd encrytion_tool
2.	Install dependencies:
pip install -r requirements.txt
3.	Set up input/output directories (optional, defaults exist):
•	input_files/ – place files to be encrypted.
•	temp_encrypted/ – temporary storage for encrypted files.
•	decrypted_files/ – decrypted files will be saved here.
4.	Add Google API credentials:
•	Place your client_secret.json in the project folder
Usage
Run the tool:
python sync_encrypt.py
Options in the tool:
1.	Encrypt and upload new files automatically.
2.	Decrypt a file from Google Drive on demand.
3.	Exit the program safely when done.
Security & Best Practices
•	Sensitive files such as client_secret.json and token.pickle are excluded from Git using .gitignore.
•	Encryption keys are never stored in plaintext.
•	Master key rotation is implemented to ensure long-term security.
•	Integration with Google Drive API is handled securely, ensuring safe cloud storage.
Technologies & Tools Used
•	Python 3 – programming language
•	Cryptography – Fernet for symmetric encryption
•	Google Drive API – cloud integration
•	JSON / Pickle – configuration and metadata storage
•	Schedule & Threading – periodic key rotation
•	OS & File Handling – for secure local file management
Future Enhancements
•	Support for multiple cloud providers (AWS S3, Azure, etc.)
•	Logging and alerting for file uploads and downloads
•	GUI interface for non-technical users
Project Purpose
This project demonstrates practical cybersecurity skills in encryption, key management, and secure API integration. It is designed to safeguard sensitive data and showcase applied knowledge for real-world security use cases.

