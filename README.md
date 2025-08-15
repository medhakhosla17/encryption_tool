Encrypted Cloud Sync Tool
A Python-based data encryption and cloud synchronization tool designed to safeguard sensitive files before uploading them to cloud storage. This project demonstrates practical cybersecurity skills, secure key management, and API integration with Google Drive for automated encrypted backups.
<br>
<br>
Features
1. AES Encryption: Uses Fernet symmetric encryption to encrypt and decrypt files securely.
2. Key Management: Implements a Key Encryption Key (KEK) & Master Key system for secure handling of file encryption keys.
3. Automatic Key Rotation: Supports scheduled rotation of master keys to improve security over time.
4. Google Drive Integration: Securely uploads encrypted files to Google Drive and allows downloading and decryption when needed.
5. Selective Sync: Only encrypts and uploads files that haven’t been uploaded before.
6. Secure Configuration: Sensitive files like API credentials are excluded via .gitignore.
<br>
How It Works <br>
1.	The tool monitors an input folder for new files. <br>
2.	Each file is encrypted locally using a unique file key, which is itself encrypted with the master key.<br>
3.	The encrypted files are uploaded to Google Drive using the Drive API.
4.	Encrypted files can be downloaded and decrypted on demand using the master key.<br>
5.	The master key can be rotated periodically to enhance security.
<br>
<br>
Setup & Installation
1.	Clone the repository (without secrets): git clone https://github.com/medhakhosla17/encrytion_tool.git cd encrytion_tool <br>
2.	Install dependencies: pip install -r requirements.txt <br>
3.	Set up input/output directories (optional, defaults exist):
•	input_files/ – place files to be encrypted.
•	temp_encrypted/ – temporary storage for encrypted files.
•	decrypted_files/ – decrypted files will be saved here. <br>
4.	Add Google API credentials: Place your client_secret.json in the project folder <br>

<br>
Usage <br>
Run the tool:
python sync_encrypt.py
Options in the tool: <br>
1.	Encrypt and upload new files automatically. <br>
2.	Decrypt a file from Google Drive on demand. <br>
3.	Exit the program safely when done. <br>

<br>
Security & Best Practices <br>
•	Sensitive files such as client_secret.json and token.pickle are excluded from Git using .gitignore. <br>
•	Encryption keys are never stored in plaintext. <br>
•	Master key rotation is implemented to ensure long-term security. <br>
•	Integration with Google Drive API is handled securely, ensuring safe cloud storage. <br>

<br>
Technologies & Tools Used <br>
•	Python 3 – programming language <br>
•	Cryptography – Fernet for symmetric encryption <br>
•	Google Drive API – cloud integration <br>
•	JSON / Pickle – configuration and metadata storage <br>
•	Schedule & Threading – periodic key rotation <br>
•	OS & File Handling – for secure local file management <br>

<br>
Future Enhancements <br>
•	Support for multiple cloud providers (AWS S3, Azure, etc.)<br>
•	Logging and alerting for file uploads and downloads<br>
•	GUI interface for non-technical users<br>

<br>
Project Purpose<br>
This project demonstrates practical cybersecurity skills in encryption, key management, and secure API integration. It is designed to safeguard sensitive data and showcase applied knowledge for real-world security use cases. kj

