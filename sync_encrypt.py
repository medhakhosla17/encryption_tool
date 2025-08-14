# import os
# import json
# import time
# import threading
# from cryptography.fernet import Fernet
# import schedule
# from googleapiclient.discovery import build
# from googleapiclient.http import MediaFileUpload, MediaIoBaseDownload
# from google_auth_oauthlib.flow import InstalledAppFlow
# from google.auth.transport.requests import Request
# import pickle
# import io

# # ----------------- Config -----------------
# INPUT_DIR = "input_files"
# SYNC_DIR = "temp_encrypted"
# KEYS_DIR = "keys"
# FILE_KEYS_METADATA = os.path.join(KEYS_DIR, "file_keys_metadata.json")
# MASTER_KEY_PATH = os.path.join(KEYS_DIR, "master.key")
# ROTATION_METADATA = os.path.join(KEYS_DIR, "rotation_metadata.json")
# ROTATION_INTERVAL_SECONDS = 60 * 60 * 24 * 7  # 7 days
# CREDS_PATH = "client_secret_607229622392-2qssir0ulfg5datq1iaui9rcr0as8fcu.apps.googleusercontent.com.json"
# SCOPES = ['https://www.googleapis.com/auth/drive.file']

# # ----------------- Helpers -----------------
# def ensure_directories():
#     for d in [INPUT_DIR, SYNC_DIR, KEYS_DIR]:
#         if not os.path.exists(d):
#             os.makedirs(d)

# def load_json(path, default=None):
#     if not os.path.exists(path):
#         return default if default is not None else {}
#     with open(path, "r") as f:
#         return json.load(f)

# def save_json(path, data):
#     with open(path, "w") as f:
#         json.dump(data, f, indent=4)

# # ----------------- Google Drive -----------------
# def google_drive_service():
#     creds = None
#     token_path = 'token.pickle'
#     if os.path.exists(token_path):
#         with open(token_path, 'rb') as token:
#             creds = pickle.load(token)
#     if not creds or not creds.valid:
#         if creds and creds.expired and creds.refresh_token:
#             creds.refresh(Request())
#         else:
#             flow = InstalledAppFlow.from_client_secrets_file(CREDS_PATH, SCOPES)
#             creds = flow.run_local_server(port=0)
#         with open(token_path, 'wb') as token:
#             pickle.dump(creds, token)
#     return build('drive', 'v3', credentials=creds)

# def upload_file_to_drive(service, local_path, drive_filename):
#     media = MediaFileUpload(local_path, resumable=True)
#     file_metadata = {'name': drive_filename}
#     file = service.files().create(body=file_metadata, media_body=media, fields='id').execute()
#     print(f"Uploaded {local_path} to Google Drive as {drive_filename}")
#     return file.get('id')

# def download_file_from_drive(service, drive_filename, local_path):
#     results = service.files().list(q=f"name='{drive_filename}'", fields="files(id, name)").execute()
#     items = results.get('files', [])
#     if not items:
#         print(f"{drive_filename} not found in Google Drive")
#         return False
#     file_id = items[0]['id']
#     request = service.files().get_media(fileId=file_id)
#     fh = open(local_path, 'wb')
#     downloader = MediaIoBaseDownload(fh, request)
#     done = False
#     while not done:
#         status, done = downloader.next_chunk()
#     fh.close()
#     print(f"Downloaded {drive_filename} from Google Drive to {local_path}")
#     return True

# # ----------------- Key Management -----------------
# def generate_master_key():
#     key = Fernet.generate_key()
#     with open(MASTER_KEY_PATH, "wb") as f:
#         f.write(key)
#     print(f"Master key generated and saved: {MASTER_KEY_PATH}")
#     return key

# def load_master_key():
#     if not os.path.exists(MASTER_KEY_PATH):
#         return generate_master_key()
#     with open(MASTER_KEY_PATH, "rb") as f:
#         return f.read()

# # ----------------- Encryption / Decryption -----------------
# def encrypt_file(filepath, master_fernet, drive_service):
#     filename = os.path.basename(filepath)
#     encrypted_filename = filename + ".enc"

#     # Load metadata
#     metadata = load_json(FILE_KEYS_METADATA, {})

#     # Check if file already encrypted locally
#     if encrypted_filename in metadata:
#         print(f"Skipping {filename}, already encrypted according to metadata.")
#         return encrypted_filename

#     # Check if file already exists on Google Drive
#     results = drive_service.files().list(q=f"name='{encrypted_filename}'", fields="files(id, name)").execute()
#     if results.get('files', []):
#         print(f"Skipping {filename}, already exists on Google Drive.")
#         return encrypted_filename

#     # Generate file key & encrypt
#     file_key = Fernet.generate_key()
#     file_fernet = Fernet(file_key)
#     with open(filepath, "rb") as f:
#         data = f.read()
#     encrypted_data = file_fernet.encrypt(data)

#     # Save encrypted file locally (temp folder)
#     if not os.path.exists(SYNC_DIR):
#         os.makedirs(SYNC_DIR)
#     encrypted_path = os.path.join(SYNC_DIR, encrypted_filename)
#     with open(encrypted_path, "wb") as f:
#         f.write(encrypted_data)

#     # Wrap key and update metadata
#     wrapped_key = master_fernet.encrypt(file_key)
#     metadata[encrypted_filename] = wrapped_key.decode()
#     save_json(FILE_KEYS_METADATA, metadata)

#     # Upload to Google Drive
#     upload_file_to_drive(drive_service, encrypted_path, encrypted_filename)
#     return encrypted_filename

# def decrypt_file(encrypted_filename, master_fernet, drive_service):
#     metadata = load_json(FILE_KEYS_METADATA, {})
#     wrapped_key_str = metadata.get(encrypted_filename)
#     if not wrapped_key_str:
#         print(f"No wrapped key found for {encrypted_filename}")
#         return

#     # Download encrypted file first
#     local_enc_path = os.path.join(SYNC_DIR, encrypted_filename)
#     if not os.path.exists(local_enc_path):
#         success = download_file_from_drive(drive_service, encrypted_filename, local_enc_path)
#         if not success:
#             return

#     try:
#         file_key = master_fernet.decrypt(wrapped_key_str.encode())
#     except Exception as e:
#         print(f"Error unwrapping key for {encrypted_filename}: {e}")
#         return

#     file_fernet = Fernet(file_key)
#     with open(local_enc_path, "rb") as f:
#         encrypted_data = f.read()

#     try:
#         decrypted_data = file_fernet.decrypt(encrypted_data)
#     except Exception as e:
#         print(f"Error decrypting file {encrypted_filename}: {e}")
#         return

#     output_dir = "decrypted_files"
#     if not os.path.exists(output_dir):
#         os.makedirs(output_dir)
#     output_path = os.path.join(output_dir, encrypted_filename[:-4])
#     with open(output_path, "wb") as f:
#         f.write(decrypted_data)
#     print(f"Decrypted {encrypted_filename} -> {output_path}")

# # ----------------- Key Rotation -----------------
# def rotate_master_key():
#     print("\n--- Automatic Master Key Rotation Triggered ---")
#     old_master_key = load_master_key()
#     old_master_fernet = Fernet(old_master_key)
#     new_master_key = Fernet.generate_key()
#     new_master_fernet = Fernet(new_master_key)

#     with open(MASTER_KEY_PATH, "wb") as f:
#         f.write(new_master_key)
#     print(f"New master key saved: {MASTER_KEY_PATH}")

#     metadata = load_json(FILE_KEYS_METADATA, {})
#     updated_metadata = {}
#     for enc_filename, wrapped_key_str in metadata.items():
#         try:
#             file_key = old_master_fernet.decrypt(wrapped_key_str.encode())
#             new_wrapped_key = new_master_fernet.encrypt(file_key)
#             updated_metadata[enc_filename] = new_wrapped_key.decode()
#         except Exception as e:
#             print(f"Error rotating key for {enc_filename}: {e}")
#     save_json(FILE_KEYS_METADATA, updated_metadata)

#     rotation_meta = load_json(ROTATION_METADATA, {"last_rotation": 0})
#     rotation_meta["last_rotation"] = int(time.time())
#     save_json(ROTATION_METADATA, rotation_meta)
#     print("--- Master Key Rotation Complete ---\n")

# # ----------------- Scheduler -----------------
# def scheduled_key_rotation():
#     rotate_master_key()

# def run_scheduler():
#     while True:
#         schedule.run_pending()
#         time.sleep(1)

# # ----------------- Main -----------------
# def main():
#     ensure_directories()
#     drive_service = google_drive_service()
#     rotation_meta = load_json(ROTATION_METADATA, {"last_rotation": 0})
#     now = int(time.time())

#     if now - rotation_meta.get("last_rotation", 0) >= ROTATION_INTERVAL_SECONDS:
#         scheduled_key_rotation()
#     else:
#         print(f"Time since last rotation: {now - rotation_meta.get('last_rotation', 0)} seconds. No rotation needed yet.")

#     master_key = load_master_key()
#     master_fernet = Fernet(master_key)

#     print("Encrypting all new files in input folder and uploading to Google Drive...")
#     metadata = load_json(FILE_KEYS_METADATA, {})
#     for filename in os.listdir(INPUT_DIR):
#         filepath = os.path.join(INPUT_DIR, filename)
#         if os.path.isfile(filepath):
#             encrypt_file(filepath, master_fernet, drive_service)

#     # Schedule automatic rotation every 7 days
#     schedule.every(7).days.do(scheduled_key_rotation)
#     scheduler_thread = threading.Thread(target=run_scheduler, daemon=True)
#     scheduler_thread.start()

#     # Interactive menu
#     while True:
#         print("\nOptions:")
#         print("1 - Decrypt a file from Google Drive")
#         print("n - Exit")
#         choice = input("Enter your choice: ").strip().lower()
#         if choice == "1":
#             enc_filename = input("Enter encrypted filename (with .enc): ").strip()
#             decrypt_file(enc_filename, master_fernet, drive_service)
#         elif choice == "n":
#             print("Exiting.")
#             break
#         else:
#             print("Invalid choice. Try again.")

# if __name__ == "__main__":
#     main()

# new code starts here

import os
import json
import time
import threading
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64
import schedule
from googleapiclient.discovery import build
from googleapiclient.http import MediaFileUpload, MediaIoBaseDownload
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
import pickle
import io
import getpass

# ----------------- Config -----------------
INPUT_DIR = "input_files"
SYNC_DIR = "temp_encrypted"
KEYS_DIR = "keys"
FILE_KEYS_METADATA = os.path.join(KEYS_DIR, "file_keys_metadata.json")
MASTER_KEY_ENC_PATH = os.path.join(KEYS_DIR, "master.key.enc")
ROTATION_METADATA = os.path.join(KEYS_DIR, "rotation_metadata.json")
ROTATION_INTERVAL_SECONDS = 60 * 60 * 24 * 7  # 7 days
CREDS_PATH = "client_secret_607229622392-2qssir0ulfg5datq1iaui9rcr0as8fcu.apps.googleusercontent.com.json"
SCOPES = ['https://www.googleapis.com/auth/drive.file']

# ----------------- Helpers -----------------
def ensure_directories():
    for d in [INPUT_DIR, SYNC_DIR, KEYS_DIR]:
        if not os.path.exists(d):
            os.makedirs(d)

def load_json(path, default=None):
    if not os.path.exists(path):
        return default if default is not None else {}
    with open(path, "r") as f:
        return json.load(f)

def save_json(path, data):
    with open(path, "w") as f:
        json.dump(data, f, indent=4)

# ----------------- Google Drive -----------------
def google_drive_service():
    creds = None
    token_path = 'token.pickle'
    if os.path.exists(token_path):
        with open(token_path, 'rb') as token:
            creds = pickle.load(token)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(CREDS_PATH, SCOPES)
            creds = flow.run_local_server(port=0)
        with open(token_path, 'wb') as token:
            pickle.dump(creds, token)
    return build('drive', 'v3', credentials=creds)

def upload_file_to_drive(service, local_path, drive_filename):
    media = MediaFileUpload(local_path, resumable=True)
    file_metadata = {'name': drive_filename}
    file = service.files().create(body=file_metadata, media_body=media, fields='id').execute()
    print(f"Uploaded {local_path} to Google Drive as {drive_filename}")
    return file.get('id')

def download_file_from_drive(service, drive_filename, local_path):
    results = service.files().list(q=f"name='{drive_filename}'", fields="files(id, name)").execute()
    items = results.get('files', [])
    if not items:
        print(f"{drive_filename} not found in Google Drive")
        return False
    file_id = items[0]['id']
    request = service.files().get_media(fileId=file_id)
    fh = open(local_path, 'wb')
    downloader = MediaIoBaseDownload(fh, request)
    done = False
    while not done:
        status, done = downloader.next_chunk()
    fh.close()
    print(f"Downloaded {drive_filename} from Google Drive to {local_path}")
    return True

# ----------------- KEK & Master Key Management -----------------
def derive_key_from_password(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def create_master_key(kek: str) -> bytes:
    # generate master key
    master_key = Fernet.generate_key()
    # generate random salt for KEK derivation
    salt = os.urandom(16)
    kek_key = derive_key_from_password(kek, salt)
    fernet = Fernet(kek_key)
    enc_master = fernet.encrypt(master_key)
    # save salt + encrypted master key
    with open(MASTER_KEY_ENC_PATH, "wb") as f:
        f.write(salt + enc_master)
    print(f"Master key generated and encrypted with KEK: {MASTER_KEY_ENC_PATH}")
    return master_key

def load_master_key(kek: str) -> bytes:
    if not os.path.exists(MASTER_KEY_ENC_PATH):
        return create_master_key(kek)
    with open(MASTER_KEY_ENC_PATH, "rb") as f:
        data = f.read()
        salt = data[:16]
        enc_master = data[16:]
    kek_key = derive_key_from_password(kek, salt)
    fernet = Fernet(kek_key)
    master_key = fernet.decrypt(enc_master)
    return master_key

# ----------------- Encryption / Decryption -----------------
def encrypt_file(filepath, master_fernet, drive_service):
    filename = os.path.basename(filepath)
    encrypted_filename = filename + ".enc"
    metadata = load_json(FILE_KEYS_METADATA, {})

    if encrypted_filename in metadata:
        print(f"Skipping {filename}, already encrypted according to metadata.")
        return encrypted_filename

    results = drive_service.files().list(q=f"name='{encrypted_filename}'", fields="files(id, name)").execute()
    if results.get('files', []):
        print(f"Skipping {filename}, already exists on Google Drive.")
        return encrypted_filename

    file_key = Fernet.generate_key()
    file_fernet = Fernet(file_key)
    with open(filepath, "rb") as f:
        data = f.read()
    encrypted_data = file_fernet.encrypt(data)

    if not os.path.exists(SYNC_DIR):
        os.makedirs(SYNC_DIR)
    encrypted_path = os.path.join(SYNC_DIR, encrypted_filename)
    with open(encrypted_path, "wb") as f:
        f.write(encrypted_data)

    wrapped_key = master_fernet.encrypt(file_key)
    metadata[encrypted_filename] = wrapped_key.decode()
    save_json(FILE_KEYS_METADATA, metadata)

    upload_file_to_drive(drive_service, encrypted_path, encrypted_filename)
    return encrypted_filename

def decrypt_file(encrypted_filename, master_fernet, drive_service):
    metadata = load_json(FILE_KEYS_METADATA, {})
    wrapped_key_str = metadata.get(encrypted_filename)
    if not wrapped_key_str:
        print(f"No wrapped key found for {encrypted_filename}")
        return

    local_enc_path = os.path.join(SYNC_DIR, encrypted_filename)
    if not os.path.exists(local_enc_path):
        success = download_file_from_drive(drive_service, encrypted_filename, local_enc_path)
        if not success:
            return

    try:
        file_key = master_fernet.decrypt(wrapped_key_str.encode())
    except Exception as e:
        print(f"Error unwrapping key for {encrypted_filename}: {e}")
        return

    file_fernet = Fernet(file_key)
    with open(local_enc_path, "rb") as f:
        encrypted_data = f.read()

    try:
        decrypted_data = file_fernet.decrypt(encrypted_data)
    except Exception as e:
        print(f"Error decrypting file {encrypted_filename}: {e}")
        return

    output_dir = "decrypted_files"
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    output_path = os.path.join(output_dir, encrypted_filename[:-4])
    with open(output_path, "wb") as f:
        f.write(decrypted_data)
    print(f"Decrypted {encrypted_filename} -> {output_path}")

# ----------------- Key Rotation -----------------
def rotate_master_key(master_fernet):
    print("\n--- Automatic Master Key Rotation Triggered ---")
    old_master_key = master_fernet
    new_master_key = Fernet.generate_key()
    master_fernet_new = Fernet(new_master_key)

    # save new master key encrypted with KEK
    kek = getpass.getpass("Enter your KEK (password) for encrypting master key: ")
    create_master_key(kek)

    metadata = load_json(FILE_KEYS_METADATA, {})
    updated_metadata = {}
    for enc_filename, wrapped_key_str in metadata.items():
        try:
            file_key = old_master_key.decrypt(wrapped_key_str.encode())
            new_wrapped_key = master_fernet_new.encrypt(file_key)
            updated_metadata[enc_filename] = new_wrapped_key.decode()
        except Exception as e:
            print(f"Error rotating key for {enc_filename}: {e}")
    save_json(FILE_KEYS_METADATA, updated_metadata)

    rotation_meta = load_json(ROTATION_METADATA, {"last_rotation": 0})
    rotation_meta["last_rotation"] = int(time.time())
    save_json(ROTATION_METADATA, rotation_meta)
    print("--- Master Key Rotation Complete ---\n")
    return master_fernet_new

# ----------------- Scheduler -----------------
def scheduled_key_rotation(master_fernet):
    return rotate_master_key(master_fernet)

def run_scheduler():
    while True:
        schedule.run_pending()
        time.sleep(1)

# ----------------- Main -----------------
def main():
    ensure_directories()
    drive_service = google_drive_service()

    # Ask user for KEK password at start
    kek = getpass.getpass("Enter your KEK (password) for master key: ")
    master_key_bytes = load_master_key(kek)
    master_fernet = Fernet(master_key_bytes)

    rotation_meta = load_json(ROTATION_METADATA, {"last_rotation": 0})
    now = int(time.time())
    if now - rotation_meta.get("last_rotation", 0) >= ROTATION_INTERVAL_SECONDS:
        master_fernet = scheduled_key_rotation(master_fernet)
    else:
        print(f"Time since last rotation: {now - rotation_meta.get('last_rotation', 0)} seconds. No rotation needed yet.")

    print("Encrypting all new files in input folder and uploading to Google Drive...")
    metadata = load_json(FILE_KEYS_METADATA, {})
    for filename in os.listdir(INPUT_DIR):
        filepath = os.path.join(INPUT_DIR, filename)
        if os.path.isfile(filepath):
            encrypt_file(filepath, master_fernet, drive_service)

    schedule.every(7).days.do(lambda: scheduled_key_rotation(master_fernet))
    scheduler_thread = threading.Thread(target=run_scheduler, daemon=True)
    scheduler_thread.start()

    while True:
        print("\nOptions:")
        print("1 - Decrypt a file from Google Drive")
        print("n - Exit")
        choice = input("Enter your choice: ").strip().lower()
        if choice == "1":
            enc_filename = input("Enter encrypted filename (with .enc): ").strip()
            decrypt_file(enc_filename, master_fernet, drive_service)
        elif choice == "n":
            print("Exiting.")
            break
        else:
            print("Invalid choice. Try again.")

if __name__ == "__main__":
    main() 
