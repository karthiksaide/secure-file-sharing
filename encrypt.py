from cryptography.fernet import Fernet

# Generate key
key = Fernet.generate_key()

# Save key
with open("secret.key", "wb") as key_file:
    key_file.write(key)

f = Fernet(key)

# Create a test file
with open("test.txt", "wb") as file:
    file.write(b"Hello Karthik")

# Read file
with open("test.txt", "rb") as file:
    data = file.read()

# Encrypt
encrypted = f.encrypt(data)

# Save encrypted file
with open("test_encrypted.txt", "wb") as file:
    file.write(encrypted)

print("File Encrypted Successfully")