from flask import Flask, request, send_file
import os

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

app = Flask(__name__)

UPLOAD_FOLDER = "uploads"
ENCRYPTED_FOLDER = "encrypted"

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(ENCRYPTED_FOLDER, exist_ok=True)


# ---------------- RSA KEY GENERATION ----------------
def generate_keys():
    if not os.path.exists("private.pem"):
        key = RSA.generate(2048)

        with open("private.pem", "wb") as f:
            f.write(key.export_key())

        with open("public.pem", "wb") as f:
            f.write(key.publickey().export_key())


generate_keys()


# ---------------- AES FILE ENCRYPTION ----------------
def encrypt_file(file_path):

    aes_key = get_random_bytes(32)

    cipher = AES.new(aes_key, AES.MODE_EAX)

    with open(file_path, "rb") as f:
        data = f.read()

    ciphertext, tag = cipher.encrypt_and_digest(data)

    enc_file = file_path + ".enc"

    with open(enc_file, "wb") as f:
        f.write(cipher.nonce)
        f.write(tag)
        f.write(ciphertext)

    return enc_file, aes_key


# ---------------- RSA AES KEY ENCRYPT ----------------
def encrypt_aes_key(aes_key):

    with open("public.pem", "rb") as f:
        public_key = RSA.import_key(f.read())

    cipher_rsa = PKCS1_OAEP.new(public_key)

    encrypted_key = cipher_rsa.encrypt(aes_key)

    with open("aes_key.enc", "wb") as f:
        f.write(encrypted_key)


# ---------------- RSA AES KEY DECRYPT ----------------
def decrypt_aes_key():

    with open("private.pem", "rb") as f:
        private_key = RSA.import_key(f.read())

    cipher_rsa = PKCS1_OAEP.new(private_key)

    with open("aes_key.enc", "rb") as f:
        encrypted_key = f.read()

    aes_key = cipher_rsa.decrypt(encrypted_key)

    return aes_key


# ---------------- FILE DECRYPTION ----------------
def decrypt_file(enc_file):

    aes_key = decrypt_aes_key()

    with open(enc_file, "rb") as f:
        nonce = f.read(16)
        tag = f.read(16)
        ciphertext = f.read()

    cipher = AES.new(aes_key, AES.MODE_EAX, nonce)

    data = cipher.decrypt_and_verify(ciphertext, tag)

    output_file = "decrypted_file"

    with open(output_file, "wb") as f:
        f.write(data)

    return output_file


# ---------------- UPLOAD ROUTE ----------------
@app.route("/upload", methods=["POST"])
def upload():

    file = request.files["file"]

    path = os.path.join(UPLOAD_FOLDER, file.filename)

    file.save(path)

    enc_file, aes_key = encrypt_file(path)

    encrypt_aes_key(aes_key)

    return "File uploaded and encrypted successfully"


# ---------------- DOWNLOAD ROUTE ----------------
@app.route("/download")
def download():

    enc_file = os.path.join(UPLOAD_FOLDER, os.listdir(UPLOAD_FOLDER)[0] + ".enc")

    decrypted = decrypt_file(enc_file)

    return send_file(decrypted, as_attachment=True)


# ---------------- RUN ----------------
if __name__ == "__main__":

    port = int(os.environ.get("PORT", 10000))

    app.run(host="0.0.0.0", port=port)