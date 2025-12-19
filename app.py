from flask import Flask, render_template, request, redirect, url_for, flash
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
import hashlib, base64

app = Flask(__name__)
app.secret_key = 'replace-with-a-secure-random-key-for-production'

# ---------- Crypto helpers (using PyCryptodome) ----------
def sha256_hash(text):
    return hashlib.sha256(text.encode()).hexdigest()

def generate_rsa_keys(bits=2048):
    key = RSA.generate(bits)
    return key.publickey(), key

def aes_encrypt(message, key):
    cipher = AES.new(key, AES.MODE_CBC)
    pad_len = 16 - (len(message) % 16)
    padded = message + (chr(pad_len) * pad_len)
    ciphertext = cipher.encrypt(padded.encode())
    return base64.b64encode(cipher.iv + ciphertext).decode()

def aes_decrypt(ciphertext_b64, key):
    data = base64.b64decode(ciphertext_b64)
    iv = data[:16]
    ciphertext = data[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    plaintext = cipher.decrypt(ciphertext).decode(errors='ignore')
    pad_len = ord(plaintext[-1])
    return plaintext[:-pad_len]

def rsa_encrypt_key(aes_key, public_key):
    cipher_rsa = PKCS1_OAEP.new(public_key)
    return base64.b64encode(cipher_rsa.encrypt(aes_key)).decode()

def rsa_decrypt_key(encrypted_aes_key_b64, private_key):
    cipher_rsa = PKCS1_OAEP.new(private_key)
    encrypted = base64.b64decode(encrypted_aes_key_b64)
    return cipher_rsa.decrypt(encrypted)

# ---------- Simple in-memory keypair for demo ----------
PUBKEY, PRIVKEY = generate_rsa_keys()

# ---------- Routes ----------
@app.route('/', methods=['GET'])
def index():
    return render_template('index.html')

@app.route('/encrypt', methods=['POST'])
def encrypt():
    message = request.form.get('message', '')
    if not message:
        flash('Masukkan pesan terlebih dahulu', 'danger')
        return redirect(url_for('index'))

    # Hash + combine
    msg_hash = sha256_hash(message)
    combined = message + '|' + msg_hash

    # create AES key and encrypt
    aes_key = get_random_bytes(16)
    ciphertext = aes_encrypt(combined, aes_key)

    # encrypt AES key with RSA public key (demo key)
    encrypted_key = rsa_encrypt_key(aes_key, PUBKEY)

    return render_template('result.html',
                           action='encrypt',
                           ciphertext=ciphertext,
                           encrypted_key=encrypted_key)

@app.route('/decrypt', methods=['POST'])
def decrypt():
    ciphertext = request.form.get('ciphertext', '')
    encrypted_key = request.form.get('encrypted_key', '')
    if not ciphertext or not encrypted_key:
        flash('Masukkan ciphertext dan encrypted AES key', 'danger')
        return redirect(url_for('index'))
    try:
        aes_key = rsa_decrypt_key(encrypted_key, PRIVKEY)
        decrypted = aes_decrypt(ciphertext, aes_key)
        if '|' in decrypted:
            msg, orig_hash = decrypted.split('|', 1)
            valid = (sha256_hash(msg) == orig_hash)
        else:
            msg = decrypted
            valid = False
        return render_template('result.html',
                               action='decrypt',
                               message=msg,
                               integrity=valid)
    except Exception as e:
        flash('Gagal dekripsi: ' + str(e), 'danger')
        return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
