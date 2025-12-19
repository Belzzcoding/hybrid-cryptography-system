HYBRID FLASK APP
=================

A small Flask demo implementing a hybrid cryptosystem:
- AES-CBC for message confidentiality (using PyCryptodome)
- RSA OAEP to encrypt the AES key
- SHA-256 for integrity checking

Files included:
- app.py              : Main Flask application
- templates/index.html: Main UI (encrypt/decrypt forms)
- templates/result.html: Result display
- requirements.txt    : Dependencies

How to run (locally):
1. Create and activate a Python virtual environment (recommended)
   python -m venv venv
   source venv/bin/activate   # Linux/macOS
   venv\Scripts\activate    # Windows (PowerShell)

2. Install dependencies
   pip install -r requirements.txt

3. Run the Flask app
   python app.py

4. Open http://127.0.0.1:5000 in your browser

Notes:
- This project is for educational/demo purpose only. Do NOT use the demo keys or code for real production use.
- The RSA keypair is generated in-memory when the server starts; it is not persisted.
