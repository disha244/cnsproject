import sqlite3
import os

os.makedirs("database", exist_ok=True)

connection = sqlite3.connect("database/messages.db")

cursor = connection.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS messages (
    id TEXT PRIMARY KEY,
    encrypted_aes_key TEXT NOT NULL,
    nonce TEXT NOT NULL,
    ciphertext TEXT NOT NULL,
    hash TEXT NOT NULL
)
""")

connection.commit()
connection.close()

print("Database created successfully!")