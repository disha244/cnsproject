import qrcode
import uuid
import sqlite3

from crypto import encrypt_message


# 1. Ask for secret message
message = input("Enter your secret message: ")

if not message.strip():
    print("Message cannot be empty.")
    exit()


# 2. Encrypt the message
encrypted = encrypt_message(message)


# 3. Create a unique ID
message_id = "MSG-" + uuid.uuid4().hex[:6].upper()


# 4. Store encrypted data in database
connection = sqlite3.connect("database/messages.db")

cursor = connection.cursor()

cursor.execute("""
INSERT INTO messages
(id, encrypted_aes_key, nonce, ciphertext, hash)
VALUES (?, ?, ?, ?, ?)
""", (
    message_id,
    encrypted["encrypted_aes_key"],
    encrypted["nonce"],
    encrypted["ciphertext"],
    encrypted["hash"]
))

connection.commit()
connection.close()


# 5. Create QR containing ONLY the ID
qr = qrcode.QRCode(
    version=1,
    box_size=20,
    border=10
)

qr.add_data(message_id)
qr.make(fit=True)

qr_image = qr.make_image()

qr_image.save("secret_qr.png")


print()
print("===================================")
print("QR CREATED SUCCESSFULLY!")
print("===================================")
print("Message ID:", message_id)
print("QR file: secret_qr.png")