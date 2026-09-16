import cv2
import sqlite3

from crypto import decrypt_message


# ==========================================
# GET MESSAGE FROM DATABASE
# ==========================================

def get_message(message_id):

    connection = sqlite3.connect(
        "database/messages.db"
    )

    cursor = connection.cursor()

    cursor.execute("""
        SELECT
            encrypted_aes_key,
            nonce,
            ciphertext,
            hash
        FROM messages
        WHERE id = ?
    """, (message_id,))

    result = cursor.fetchone()

    connection.close()

    if result is None:
        return None

    return {
        "encrypted_aes_key": result[0],
        "nonce": result[1],
        "ciphertext": result[2],
        "hash": result[3]
    }


# ==========================================
# QR SCANNER
# ==========================================

camera = cv2.VideoCapture(0)

detector = cv2.QRCodeDetector()

print("===================================")
print("       SECURE QR SCANNER")
print("===================================")
print("Show the QR code to the camera.")
print("Press Q to quit.")


while True:

    success, frame = camera.read()

    if not success:
        print("Camera error!")
        break

    # Detect QR
    data, points, _ = detector.detectAndDecode(frame)

    # Show camera
    cv2.imshow(
        "Secure QR Scanner",
        frame
    )

    # QR detected
    if data:

        print("\nQR CODE DETECTED!")

        message_id = data.strip()

        print("Message ID:", message_id)

        # Get encrypted data
        encrypted_package = get_message(
            message_id
        )

        if encrypted_package is None:

            print("\nERROR:")
            print("Message not found in database.")

            break

        print("Encrypted message found!")

        try:

            # Decrypt message
            message = decrypt_message(
                encrypted_package
            )

            print("\n===================================")
            print("          SECRET MESSAGE")
            print("===================================")

            print(message)

            print("===================================")

        except Exception as error:

            print("\nSECURITY ERROR:")
            print(error)

        break

    # Press Q
    if cv2.waitKey(1) & 0xFF == ord("q"):

        break


camera.release()

cv2.destroyAllWindows()