import cv2
import requests

SERVER = "http://127.0.0.1:5000"

camera = cv2.VideoCapture(0)

detector = cv2.QRCodeDetector()

print("Laptop camera scanner started.")

while True:

    success, frame = camera.read()

    if not success:
        print("Camera could not open.")
        break

    data, points, _ = detector.detectAndDecode(frame)

    if data:

        message_id = data.strip()

        print("QR DETECTED:", message_id)

        try:

            requests.get(
                SERVER + "/message/" + message_id
            )

        except Exception as error:

            print("Error:", error)

        break

    cv2.imshow(
        "Laptop QR Scanner",
        frame
    )

    if cv2.waitKey(1) & 0xFF == ord("q"):
        break


camera.release()
cv2.destroyAllWindows()