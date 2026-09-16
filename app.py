from flask import Flask, request
import qrcode
import uuid
import sqlite3
import os
import cv2
import threading
import html
 
from crypto import encrypt_message, decrypt_message, generate_rsa_keys, PRIVATE_KEY_FILE, PUBLIC_KEY_FILE
 
 
app = Flask(__name__)
 
# ============================================================
# SECURITY PIN
# ============================================================
 
SECURITY_PIN = "2468"
 
 
# ============================================================
# CAMERA VARIABLES
# ============================================================
 
camera_running = False
camera_message = None
camera_thread = None
 
 
# ============================================================
# DATABASE
# ============================================================
 
def setup_database():
 
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
 
    print("Database ready.")
 
 
# ============================================================
# RSA KEYS
# ============================================================
 
def setup_rsa_keys():
 
    if not os.path.exists(PRIVATE_KEY_FILE) or not os.path.exists(PUBLIC_KEY_FILE):
 
        print("RSA keys not found. Generating new RSA keypair...")
        generate_rsa_keys()
 
    else:
 
        print("RSA keys already exist. Skipping generation.")
 
 
# ============================================================
# EXTRACT MESSAGE ID
# ============================================================
 
def extract_message_id(qr_data):
 
    qr_data = qr_data.strip()
 
    if "/message/" in qr_data:
        return qr_data.split("/message/")[-1].strip()
 
    return qr_data
 
 
# ============================================================
# HOME
# ============================================================
 
@app.route("/")
def home():
 
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Secure QR Secret Message</title>
 
        <meta name="viewport"
              content="width=device-width, initial-scale=1.0">
 
        <style>
            body {
                font-family: Arial;
                text-align: center;
                margin: 30px;
            }
 
            .box {
                max-width: 600px;
                margin: auto;
                padding: 30px;
                border: 2px solid #ddd;
                border-radius: 15px;
            }
 
            button {
                padding: 14px 25px;
                font-size: 17px;
                cursor: pointer;
            }
        </style>
    </head>
 
    <body>
 
        <div class="box">
 
            <h1>🔐 Secure QR Secret Message System</h1>
 
            <p>
                AES-256-GCM + RSA-2048-OAEP + BLAKE2b
            </p>
 
            <p>🔑 PIN Protected</p>
 
            <hr>
 
            <a href="/send">
                <button>🔐 Send Secret Message</button>
            </a>
 
            <br><br>
 
            <a href="/receive">
                <button>📷 Receive Secret Message</button>
            </a>
 
        </div>
 
    </body>
    </html>
    """
 
 
# ============================================================
# SEND MESSAGE
# ============================================================
 
@app.route("/send", methods=["GET", "POST"])
def send():
 
    if request.method == "GET":
 
        return """
        <!DOCTYPE html>
        <html>
 
        <head>
            <title>Send Secret Message</title>
 
            <meta name="viewport"
                  content="width=device-width, initial-scale=1.0">
 
            <style>
                body {
                    font-family: Arial;
                    text-align: center;
                    margin: 30px;
                }
 
                .box {
                    max-width: 600px;
                    margin: auto;
                    padding: 30px;
                    border: 2px solid #ddd;
                    border-radius: 15px;
                }
 
                textarea {
                    width: 90%;
                    padding: 12px;
                    font-size: 17px;
                }
 
                button {
                    padding: 14px 25px;
                    font-size: 17px;
                }
            </style>
        </head>
 
        <body>
 
        <div class="box">
 
            <h1>🔐 Send Secret Message</h1>
 
            <form action="/send" method="POST" id="sendForm">
 
                <textarea
                    name="message"
                    rows="8"
                    placeholder="Enter your secret message"
                    required
                ></textarea>
 
                <br><br>
 
                <button type="submit" id="sendButton">
                    🔐 Encrypt & Generate QR
                </button>
 
            </form>
 
            <p id="sendStatus"></p>
 
            <script>
                document.getElementById("sendForm").addEventListener("submit", function() {
                    var message = document.querySelector('textarea[name="message"]').value.trim();
 
                    if (message === "") {
                        return;
                    }
 
                    document.getElementById("sendButton").disabled = true;
                    document.getElementById("sendButton").innerHTML = "🔐 Encrypting...";
                    document.getElementById("sendStatus").innerHTML = "Please wait...";
                });
            </script>
 
            <br>
 
            <a href="/">🏠 Home</a>
 
        </div>
 
        </body>
        </html>
        """
 
 
    message = request.form.get("message", "").strip()
 
    if not message:
        return "Message cannot be empty."
 
 
    # ENCRYPT
 
    try:
 
        encrypted = encrypt_message(message)
 
    except Exception as error:
 
        return f"""
        <h2>❌ Encryption Failed</h2>
        <p>{html.escape(str(error))}</p>
        <a href="/send">Try Again</a>
        """
 
 
    # MESSAGE ID
 
    message_id = "MSG-" + uuid.uuid4().hex[:6].upper()
 
 
    # DATABASE
 
    try:
 
        connection = sqlite3.connect("database/messages.db")
        cursor = connection.cursor()
 
        cursor.execute("""
            INSERT INTO messages
            (
                id,
                encrypted_aes_key,
                nonce,
                ciphertext,
                hash
            )
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
 
    except Exception as error:
 
        return f"""
        <h2>❌ Database Error</h2>
        <p>{html.escape(str(error))}</p>
        <a href="/send">Try Again</a>
        """
 
 
    # CREATE QR
 
    try:
 
        os.makedirs("static", exist_ok=True)
 
        qr = qrcode.QRCode(
            version=1,
            box_size=15,
            border=8
        )
 
        qr_url = (
            request.host_url.rstrip("/")
            + "/message/"
            + message_id
        )
 
        qr.add_data(qr_url)
        qr.make(fit=True)
 
        qr_image = qr.make_image()
 
        filename = message_id + ".png"
 
        qr_path = os.path.join(
            "static",
            filename
        )
 
        qr_image.save(qr_path)
 
    except Exception as error:
 
        return f"""
        <h2>❌ QR Generation Failed</h2>
        <p>{html.escape(str(error))}</p>
        <a href="/send">Try Again</a>
        """
 
 
    print("======================================")
    print("QR GENERATED")
    print("Message ID:", message_id)
    print("QR saved:", qr_path)
    print("======================================")
 
 
    return f"""
    <!DOCTYPE html>
    <html>
 
    <head>
 
        <title>QR Generated</title>
 
        <meta name="viewport"
              content="width=device-width, initial-scale=1.0">
 
        <style>
 
            body {{
                font-family: Arial;
                text-align: center;
                margin: 30px;
            }}
 
            .box {{
                max-width: 600px;
                margin: auto;
                padding: 30px;
                border: 2px solid #ddd;
                border-radius: 15px;
            }}
 
            img {{
                width: 300px;
                max-width: 90%;
            }}
 
            button {{
                padding: 14px 25px;
                font-size: 17px;
            }}
 
        </style>
 
    </head>
 
    <body>
 
    <div class="box">
 
        <h1>✅ QR Generated</h1>
 
        <h2>{html.escape(message_id)}</h2>
 
        <img src="/static/{filename}">
 
        <p>🔐 Message encrypted successfully.</p>
 
        <p>🔑 Security PIN protection enabled.</p>
 
        <hr>
 
        <p>
            Scan this QR code using your phone.
        </p>
 
        <br>
 
        <a href="/receive">
            <button>📷 Receive Message</button>
        </a>
 
        <br><br>
 
        <a href="/">🏠 Home</a>
 
    </div>
 
    </body>
    </html>
    """
 
 
# ============================================================
# RECEIVE
# ============================================================
 
@app.route("/receive")
def receive():
 
    return """
    <!DOCTYPE html>
    <html>
 
    <head>
 
        <title>Receive Secret Message</title>
 
        <meta name="viewport"
              content="width=device-width, initial-scale=1.0">
 
        <style>
 
            body {
                font-family: Arial;
                text-align: center;
                margin: 30px;
            }
 
            .box {
                max-width: 600px;
                margin: auto;
                padding: 30px;
                border: 2px solid #ddd;
                border-radius: 15px;
            }
 
            button {
                padding: 14px 25px;
                font-size: 17px;
            }
 
        </style>
 
    </head>
 
    <body>
 
    <div class="box">
 
        <h1>🔐 Receive Secret Message</h1>
 
        <h3>📁 Scan QR From File</h3>
 
        <form
            action="/scan-image"
            method="POST"
            enctype="multipart/form-data"
        >
 
            <input
                type="file"
                name="qr_image"
                accept="image/*"
                required
            >
 
            <br><br>
 
            <button type="submit">
                🔍 Scan QR Image
            </button>
 
        </form>
 
        <hr>
 
        <h3>📷 Laptop Camera</h3>
 
        <a href="/start-camera">
 
            <button>
                📷 Start Laptop Camera
            </button>
 
        </a>
 
        <br><br>
 
        <a href="/">🏠 Home</a>
 
    </div>
 
    </body>
    </html>
    """
 
 
# ============================================================
# MESSAGE FROM QR
# ============================================================
 
@app.route("/message/<message_id>")
def message_from_qr(message_id):
 
    message_id = message_id.strip()
 
    print("======================================")
    print("QR LINK OPENED")
    print("Message ID:", message_id)
    print("======================================")
 
    return show_pin_page(message_id)
 
 
# ============================================================
# PIN PAGE
# ============================================================
 
def show_pin_page(message_id):
 
    connection = sqlite3.connect("database/messages.db")
    cursor = connection.cursor()
 
    cursor.execute(
        "SELECT id FROM messages WHERE id = ?",
        (message_id,)
    )
 
    result = cursor.fetchone()
 
    connection.close()
 
 
    if result is None:
 
        return """
        <!DOCTYPE html>
        <html>
 
        <body>
 
        <center>
 
            <h1>❌ Message Not Found</h1>
 
            <a href="/receive">Try Again</a>
 
        </center>
 
        </body>
        </html>
        """
 
 
    safe_id = html.escape(message_id)
 
 
    return f"""
    <!DOCTYPE html>
 
    <html>
 
    <head>
 
        <title>Security Verification</title>
 
        <meta
            name="viewport"
            content="width=device-width, initial-scale=1.0"
        >
 
        <style>
 
            body {{
                font-family: Arial;
                text-align: center;
                margin: 0;
                padding: 25px 15px;
            }}
 
            .box {{
                max-width: 500px;
                margin: auto;
                padding: 30px 20px;
                border: 2px solid #ddd;
                border-radius: 15px;
            }}
 
            input[type="password"] {{
                width: 200px;
                padding: 15px;
                font-size: 22px;
                text-align: center;
                letter-spacing: 6px;
                box-sizing: border-box;
            }}
 
            button {{
                width: 220px;
                padding: 15px;
                font-size: 18px;
                cursor: pointer;
            }}
 
            #status {{
                margin-top: 15px;
                font-size: 16px;
            }}
 
        </style>
 
    </head>
 
    <body>
 
    <div class="box">
 
        <h1>🔐 Security Verification</h1>
 
        <p>✅ QR Code Detected</p>
 
        <p>Message ID:</p>
 
        <h3>{safe_id}</h3>
 
        <hr>
 
        <h3>🔑 Enter Security PIN</h3>
 
        <p>
            Enter your 4-digit PIN.
        </p>
 
 
        <!-- IMPORTANT FORM -->
 
        <form
            id="verifyForm"
            action="/verify-pin"
            method="POST"
        >
 
            <input
                type="password"
                id="pin"
                name="pin"
                maxlength="4"
                minlength="4"
                inputmode="numeric"
                pattern="[0-9]{{4}}"
                autocomplete="off"
                placeholder="PIN"
                required
            >
 
            <input
                type="hidden"
                name="message_id"
                value="{safe_id}"
            >
 
            <br><br>
 
            <button
                type="submit"
                id="verifyButton"
            >
                🔓 Verify & Decrypt
            </button>
 
        </form>
 
        <div id="status"></div>
 
        <br>
 
        <a href="/receive">
            ← Back
        </a>
 
    </div>
 
 
    <script>
 
        document.getElementById("verifyForm").addEventListener(
            "submit",
            async function(event) {{
 
                event.preventDefault();
 
                const button =
                    document.getElementById("verifyButton");
 
                const status =
                    document.getElementById("status");
 
                const pin =
                    document.getElementById("pin").value;
 
 
                if (pin.length !== 4) {{
 
                    status.innerHTML =
                        "❌ Please enter the 4-digit PIN.";
 
                    return;
 
                }}
 
 
                button.disabled = true;
 
                button.innerHTML =
                    "🔓 Verifying...";
 
                status.innerHTML =
                    "Please wait...";
 
 
                try {{
 
                    const formData =
                        new FormData(this);
 
 
                    const response =
                        await fetch(
                            "/verify-pin",
                            {{
                                method: "POST",
                                body: formData
                            }}
                        );
 
 
                    const result =
                        await response.text();
 
 
                    if (!response.ok) {{
 
                        throw new Error(
                            "Server error: " +
                            response.status
                        );
 
                    }}
 
 
                    document.open();
 
                    document.write(result);
 
                    document.close();
 
 
                }} catch (error) {{
 
                    status.innerHTML =
                        "❌ Verification failed. Please try again.";
 
                    button.disabled = false;
 
                    button.innerHTML =
                        "🔓 Verify & Decrypt";
 
                    console.log(error);
 
                }}
 
            }}
 
        );
 
    </script>
 
    </body>
 
    </html>
    """
 
 
# ============================================================
# VERIFY PIN AND DECRYPT
# ============================================================
 
@app.route("/verify-pin", methods=["POST"])
def verify_pin_route():
 
    print("======================================")
    print("VERIFY & DECRYPT CLICKED")
    print("======================================")
 
 
    message_id = request.form.get(
        "message_id",
        ""
    ).strip()
 
    pin = request.form.get(
        "pin",
        ""
    ).strip()
 
 
    print("Message ID:", message_id)
    print("PIN received:", "*" * len(pin))
 
 
    # --------------------------------------------------------
    # CHECK INPUT
    # --------------------------------------------------------
 
    if not message_id:
 
        return """
        <center>
 
            <h1>❌ Message ID Missing</h1>
 
            <a href="/receive">Try Again</a>
 
        </center>
        """
 
 
    if not pin:
 
        return """
        <center>
 
            <h1>❌ PIN Missing</h1>
 
            <a href="/receive">Try Again</a>
 
        </center>
        """
 
 
    # --------------------------------------------------------
    # CHECK PIN
    # --------------------------------------------------------
 
    if pin != SECURITY_PIN:
 
        print("❌ INCORRECT PIN")
 
        return """
        <!DOCTYPE html>
 
        <html>
 
        <head>
 
            <meta
                name="viewport"
                content="width=device-width, initial-scale=1.0"
            >
 
            <title>Incorrect PIN</title>
 
        </head>
 
        <body>
 
        <center>
 
            <h1>❌ Incorrect PIN</h1>
 
            <p>
                The security PIN is incorrect.
            </p>
 
            <br>
 
            <a href="/message/""" + html.escape(message_id) + """">
                🔄 Try Again
            </a>
 
        </center>
 
        </body>
 
        </html>
        """
 
 
    print("✅ PIN CORRECT")
 
 
    # --------------------------------------------------------
    # GET ENCRYPTED MESSAGE
    # --------------------------------------------------------
 
    try:
 
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
 
 
    except Exception as error:
 
        print("❌ DATABASE ERROR:", error)
 
        return f"""
        <center>
 
            <h1>❌ Database Error</h1>
 
            <p>{html.escape(str(error))}</p>
 
            <a href="/receive">Try Again</a>
 
        </center>
        """
 
 
    # --------------------------------------------------------
    # MESSAGE NOT FOUND
    # --------------------------------------------------------
 
    if result is None:
 
        print("❌ MESSAGE NOT FOUND")
 
        return f"""
        <center>
 
            <h1>❌ Message Not Found</h1>
 
            <p>
                Message ID:
                {html.escape(message_id)}
            </p>
 
            <a href="/receive">Try Again</a>
 
        </center>
        """
 
 
    print("✅ ENCRYPTED MESSAGE FOUND")
 
 
    # --------------------------------------------------------
    # CREATE PACKAGE
    # --------------------------------------------------------
 
    encrypted_package = {
 
        "encrypted_aes_key": result[0],
 
        "nonce": result[1],
 
        "ciphertext": result[2],
 
        "hash": result[3]
 
    }
 
 
    # --------------------------------------------------------
    # DECRYPT
    # --------------------------------------------------------
 
    try:
 
        print("🔐 STARTING DECRYPTION")
 
        decrypted_message = decrypt_message(
            encrypted_package
        )
 
        print("✅ DECRYPTION SUCCESSFUL")
        print("SECRET MESSAGE:", decrypted_message)
 
 
    except Exception as error:
 
        print("❌ DECRYPTION FAILED")
        print("Error:", repr(error))
 
        return f"""
        <!DOCTYPE html>
 
        <html>
 
        <head>
 
            <meta
                name="viewport"
                content="width=device-width, initial-scale=1.0"
            >
 
        </head>
 
        <body>
 
        <center>
 
            <h1>❌ Decryption Failed</h1>
 
            <p>
                The PIN was correct, but
                decryption failed.
            </p>
 
            <p>
                {html.escape(str(error))}
            </p>
 
            <br>
 
            <a href="/receive">
                Try Again
            </a>
 
        </center>
 
        </body>
 
        </html>
        """
 
 
    # --------------------------------------------------------
    # DISPLAY SECRET MESSAGE
    # --------------------------------------------------------
 
    safe_message = html.escape(
        str(decrypted_message)
    )
 
 
    return f"""
    <!DOCTYPE html>
 
    <html>
 
    <head>
 
        <title>Secret Message</title>
 
        <meta
            name="viewport"
            content="width=device-width, initial-scale=1.0"
        >
 
        <style>
 
            body {{
                font-family: Arial;
                text-align: center;
                margin: 20px;
                padding: 10px;
                background: #f5f5f5;
            }}
 
            .box {{
                max-width: 700px;
                margin: auto;
                padding: 30px;
                background: white;
                border: 2px solid #ddd;
                border-radius: 15px;
            }}
 
            .secret {{
                margin: 25px auto;
                padding: 25px;
                font-size: 24px;
                border: 2px solid #ddd;
                border-radius: 12px;
                word-wrap: break-word;
                overflow-wrap: break-word;
                white-space: pre-wrap;
            }}
 
            .success {{
                font-size: 17px;
            }}
 
            button {{
                padding: 12px 25px;
                font-size: 16px;
            }}
 
        </style>
 
    </head>
 
    <body>
 
    <div class="box">
 
        <h1>🔓 SECRET MESSAGE</h1>
 
        <hr>
 
        <p class="success">
            ✅ QR Code Verified
        </p>
 
        <p class="success">
            ✅ Security PIN Verified
        </p>
 
        <p class="success">
            ✅ BLAKE2b Verification Successful
        </p>
 
        <p class="success">
            ✅ RSA-2048-OAEP Decryption Successful
        </p>
 
        <p class="success">
            ✅ AES-256-GCM Decryption Successful
        </p>
 
        <hr>
 
        <h2>Your Secret Message</h2>
 
        <div class="secret">
            {safe_message}
        </div>
 
        <hr>
 
        <p>
            🔐 Secret message decrypted successfully.
        </p>
 
        <br>
 
        <a href="/receive">
 
            <button>
                📷 Scan Another QR
            </button>
 
        </a>
 
        <br><br>
 
        <a href="/">
            🏠 Home
        </a>
 
    </div>
 
    </body>
 
    </html>
    """
 
 
# ============================================================
# SCAN IMAGE
# ============================================================
 
@app.route("/scan-image", methods=["POST"])
def scan_image():
 
    import numpy as np
 
    uploaded_file = request.files.get("qr_image")
 
    if uploaded_file is None:
 
        return """
        <h2>❌ No QR image selected.</h2>
        <a href="/receive">Try Again</a>
        """
 
 
    image_bytes = uploaded_file.read()
 
    image_array = np.frombuffer(
        image_bytes,
        np.uint8
    )
 
    image = cv2.imdecode(
        image_array,
        cv2.IMREAD_COLOR
    )
 
 
    if image is None:
 
        return """
        <h2>❌ Could not read image.</h2>
        <a href="/receive">Try Again</a>
        """
 
 
    detector = cv2.QRCodeDetector()
 
    data, points, _ = detector.detectAndDecode(
        image
    )
 
 
    if not data:
 
        return """
        <center>
 
            <h1>❌ QR Code Not Detected</h1>
 
            <a href="/receive">
                Try Again
            </a>
 
        </center>
        """
 
 
    message_id = extract_message_id(data)
 
    print("QR detected:", data)
    print("Message ID:", message_id)
 
    return show_pin_page(message_id)
 
 
# ============================================================
# CAMERA
# ============================================================
 
def camera_scanner():
 
    global camera_running
    global camera_message
 
    camera = cv2.VideoCapture(
        0,
        cv2.CAP_DSHOW
    )
 
    detector = cv2.QRCodeDetector()
 
    camera_running = True
    camera_message = None
 
    print("======================================")
    print("LAPTOP CAMERA STARTED")
    print("Show QR code from mobile.")
    print("======================================")
 
 
    while camera_running:
 
        success, frame = camera.read()
 
        if not success:
 
            print("Could not read camera.")
            break
 
 
        data, points, _ = detector.detectAndDecode(
            frame
        )
 
 
        if data:
 
            message_id = extract_message_id(data)
 
            print("======================================")
            print("QR DETECTED")
            print("Message ID:", message_id)
            print("======================================")
 
            camera_message = message_id
 
            break
 
 
        cv2.imshow(
            "Secure QR Scanner - Show QR From Mobile",
            frame
        )
 
 
        if cv2.waitKey(1) & 0xFF == ord("q"):
 
            break
 
 
    camera.release()
 
    cv2.destroyAllWindows()
 
    camera_running = False
 
 
@app.route("/start-camera")
def start_camera():
 
    global camera_thread
    global camera_message
    global camera_running
 
 
    if not camera_running:
 
        camera_message = None
 
        camera_thread = threading.Thread(
            target=camera_scanner
        )
 
        camera_thread.daemon = True
 
        camera_thread.start()
 
 
    return """
    <!DOCTYPE html>
 
    <html>
 
    <head>
 
        <meta
            http-equiv="refresh"
            content="2;url=/camera-result"
        >
 
        <meta
            name="viewport"
            content="width=device-width, initial-scale=1.0"
        >
 
    </head>
 
    <body>
 
    <center>
 
        <h1>📷 Laptop Camera Started</h1>
 
        <p>
            Show the QR code from your phone
            to the laptop camera.
        </p>
 
        <p>
            Waiting for QR code...
        </p>
 
    </center>
 
    </body>
 
    </html>
    """
 
 
@app.route("/camera-result")
def camera_result():
 
    if camera_message is None:
 
        return """
        <!DOCTYPE html>
 
        <html>
 
        <head>
 
            <meta
                http-equiv="refresh"
                content="2"
            >
 
        </head>
 
        <body>
 
        <center>
 
            <h1>📷 Scanning...</h1>
 
            <p>
                Show QR code from mobile.
            </p>
 
        </center>
 
        </body>
 
        </html>
        """
 
 
    return f"""
    <!DOCTYPE html>
 
    <html>
 
    <head>
 
        <meta
            http-equiv="refresh"
            content="1;url=/message/{html.escape(camera_message)}"
        >
 
    </head>
 
    <body>
 
    <center>
 
        <h1>✅ QR Detected</h1>
 
        <p>
            Opening security verification...
        </p>
 
    </center>
 
    </body>
 
    </html>
    """
 
 
# ============================================================
# START SERVER
# ============================================================
 
if __name__ == "__main__":
 
    setup_database()
    setup_rsa_keys()
 
    app.run(
        host="0.0.0.0",
        port=5000,
        debug=True,
        use_reloader=False
    )
 