from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PrivateFormat,
    PublicFormat,
    NoEncryption,
    load_pem_private_key,
    load_pem_public_key
)

import hashlib
import os
import base64


# ============================================================
# KEY FOLDER
# ============================================================

KEY_FOLDER = "keys"

PRIVATE_KEY_FILE = os.path.join(
    KEY_FOLDER,
    "private_key.pem"
)

PUBLIC_KEY_FILE = os.path.join(
    KEY_FOLDER,
    "public_key.pem"
)


# ============================================================
# GENERATE RSA KEYS
# ============================================================

def generate_rsa_keys():

    os.makedirs(KEY_FOLDER, exist_ok=True)

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    public_key = private_key.public_key()

    with open(PRIVATE_KEY_FILE, "wb") as file:

        file.write(
            private_key.private_bytes(
                encoding=Encoding.PEM,
                format=PrivateFormat.PKCS8,
                encryption_algorithm=NoEncryption()
            )
        )

    with open(PUBLIC_KEY_FILE, "wb") as file:

        file.write(
            public_key.public_bytes(
                encoding=Encoding.PEM,
                format=PublicFormat.SubjectPublicKeyInfo
            )
        )

    print("RSA keys generated successfully.")


# ============================================================
# LOAD PRIVATE KEY
# ============================================================

def load_private_key():

    if not os.path.exists(PRIVATE_KEY_FILE):

        raise FileNotFoundError(
            "Private RSA key not found. "
            "Generate RSA keys first."
        )

    with open(PRIVATE_KEY_FILE, "rb") as file:

        return load_pem_private_key(
            file.read(),
            password=None
        )


# ============================================================
# LOAD PUBLIC KEY
# ============================================================

def load_public_key():

    if not os.path.exists(PUBLIC_KEY_FILE):

        raise FileNotFoundError(
            "Public RSA key not found. "
            "Generate RSA keys first."
        )

    with open(PUBLIC_KEY_FILE, "rb") as file:

        return load_pem_public_key(
            file.read()
        )


# ============================================================
# ENCRYPT MESSAGE
# ============================================================

def encrypt_message(message):

    # --------------------------------------------------------
    # AES-256 KEY
    # --------------------------------------------------------

    aes_key = AESGCM.generate_key(
        bit_length=256
    )


    # --------------------------------------------------------
    # AES-GCM NONCE
    # --------------------------------------------------------

    nonce = os.urandom(12)


    # --------------------------------------------------------
    # AES-256-GCM ENCRYPTION
    # --------------------------------------------------------

    aes = AESGCM(aes_key)

    ciphertext = aes.encrypt(
        nonce,
        message.encode("utf-8"),
        None
    )


    # --------------------------------------------------------
    # RSA-2048-OAEP
    # Encrypt AES key
    # --------------------------------------------------------

    public_key = load_public_key()

    encrypted_aes_key = public_key.encrypt(

        aes_key,

        padding.OAEP(

            mgf=padding.MGF1(
                algorithm=hashes.SHA256()
            ),

            algorithm=hashes.SHA256(),

            label=None
        )
    )


    # --------------------------------------------------------
    # BLAKE2b INTEGRITY HASH
    # --------------------------------------------------------

    hash_value = hashlib.blake2b(

        encrypted_aes_key +
        nonce +
        ciphertext,

        digest_size=64
    ).hexdigest()


    # --------------------------------------------------------
    # PACKAGE
    # --------------------------------------------------------

    return {

        "encrypted_aes_key":
            base64.b64encode(
                encrypted_aes_key
            ).decode("utf-8"),

        "nonce":
            base64.b64encode(
                nonce
            ).decode("utf-8"),

        "ciphertext":
            base64.b64encode(
                ciphertext
            ).decode("utf-8"),

        "hash":
            hash_value
    }


# ============================================================
# DECRYPT MESSAGE
# ============================================================

def decrypt_message(package):

    # --------------------------------------------------------
    # CHECK REQUIRED DATA
    # --------------------------------------------------------

    required_fields = [
        "encrypted_aes_key",
        "nonce",
        "ciphertext",
        "hash"
    ]

    for field in required_fields:

        if field not in package:

            raise ValueError(
                f"Missing encrypted field: {field}"
            )


    # --------------------------------------------------------
    # BASE64 DECODE
    # --------------------------------------------------------

    try:

        encrypted_aes_key = base64.b64decode(
            package["encrypted_aes_key"]
        )

        nonce = base64.b64decode(
            package["nonce"]
        )

        ciphertext = base64.b64decode(
            package["ciphertext"]
        )

    except Exception as error:

        raise ValueError(
            "Invalid encrypted data: "
            + str(error)
        )


    received_hash = package["hash"]


    # --------------------------------------------------------
    # VERIFY BLAKE2b
    # --------------------------------------------------------

    calculated_hash = hashlib.blake2b(

        encrypted_aes_key +
        nonce +
        ciphertext,

        digest_size=64
    ).hexdigest()


    if calculated_hash != received_hash:

        raise ValueError(
            "BLAKE2b integrity verification failed."
        )


    # --------------------------------------------------------
    # RSA-2048-OAEP DECRYPT AES KEY
    # --------------------------------------------------------

    private_key = load_private_key()

    try:

        aes_key = private_key.decrypt(

            encrypted_aes_key,

            padding.OAEP(

                mgf=padding.MGF1(
                    algorithm=hashes.SHA256()
                ),

                algorithm=hashes.SHA256(),

                label=None
            )
        )

    except Exception as error:

        raise ValueError(
            "RSA-2048-OAEP decryption failed: "
            + str(error)
        )


    # --------------------------------------------------------
    # AES-256-GCM DECRYPT
    # --------------------------------------------------------

    try:

        aes = AESGCM(aes_key)

        plaintext = aes.decrypt(

            nonce,

            ciphertext,

            None
        )

    except Exception as error:

        raise ValueError(
            "AES-256-GCM decryption failed: "
            + str(error)
        )


    # --------------------------------------------------------
    # RETURN ORIGINAL MESSAGE
    # --------------------------------------------------------

    try:

        return plaintext.decode("utf-8")

    except Exception as error:

        raise ValueError(
            "Could not decode decrypted message: "
            + str(error)
        )