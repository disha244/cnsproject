from crypto import encrypt_message, decrypt_message


message = "This is my secret message."

print("===================================")
print(" SECURE MESSAGE ENCRYPTION TEST")
print("===================================")

print("\nOriginal message:")
print(message)


print("\nEncrypting message...")

encrypted_package = encrypt_message(message)

print("Encryption successful!")


print("\nEncrypted package:")

for key, value in encrypted_package.items():
    print(key, ":", value)


print("\nDecrypting message...")

decrypted_message = decrypt_message(
    encrypted_package
)

print("Decryption successful!")


print("\nDecrypted message:")
print(decrypted_message)


if message == decrypted_message:

    print("\n===================================")
    print(" TEST PASSED")
    print("===================================")

else:

    print("\nTEST FAILED")