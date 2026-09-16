import qrcode

img = qrcode.make("HELLO QR TEST")

img.save("test_qr.png")

print("Test QR created!")