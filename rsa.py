from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP


message = b'You can attack now!'
key = RSA.generate(2048)

private_key = key.export_key()
file_out = open("private.pem", "wb")
file_out.write(private_key)
file_out.close()

public_key = key.publickey().export_key()
file_out = open("public.pem", "wb")
file_out.write(public_key)
file_out.close()

cipher = PKCS1_OAEP.new(RSA.import_key(public_key))
ciphertext = cipher.encrypt(message)

print(ciphertext)

key = RSA.importKey(private_key)
cipher = PKCS1_OAEP.new(key)
message = cipher.decrypt(ciphertext)

print("Message: ", message)