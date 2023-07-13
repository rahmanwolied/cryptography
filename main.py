import json
from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA1, SHA256
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Hash import CMAC
from Crypto.Cipher import AES

def mac(msg):
    secret = b'Sixteen byte key'
    cobj = CMAC.new(secret, ciphermod=AES)
    cobj.update(msg.encode('utf-8'))
    print (cobj.hexdigest())

def signature_generate(msg):
    message = msg.encode('utf-8')
    key = RSA.import_key(open('private.pem').read())
    h = SHA256.new(message)
    signature = pkcs1_15.new(key).sign(h)
    print(signature)

def signature_verify(msg):
    msg = msg.encode('utf-8')
    key = RSA.import_key(open('public.pem').read())
    h = SHA256.new(msg)
    try:
        pkcs1_15.new(key).verify(h, signature)
        print ("The signature is valid.")
    except (ValueError, TypeError):
        print ("The signature is not valid.")

def signature():
    mode = input("Generate(g) or Verify(v): ")
    if mode == 'g':
        msg = input("Message: ")
        signature_generate(msg)
    elif mode == 'v':
        msg = input("Message: ")
        signature_verify(msg)
    

def SHA1_(msg):
    h = SHA1.new()
    h.update(msg.encode('utf-8'))
    print (h.hexdigest())

def SHA256_(msg):
    h256 = SHA256.new()
    h256.update(msg.encode('utf-8'))
    print(h256.hexdigest())

def HASH():
    mode = input("SHA1 (1) or SHA256 (256)")
    msg = input("msg: ")
    if mode == '1':
        SHA1_(msg)
    elif mode == '256':
        SHA256_(msg)

def RSA_encrypt(plaintext, key):
    plaintext = plaintext.encode('utf-8')

    cipher = PKCS1_OAEP.new(RSA.import_key(key))
    ciphertext = cipher.encrypt(plaintext)
    print(ciphertext)
    return ciphertext

def RSA_decrypt(ciphertext, key):
    cipher = PKCS1_OAEP.new(RSA.import_key(key))
    message = cipher.decrypt(ciphertext)

    print("Message: ", message)

    return message

def RSA_algo():
    feature = input("Encrypt(e) or Decrypt(d)? ")

    key = input("Key: ")

    if feature == 'e':
        plaintext = input("Plaintext: ")
        RSA_encrypt(plaintext, key)

    elif feature == 'd':
        ciphertext = input("Ciphertext: ")
        RSA_decrypt(ciphertext, key)

def AES_algo():
    mode = input("Choose mode: ECB/ CBC: ")
    if mode == "ECB":
        feature = input("Encrypt(e) or Decrypt(d)? ")

        key = input("Key: ")
        while len(key) != 16:
            key = input("Please type a 16 byte long key. ")

        if feature == 'e':
            plaintext = input("Plaintext: ")
            ECB_encrypt(plaintext, key)

        elif feature == 'd':
            ciphertext = input("Ciphertext: ")
            ECB_decrypt(ciphertext, key)

    elif mode == 'CBC':
        feature = input("Encrypt(e) or Decrypt(d)? ")

        key = input("Key: ")
        while len(key) != 16:
            key = input("Please type a 16 byte long key. ")

        if feature == 'e':
            plaintext = input("Plaintext: ")
            CBC_encrypt(plaintext, key)

        elif feature == 'd':
            ciphertext = input("Ciphertext: ")
            CBC_decrypt(ciphertext, key)


def ECB_encrypt(plaintext, key):
    plaintext = plaintext.encode("utf-8")
    key = key.encode("utf-8")
    cipher = AES.new(key, AES.MODE_ECB)
    ct_bytes = cipher.encrypt(pad(plaintext, AES.block_size))
    ct = b64encode(ct_bytes).decode('utf-8')
    print(ct)

def ECB_decrypt(ciphertext, key):
    ciphertext = b64decode(ciphertext)
    key = key.encode("utf-8")
    cipher = AES.new(key, AES.MODE_ECB)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    plaintext = b64encode(plaintext).decode('utf-8')
    print(plaintext)

def CBC_encrypt(plaintext, key):
    plaintext = plaintext.encode('utf-8')
    key = key.encode("utf-8")
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(plaintext, AES.block_size))
    iv = b64encode(cipher.iv).decode('utf-8')
    ct = b64encode(ct_bytes).decode('utf-8')
    result = json.dumps({'iv':iv, 'ciphertext':ct})
    cbc_out = open('cbc_out.json', 'w')
    cbc_out.write(result)
    print(result)

def CBC_decrypt(input, key):
    try:
        input = open(input, 'r')
        input = input.read()
        b64 = json.loads(input)
        iv = b64decode(b64['iv'])
        ct = b64decode(b64['ciphertext'])
        cipher = AES.new(key, AES.MODE_CBC, iv)
        pt = unpad(cipher.decrypt(ct), AES.block_size)
        print("The message was: ", pt)
    except (ValueError, KeyError):
        print("Incorrect decryption")

while True:
    print("1. AES Encryption/Decryption:\n2. RSA Encryption/Decryption:\n3. Hashing\n4. Digital Signature\n5. MAC Generation")
    algo = input("Please choose the algorithm: ")
    if algo == "1":
        AES_algo()
        break
    elif algo == '2':
        RSA_algo()
        break
    elif algo =='3':
        HASH()
        break
    elif algo == '4':
        signature()
        break
    elif algo == '5':
        msg = input("Message: ")
        mac(msg)
        break



































































































