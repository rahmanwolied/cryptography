from Crypto.Hash import CMAC
from Crypto.Cipher import AES

secret = b'Sixteen byte kew'
cobj = CMAC.new(secret, ciphermod=AES)
cobj.update(b'Hello')
print (cobj.hexdigest())
