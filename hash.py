from Crypto.Hash import SHA1, SHA256

h256 = SHA256.new()
h256.update(b'hello')
print(h256.hexdigest())
# h = SHA1.new()
# h.update(b'Hello')
# print (h.hexdigest())
