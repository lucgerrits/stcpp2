#https://stackoverflow.com/a/3964285

import binascii
filename = 'tests/roland.png'
with open(filename, 'rb') as f:
    content = f.read()
print(binascii.hexlify(content))
print(len(binascii.hexlify(content)))
