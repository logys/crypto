from Crypto.Cipher import AES
import sys
import Padding
import hashlib
import base64

original_message = "Hola mundo"
key = "llavemagica"
salt = "241fa86763b85341"

if (len(sys.argv)>1):
    original_message = str(sys.argv[1])
if (len(sys.argv)>2):
    key = str(sys.argv[2])
if (len(sys.argv)>3):
    salt = str(sys.argv[3])

print ("Mensaje:", original_message)
print ("Key:", key)
print ("Salt:", salt)

paded_original_message = Padding.appendPadding(original_message)

def getKeyIv(key, salt):
    ascii_key = key.encode('ascii')
    hex_salt = bytearray.fromhex(salt)
    mdf = hashlib.md5(ascii_key+hex_salt)
    keyiv = mdf.digest()
    tmp = [keyiv]
    while len(tmp) < 32 + 16:
            tmp.append( hashlib.md5(tmp[-1] + ascii_key + hex_salt).digest() )
            keyiv += tmp[-1]  # append the last byte
    key = keyiv[:32]
    iv = keyiv[32:32+16]
    return key, iv

def encryptAes(msg, key, aes_mode, salt):
    key, initial_vector = getKeyIv(key, salt)
    cipher_object = AES.new(key, aes_mode, initial_vector)
    return cipher_object.encrypt(msg.encode())

ciphered_text = encryptAes(paded_original_message, key, AES.MODE_CBC, salt)

ctext = b'Salted__' + bytearray.fromhex(salt) + ciphered_text 

print ("\nCipher (CBC) - Base64:\t", base64.b64encode(bytearray(ctext)).decode())
print ("\nCipher (CBC) - Hex:\t",ctext.hex())
print ("Cipher in binary:\t",ctext)

def decrypt(ciphered_text, key, aes_mode, salt):
    key,iv=getKeyIv(key,salt)
    encobj = AES.new(key,aes_mode,iv)
    return(encobj.decrypt(ciphered_text))

plaintext = decrypt(ciphered_text, key, AES.MODE_CBC, salt)
print ("\nDecrypted (Before unpad):\t", plaintext)
plaintext = Padding.removePadding(plaintext.decode(),mode='CMS')
print ("\nDecrypted:\t"+plaintext)
