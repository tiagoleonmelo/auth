from PyKCS11 import *
import binascii

lib = '/usr/local/lib/libpteidpkcs11.so'
pkcs11 = PyKCS11Lib()
pkcs11.load(lib)  # define environment variable PYKCS11LIB=YourPKCS11Lib

# get 1st slot
slot = pkcs11.getSlotList(tokenPresent=True)[0]

session = pkcs11.openSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION)
# session.login("1234")

# key ID in hex (has to be tuple, that's why trailing comma)
keyID = (0x22,)

# find public key and print modulus
pubKey = session.findObjects([(CKA_CLASS, CKO_PUBLIC_KEY), (CKA_ID, keyID)])[0]
modulus = session.getAttributeValue(pubKey, [CKA_MODULUS])[0]
print("\nmodulus: {}".format(binascii.hexlify(bytearray(modulus))))

# logout
session.logout()
session.closeSession()