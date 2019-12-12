from PyKCS11 import *
import binascii
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import ExtensionOID, NameOID

lib = '/usr/local/lib/libpteidpkcs11.so'
pkcs11 = PyKCS11.PyKCS11Lib()
pkcs11.load(lib)
slots = pkcs11.getSlotList()

for slot in slots:
    print(pkcs11.getTokenInfo(slot))
    print("#######################")

all_attr = list(PyKCS11.CKA.keys())
#Filter attributes
all_attr = [e for e in all_attr if isinstance(e, int)]
session = pkcs11.openSession(slot)
for obj in session.findObjects():
    # Get object attributes
    attr = session.getAttributeValue(obj, all_attr)
    # Create dictionary with attributes
    attr = dict(zip(map(PyKCS11.CKA.get, all_attr), attr))
    #print(attr['CKA_CLASS'])
    if attr['CKA_CERTIFICATE_TYPE']!=None:
        cert=x509.load_der_x509_certificate((bytes(attr['CKA_VALUE'])),default_backend())
        #print('Label: ', attr['CKA_LABEL'],cert)
        print(cert.subject.get_attributes_for_oid(NameOID.SERIAL_NUMBER)[0].value)
        print(cert.issuer)


# private_key = session.findObjects([
# (CKA_CLASS, CKO_PRIVATE_KEY),
# (CKA_LABEL, 'CITIZEN AUTHENTICATION KEY')
# ])[0]

# "Hello world" in hex
toSign = "48656c6c6f20776f726c640d0a"

# find private key and compute signature
# privKey = session.findObjects([(CKA_CLASS, CKO_PRIVATE_KEY), (CKA_LABEL, 'CITIZEN AUTHENTICATION KEY')])[0]
# signature = session.sign(privKey, binascii.unhexlify(toSign), Mechanism(CKM_SHA1_RSA_PKCS, None))
# print("\nsignature: {}".format(binascii.hexlify(bytearray(signature))))

# # find public key and verify signature
# pubKey = session.findObjects([(CKA_CLASS, CKO_PUBLIC_KEY)])[0]
# result = session.verify(pubKey, binascii.unhexlify(toSign), signature, Mechanism(CKM_SHA1_RSA_PKCS, None))
# print("\nVerified:", result)

# print(pubKey)

# mechanism = PyKCS11.Mechanism(PyKCS11.CKM_SHA1_RSA_PKCS, None)
# text = b'text to sign'
# signature = bytes(session.sign(private_key, text, mechanism))

# print(signature)
# fi=open("a piada e a piada.txt","wb")
# fi.write(b'ola')
# fi.write(signature)