import PyKCS11
import binascii
from cryptography import x509
from cryptography.hazmat.backends import default_backend

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
        print(cert.subject)
        print(cert.issuer)
private_key = session.findObjects([
(PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY),
(PyKCS11.CKA_LABEL, 'CITIZEN AUTHENTICATION KEY')
])[0]

public_key = session.findObjects([
(PyKCS11.CKA_CLASS, PyKCS11.CKO_PUBLIC_KEY),
(PyKCS11.CKA_LABEL, 'CITIZEN AUTHENTICATION CERTIFICATE')
])[0]
print(public_key)

# mechanism = PyKCS11.Mechanism(PyKCS11.CKM_SHA1_RSA_PKCS, None)
# text = b'text to sign'
# signature = bytes(session.sign(private_key, text, mechanism))
# print(signature)
# fi=open("a piada e a piada.txt","wb")
# fi.write(b'ola')
# fi.write(signature)