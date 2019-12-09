from cryptography import x509
from cryptography.hazmat.backends import default_backend
from datetime import datetime
import sys
import os


def get_serial_number(filename):

    cert_file = open(filename, "rb")
    content = cert_file.read()

    cert = x509.load_pem_x509_certificate(content, default_backend())
    cert_file.close()

    return cert.serial_number


def check_validity(filename):

    cert_file = open(filename, "rb")
    content = cert_file.read()

    cert = x509.load_pem_x509_certificate(content, default_backend())

    start = cert.not_valid_before
    end = cert.not_valid_after
    curr = datetime.now()


    cert_file.close()

    return start < curr < end

def check_validity_content(content):

    cert = x509.load_pem_x509_certificate(content, default_backend())

    start = cert.not_valid_before
    end = cert.not_valid_after
    curr = datetime.now()

    return start < curr < end



def store_cert(filename, d):
    cert_file = open(filename, "rb")
    content = cert_file.read()

    cert = x509.load_pem_x509_certificate(content, default_backend())
    d[cert.subject] = cert

    cert_file.close()


def get_local_certs(dir, d):
    # Check if dir or file
    # if file check if pem
    # if pem check if valid
    # if valid store
    
    for c in os.scandir(dir):
        if os.path.isfile(c):
            if check_validity(c):
                store_cert(c, d)


## Generates a chain of trust for each entry in d, from user cert to root cert
# returns a list
def chain_of_trust(cert, d):


    if cert.subject == cert.issuer:
        return []

    for c in d.values():
        if c.issuer in d.keys():
            return [d[c.subject]] + chain_of_trust(c, d)



if __name__ == "__main__":
    print(get_serial_number(sys.argv[1]))

    subj = dict()
    store_cert(sys.argv[1], subj)

    get_local_certs("/etc/ssl/certs", subj)

    print(subj)
    print(len(subj))

    cert_file = open("google_cert", "rb")
    content = cert_file.read()

    cert = x509.load_pem_x509_certificate(content, default_backend())

    print(chain_of_trust(cert, subj))
