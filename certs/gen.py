import datetime

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


root_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)
subject = issuer = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Texas"),
    x509.NameAttribute(NameOID.LOCALITY_NAME, u"Austin"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Company"),
    x509.NameAttribute(NameOID.COMMON_NAME, u"My CA"),
])
root_cert = x509.CertificateBuilder().subject_name(
    subject
).issuer_name(
    issuer
).public_key(
    root_key.public_key()
).serial_number(
    x509.random_serial_number()
).not_valid_before(
    datetime.datetime.utcnow()
).not_valid_after(
    datetime.datetime.utcnow() + datetime.timedelta(days=3650)
).add_extension(
    x509.BasicConstraints(True, 0),
    critical=False
).sign(root_key, hashes.SHA256(), default_backend())

# Write root_key, root_cert to files
with open("ca_key.pem", "wb") as f:
    f.write(root_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.BestAvailableEncryption(b"openstack-ansible")
    ))

with open("ca_cert.pem", "wb") as f:
    f.write(root_cert.public_bytes(
        encoding=serialization.Encoding.PEM,
    ))

# Now we want to generate a cert from that root
cert_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)
new_subject = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Texas"),
    x509.NameAttribute(NameOID.LOCALITY_NAME, u"Austin"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"New Org Name!"),
    x509.NameAttribute(NameOID.COMMON_NAME, u"My Server"),
])
cert = x509.CertificateBuilder().subject_name(
    new_subject
).issuer_name(
    root_cert.issuer
).public_key(
    cert_key.public_key()
).serial_number(
    x509.random_serial_number()
).not_valid_before(
    datetime.datetime.utcnow()
).not_valid_after(
datetime.datetime.utcnow() + datetime.timedelta(days=30)
).add_extension(
    x509.SubjectAlternativeName([x509.DNSName(u"somedomain.com")]),
    critical=False,
).sign(root_key, hashes.SHA256(), default_backend())

# Write cert_key, cert to files
with open("server_key.pem", "wb") as f:
    f.write(cert_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.BestAvailableEncryption(b"openstack-ansible")
    ))

with open("server_cert.pem", "wb") as f:
    f.write(cert.public_bytes(
        encoding=serialization.Encoding.PEM,
    ))