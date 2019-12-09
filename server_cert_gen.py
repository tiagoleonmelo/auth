from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import datetime
import uuid

## Generates a cert signed from an already existing CA
def create_cert(cert_authority, private_key):
    one_day = datetime.timedelta(1, 0, 0)
    # Use our private key to generate a public key
    root_key = serialization.load_pem_private_key(
        private_key.encode("ascii"), password=None, backend=default_backend()
    )

    root_cert = x509.load_pem_x509_certificate(
        cert_authority.encode("ascii"), default_backend()
    )

    # Now we want to generate a cert from that root
    cert_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
    new_subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"PT"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Aveiro"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"Aveiro"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"deti"),
        ]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(new_subject)
        .issuer_name(root_cert.issuer)
        .public_key(cert_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime(2020, 8, 2))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(u"somedomain.com")]),
            critical=False,
        )
        .sign(root_key, hashes.SHA256(), default_backend())
    )

    # Dump to scratch
    with open("scratch/phone_cert.pem", "wb") as f:
        f.write(cert.public_bytes(encoding=serialization.Encoding.PEM))

    # Return PEM
    cert_pem = cert.public_bytes(encoding=serialization.Encoding.PEM)

    cert_key_pem = cert_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )

    return cert_pem, cert_key_pem



private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)

public_key = private_key.public_key()

with open("server.key", "wb") as f:
    f.write(private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.BestAvailableEncryption(b"openstack-ansible")
    ))

with open("ca.crt", "rb") as f:
    ca_crt = f.read()

server_cert, server_cert_key = create_cert(ca_crt, private_key)

with open("server.crt", "wb") as f:
    f.write(server_cert.public_bytes(
        encoding=serialization.Encoding.PEM,
    ))