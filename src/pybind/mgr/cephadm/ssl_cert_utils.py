
from typing import Any, Tuple, IO, List, Union, Optional
import ipaddress

from datetime import datetime, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend


class SSLConfigException(Exception):
    pass


class SSLCerts:
    def __init__(self, _certificate_duration_days: int = (365 * 10 + 3)) -> None:
        self.root_certificate_duration_days = (365 * 10 + 3)
        self.certificate_duration_days = _certificate_duration_days
        self.root_cert: Any
        self.root_key: Any
        self.key_file: IO[bytes]
        self.cert_file: IO[bytes]

    def generate_root_cert(
        self,
        addr: Optional[str] = None,
        custom_san_list: Optional[List[str]] = None
    ) -> Tuple[str, str]:
        self.root_key = rsa.generate_private_key(
            public_exponent=65537, key_size=4096, backend=default_backend())
        root_public_key = self.root_key.public_key()
        root_builder = x509.CertificateBuilder()
        root_builder = root_builder.subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, u'cephadm-root'),
        ]))
        root_builder = root_builder.issuer_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, u'cephadm-root'),
        ]))
        root_builder = root_builder.not_valid_before(datetime.now())
        root_builder = root_builder.not_valid_after(datetime.now() + timedelta(days=self.root_certificate_duration_days))
        root_builder = root_builder.serial_number(x509.random_serial_number())
        root_builder = root_builder.public_key(root_public_key)

        san_list: List[x509.GeneralName] = []
        if addr:
            san_list.extend([x509.IPAddress(ipaddress.ip_address(addr))])
        if custom_san_list:
            san_list.extend([x509.DNSName(n) for n in custom_san_list])
        root_builder = root_builder.add_extension(
            x509.SubjectAlternativeName(
                san_list
            ),
            critical=False
        )

        root_builder = root_builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True,
        )

        self.root_cert = root_builder.sign(
            private_key=self.root_key, algorithm=hashes.SHA256(), backend=default_backend()
        )

        cert_str = self.root_cert.public_bytes(encoding=serialization.Encoding.PEM).decode('utf-8')
        key_str = self.root_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')

        return (cert_str, key_str)

    def generate_cert(
        self,
        _hosts: Union[str, List[str]],
        _addrs: Union[str, List[str]],
        custom_san_list: Optional[List[str]] = None,
    ) -> Tuple[str, str]:

        addrs = [_addrs] if isinstance(_addrs, str) else _addrs
        hosts = [_hosts] if isinstance(_hosts, str) else _hosts

        valid_ips = True
        try:
            ips = [x509.IPAddress(ipaddress.ip_address(addr)) for addr in addrs]
        except Exception:
            valid_ips = False

        private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=4096, backend=default_backend())
        public_key = private_key.public_key()

        builder = x509.CertificateBuilder()
        builder = builder.subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, addrs[0]), ]))
        builder = builder.issuer_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, u'cephadm-root'), ]))
        builder = builder.not_valid_before(datetime.now())
        builder = builder.not_valid_after(datetime.now() + timedelta(days=self.certificate_duration_days))
        builder = builder.serial_number(x509.random_serial_number())
        builder = builder.public_key(public_key)

        san_list: List[x509.GeneralName] = [x509.DNSName(host) for host in hosts]
        if valid_ips:
            san_list.extend(ips)
        if custom_san_list:
            san_list.extend([x509.DNSName(n) for n in custom_san_list])

        builder = builder.add_extension(
            x509.SubjectAlternativeName(
                san_list
            ),
            critical=False
        )
        builder = builder.add_extension(x509.BasicConstraints(
            ca=False, path_length=None), critical=True,)

        cert = builder.sign(private_key=self.root_key,
                            algorithm=hashes.SHA256(), backend=default_backend())
        cert_str = cert.public_bytes(encoding=serialization.Encoding.PEM).decode('utf-8')
        key_str = private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                            format=serialization.PrivateFormat.TraditionalOpenSSL,
                                            encryption_algorithm=serialization.NoEncryption()
                                            ).decode('utf-8')

        return (cert_str, key_str)

    def renew_cert(
        self,
        old_cert: str,
        new_duration_days: Optional[int] = None
    ) -> Tuple[str, str]:
        """
        Renews a certificate, generating a new private key and extending its duration.

        :param old_cert: The existing certificate (PEM format) to be renewed.
        :param new_duration_days: The new validity duration for the certificate in days.
                                  If not provided, it defaults to `self.certificate_duration_days`.
        :return: A tuple containing the renewed certificate and the new private key (PEM format).
        """
        try:
            # Load the old certificate
            old_certificate = x509.load_pem_x509_certificate(old_cert.encode('utf-8'), backend=default_backend())

            # Generate a new private key
            new_private_key = rsa.generate_private_key(
                public_exponent=65537, key_size=4096, backend=default_backend()
            )

            # Extract existing SANs
            san_extension = old_certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            san_list = san_extension.value

            # Build a new certificate with the same attributes
            builder = x509.CertificateBuilder()
            builder = builder.subject_name(old_certificate.subject)
            builder = builder.issuer_name(old_certificate.issuer)
            builder = builder.not_valid_before(datetime.now())
            builder = builder.not_valid_after(
                datetime.now() + timedelta(days=new_duration_days or self.certificate_duration_days)
            )
            builder = builder.serial_number(x509.random_serial_number())
            builder = builder.public_key(new_private_key.public_key())

            # Reuse SANs
            builder = builder.add_extension(san_list, critical=False)

            # Retain the original basic constraints
            basic_constraints = old_certificate.extensions.get_extension_for_class(x509.BasicConstraints)
            builder = builder.add_extension(basic_constraints.value, critical=basic_constraints.critical)

            # Sign the new certificate
            renewed_cert = builder.sign(private_key=self.root_key, algorithm=hashes.SHA256(), backend=default_backend())

            # Convert certificate and key to PEM format
            cert_str = renewed_cert.public_bytes(encoding=serialization.Encoding.PEM).decode('utf-8')
            key_str = new_private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ).decode('utf-8')

            return cert_str, key_str

        except Exception as e:
            raise SSLConfigException(f"Failed to renew certificate: {e}")

    def get_root_cert(self) -> str:
        try:
            return self.root_cert.public_bytes(encoding=serialization.Encoding.PEM).decode('utf-8')
        except AttributeError:
            return ''

    def get_root_key(self) -> str:
        try:
            return self.root_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            ).decode('utf-8')
        except AttributeError:
            return ''

    def load_root_credentials(self, cert: str, priv_key: str) -> None:
        given_cert = x509.load_pem_x509_certificate(cert.encode('utf-8'), backend=default_backend())
        tz = given_cert.not_valid_after.tzinfo
        if datetime.now(tz) >= given_cert.not_valid_after:
            raise SSLConfigException('Given cert is expired')
        self.root_cert = given_cert
        self.root_key = serialization.load_pem_private_key(
            data=priv_key.encode('utf-8'), backend=default_backend(), password=None)
