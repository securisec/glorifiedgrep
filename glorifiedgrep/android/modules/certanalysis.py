from OpenSSL import crypto
from OpenSSL._util import lib as cryptolib
from OpenSSL.crypto import X509, _ffi, _lib

from .androidcore import _AndroidCore
from ...logger import _logger
from ...out import GreppedOut


class _CertAnalysis(_AndroidCore):

    def _get_certificates(self, o):
        # https://stackoverflow.com/a/45111623/7402287
        certs = _ffi.NULL
        if o.type_is_signed():
            certs = o._pkcs7.d.sign.cert
        elif o.type_is_signedAndEnveloped():
            certs = o._pkcs7.d.signed_and_enveloped.cert

        pycerts = []
        for i in range(_lib.sk_X509_num(certs)):
            pycert = X509.__new__(X509)
            pycert._x509 = _lib.sk_X509_value(certs, i)
            pycerts.append(pycert)

        if not pycerts:
            self.log_debug('')
            return []
        self.log_debug('')
        return tuple(pycerts)

    def _read_cert(self):
        """
        Read the contents of CERT.RSA

        :return: cert buffer
        :rtype: buffer
        """
        with open(self._cert_path, 'rb') as f:
            self.log_debug('')
            return f.read()

    def _cert_object(self):
        """
        Returns a CSR object
        """
        pkcs7 = crypto.load_pkcs7_data(crypto.FILETYPE_ASN1, self._read_cert())
        certs = self._get_certificates(pkcs7)
        certificate = crypto.dump_certificate(crypto.FILETYPE_PEM, certs[0])
        a = crypto.load_certificate(crypto.FILETYPE_PEM, certificate)
        self.log_debug('')
        return a

    def all_cert_analysis(self):
        """
        Property runs all available checks in _CertAnalysis

        :return: Dictionary of all cert analysis
        :rtype: dict

        >>> from glorifiedgrep import GlorifiedAndroid
        >>> a = GlorifiedAndroid('/path/to/apk')
        >>> a.all_manifest_analysis()
        """
        methods = [p for p in vars(
            _CertAnalysis).keys() if not p.startswith('_')]
        [getattr(self, m)() for m in methods if m != 'all_cert_analysis']
        self.log_debug('')
        return self._android_findings['cert_analysis']

    @_logger
    def cert_public_key(self) -> GreppedOut:
        """
        Get the public key from CERT.RSA

        Returns
        -------
        GreppedOut : object
            GreppedOut object

        Examples
        --------
        >>> from glorifiedgrep import GlorifiedAndroid
        >>> a = GlorifiedAndroid('/path/to/apk')
        >>> a.cert_public_key()
        """
        pkcs7 = crypto.load_pkcs7_data(crypto.FILETYPE_ASN1, self._read_cert())
        certs = self._get_certificates(pkcs7)
        p = certs[0].get_pubkey()
        bio = crypto._new_mem_buf()
        cryptolib.PEM_write_bio_PUBKEY(bio, p._pkey)
        key = crypto._bio_to_string(bio)
        self._cert_analysis['public_key'] = [key]
        self.log_debug('')
        return GreppedOut([key])

    @_logger
    def cert_certificate(self) -> GreppedOut:
        """
        Returns a PEM encoded certificate

        Returns
        -------
        GreppedOut : object
            GreppedOut object

        Examples
        --------
        >>> from glorifiedgrep import GlorifiedAndroid
        >>> a = GlorifiedAndroid('/path/to/apk')
        >>> a.cert_certificate()
        """
        pkcs7 = crypto.load_pkcs7_data(crypto.FILETYPE_ASN1, self._read_cert())
        certs = self._get_certificates(pkcs7)
        certificate = crypto.dump_certificate(crypto.FILETYPE_PEM, certs[0])
        self._cert_analysis['certificate'] = [certificate]
        self.log_debug('')
        return GreppedOut([certificate])

    @_logger
    def cert_digest(self) -> dict:
        """
        Returns the digest hash in md5. sha1 and sha256

        Returns
        -------
        dict
            Dictionary of hashes

        Examples
        --------
        >>> from glorifiedgrep import GlorifiedAndroid
        >>> a = GlorifiedAndroid('/path/to/apk')
        >>> a.cert_digest()
        """
        digest = {k: self._cert_object().digest(k)
                  for k in ['md5', 'sha1', 'sha256']}
        self._cert_analysis['digest'] = [digest]
        self.log_debug('')
        return digest

    @_logger
    def cert_issuer(self) -> GreppedOut:
        """
        The entity that verified the information and signed the certificate

        Returns
        -------
        GreppedOut : object
            GreppedOut object

        Examples
        --------
        >>> from glorifiedgrep import GlorifiedAndroid
        >>> a = GlorifiedAndroid('/path/to/apk')
        >>> a.cert_issuer()
        """
        com = self._cert_object().get_issuer().get_components()
        issuer = [{k[0].decode():k[1].decode()} for k in com]
        self._cert_analysis['issuer'] = issuer
        self.log_debug('')
        return GreppedOut(issuer)

    @_logger
    def cert_valid_dates(self) -> dict:
        """
        The that the certificate is valid before, after and if expired

        Returns
        -------
        dict
            Dict of dates and if exipred

        Examples
        --------
        >>> from glorifiedgrep import GlorifiedAndroid
        >>> a = GlorifiedAndroid('/path/to/apk')
        >>> a.cert_valid_dates()
        """
        d = self._cert_object()
        dates = {
            'not_before': d.get_notBefore(),
            'not_after': d.get_notAfter(),
            'expired': d.has_expired()
        }
        self._cert_analysis['valid'] = [dates]
        self.log_debug('')
        return dates

    @_logger
    def cert_serial_number(self) -> int:
        """
        Used to uniquely identify the certificate within a CA's systems. 
        In particular this is used to track revocation information

        Returns
        -------
        int
            Certificate serial number

        Examples
        --------
        >>> from glorifiedgrep import GlorifiedAndroid
        >>> a = GlorifiedAndroid('/path/to/apk')
        >>> a.cert_serial_number()

        """
        a = self._cert_object().get_serial_number()
        self._cert_analysis['serial_number'] = [a]
        self.log_debug('')
        return a

    @_logger
    def cert_signature_algorithm(self) -> str:
        """
        The algorithm used to sign the public key certificate

        Returns
        -------
        str
            Algorithm used to create the certificate

        Examples
        --------
        >>> from glorifiedgrep import GlorifiedAndroid
        >>> a = GlorifiedAndroid('/path/to/apk')
        >>> a.cert_signature_algorithm()
        """
        a = self._cert_object().get_signature_algorithm()
        self._cert_analysis['signature_algorithm'] = [a]
        self.log_debug('')
        return a

    @_logger
    def cert_version(self) -> int:
        """
        The certificate version number

        Returns
        -------
        int
            Version number of the certificate

        Examples
        --------
        >>> from glorifiedgrep import GlorifiedAndroid
        >>> a = GlorifiedAndroid('/path/to/apk')
        >>> a.cert_version()
        """
        a = self._cert_object().get_version()
        self._cert_analysis['version'] = [a]
        self.log_debug('')
        return a

    @_logger
    def cert_bits(self) -> int:
        """
        Certificate bit

        Returns
        -------
        int
            Certificate bits

        Examples
        --------
        >>> from glorifiedgrep import GlorifiedAndroid
        >>> a = GlorifiedAndroid('/path/to/apk')
        >>> a.cert_bits()
        """
        a = self._cert_object().get_pubkey().bits()
        self._cert_analysis['bits'] = [a]
        self.log_debug('')
        return a

    @_logger
    def cert_subject(self) -> list:
        """
        The entity a certificate belongs to: a machine, an individual, or an organization.

        Returns
        -------
        dict
            Dict of certificate subjects CN, O, C, ST, L, OU, Cn

        Examples
        --------
        >>> from glorifiedgrep import GlorifiedAndroid
        >>> a = GlorifiedAndroid('/path/to/apk')
        >>> a.cert_subject()
        """
        com = self._cert_object().get_subject().get_components()
        issuer = [{k[0].decode():k[1].decode()} for k in com]
        self._cert_analysis['subject'] = issuer
        self.log_debug('')
        return issuer
