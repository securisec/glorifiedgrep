from ..logger import Logger
from .modules.certanalysis import _CertAnalysis
from .modules.codeanalysis import _CodeAnalysis
from .modules.fileanalysis import _FileAnalysys
from .modules.manifestanalysis import _ManifestAnalysis
from .modules.otheranalysis import _OtherAnalysis
from .modules.owaspmasvs import _OwaspMasvs

class ParseManifest(_ManifestAnalysis):
    """
    This class can be used to just parse an AnroidManifest.xml file and 
    parse it. This class does not decompile an APK file
    """

    def __init__(self, manifest_path):
        """
        The __init__ method for the ParseManifest class

        :param str manifest_path: Path to the manifest file

        >>> a = ParseManifest('/path/to/AndroidManifest.xml')
        >>> a.activities
        """
        super().__init__(apk_path=None)
        self._manifest_path = manifest_path


class CertInfo(_CertAnalysis):
    """
    This class is used for analyzing the certificate that an application 
    is signed with. All the methods from this class is available in 
    ``GlorifiedAndroid`` class, but can also be used by itself by passing 
    the path to the certificate.

    Examples
    --------
    >>> from glorifiedgrep.android import CertInfo
    >>> cert = CertInfo('/path/to/cert)
    """

    def __init__(self, cert_path):
        """
        The __init__ method for the CertInfo class

        :param str cert_path: Path to the CERT.RSA file

        >>> c = CertInfo('/path/to/CERT.RSA')
        >>> c.cert_public_key
        """
        super().__init__(apk_path=None)
        self._cert_path = cert_path


class CodeAnalysis(_CodeAnalysis, _OwaspMasvs):
    """
    This class can be used to perform code analysis checks against
    an already decompiled APK. This class also interits all the 
    OWASP class methods. 
    """

    def __init__(self, source_path):
        """
        The __init__ method for the CertInfo class

        :param str cert_path: Path to the CERT.RSA file

        >>> c = CertInfo('/path/to/some/dir')
        >>> c.code_dex_classloader()
        """
        super().__init__(None)
        self._java_sources = source_path


class OWASPAnalysis(_OwaspMasvs):
    """
    This class can be used to perform code analysis checks against
    an already decompiled APK
    """

    def __init__(self, source_path):
        """
        The __init__ method for the CertInfo class

        :param str cert_path: Path to the CERT.RSA file

        >>> o = OWASPAnalysis('/path/to/some/dir')
        >>> c.owasp_insecure_random()
        """
        super().__init__(None)
        self._java_sources = source_path


class OtherAnalysis(_OtherAnalysis):
    """
    This calss can be used to gather arbitrary information like URL's, 
    secret keys, tokens, chinese characters etc.
    """

    def __init__(self, source_path):
        """
        The __init__ method for the OtherAnalysis class

        :param str source_path: Path to folder where decompiled source code is

        >>> o = OtherAnalysis('/path/to/some/dir')
        >>> o.other_chinese_chars()
        """
        super().__init__(None)
        self._java_sources = source_path
