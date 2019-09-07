import re
import sys

from .logger import Logger
from .android.modules.certanalysis import _CertAnalysis
from .android.modules.codeanalysis import _CodeAnalysis
from .android.modules.fileanalysis import _FileAnalysys
from .android.modules.manifestanalysis import _ManifestAnalysis
from .android.modules.otheranalysis import _OtherAnalysis
from .android.modules.owaspmasvs import _OwaspMasvs
from .__version__ import __version__, __author__

python_version = sys.version_info
if python_version.major < 3:
    raise TypeError("Glorifiedgrep works with python 3.7+")
elif python_version.major == 3 and python_version.minor < 7:
    raise TypeError("Glorifiedgrep works with python 3.7+")


class GlorifiedAndroid(
    _ManifestAnalysis,
    _CodeAnalysis,
    _FileAnalysys,
    _CertAnalysis,
    _OtherAnalysis,
    _OwaspMasvs,
):
    """
    Main class that is instantiated when using GlorifiedAndroid.
    """

    def search_methods(self, regex: str) -> list:
        """
        Search methods available through the GlorifiedAndroid class. This 
        does not search for methods in any classes from the utils 
        module. 
        
        :param regex: regex to search for
        :type regex: str
        :return: List of matching methods
        :rtype: list

        >>> GlorifiedAndroid(apk).search_methods('intent')
        """
        methods = [
            func
            for func in dir(self)
            if callable(getattr(self, func)) and not func.startswith("_")
        ]
        r = re.compile(regex, re.I)
        return list(filter(lambda x: r.findall(x), methods))
