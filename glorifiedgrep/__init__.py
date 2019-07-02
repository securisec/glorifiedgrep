import re

from .logger import Logger
from .android.modules.certanalysis import _CertAnalysis
from .android.modules.codeanalysis import _CodeAnalysis
from .android.modules.fileanalysis import _FileAnalysys
from .android.modules.manifestanalysis import _ManifestAnalysis
from .android.modules.otheranalysis import _OtherAnalysis
from .android.modules.owaspmasvs import _OwaspMasvs
from .__version__ import __version__, __author__

class GlorifiedAndroid(_ManifestAnalysis, _CodeAnalysis, _FileAnalysys,
           _CertAnalysis, _OtherAnalysis, _OwaspMasvs):
    """
    Main class that is instantiated when using GlorifiedAndroid.
    """

    # TODO deprecate this
    # def run_all_analysis(self):
    #     """
    #     Method runs all available analysis checks on the app and 
    #     returns the complete dictionary. This is not the best way to use 
    #     GlorifiedAndroid as it generates a lot of data and is much slower. This method 
    #     was designed for testing only.

    #     :return: Analysis results as a dictionary
    #     :rtype: dict

    #     >>> a = GlorifiedAndroid('/path/to/apk')
    #     >>> a.run_all_analysis(manifest_only=True)
    #     """
    #     # run all app analysis
    #     self.all_manifest_analysis()
    #     self.all_file_analysis()
    #     self.all_cert_analysis()
    #     self.all_code_analysis()
    #     self.all_owasp_analysis()
    #     self.all_other_analysis()
    #     return self._android_findings

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
        methods = [func for func in dir(self) if callable(
            getattr(self, func)) and not func.startswith("_")]
        r = re.compile(regex, re.I)
        return list(filter(
            lambda x: r.findall(x), methods
        ))
