from __future__ import annotations
import re
from .androidcore import _AndroidCore
from ...logger import _logger
from ...out import GreppedOut
from .constants import _GrepConstants, _Trackers


class _OtherAnalysis(_AndroidCore, _GrepConstants, _Trackers):

    def all_other_analysis(self):
        """
        Property runs all available checks in _OtherAnalysis

        :return: Dictionary of all other analysis
        :rtype: dict

        >>> a = GlorifiedAndroid('/path/to/apk')
        >>> a.all_other_analysis()
        """
        methods = [p for p in vars(
            _OtherAnalysis).keys() if not p.startswith('_')]
        [getattr(self, m)() for m in methods if m != 'all_other_analysis']
        self.log_debug('')
        return self._android_findings['other_analysis']

    @_logger
    def other_email_addresses(self, show_code=False) -> GreppedOut:
        """
        Find email addresses in the decompiled source

        Parameters
        ----------
        show_code : bool, optional
            Show the full matched line, by default False
        
        Returns
        -------
        GreppedOut : object
            GreppedOut object

        Examples
        --------
        >>> from glorifiedgrep import GlorifiedAndroid
        >>> a = GlorifiedAndroid('/path/to/apk')
        >>> a.other_email_addresses()
        """
        regex = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b'
        grep = self._run_rg(regex=regex, code=show_code)
        match = self._process_match(grep)
        self._other_analysis['email'] = match
        self.log_debug('')
        return GreppedOut(match)

    @_logger
    def other_unicode_chars(self, script: str='Hangul', show_code=False):
        """
        Find unicode characters representing differnt character sets from 
        different languages in the decompiled apk. Supports both Unicode 
        Scripes and Unicode Blocks. See the reference for supported ranges. 
        | `Reference <https://www.regular-expressions.info/unicode.html>`__

        Parameters
        ----------
        script : string, default Hangul
            Any supported Unicode Script or Unicode Blocks. Ex: ``Han`` for Chinese characters.
        show_code : bool, optional
            Show the full matched line, by default False
        
        Returns
        -------
        GreppedOut : object
            GreppedOut object

        Examples
        --------
        >>> from glorifiedgrep import GlorifiedAndroid
        >>> a = GlorifiedAndroid('/path/to/apk')
        >>> a.other_chinese_chars()
        """
        regex = r'[\p{' + script + '}]+'
        g = self._run_rg(regex=regex, code=show_code)
        match = self._process_match(g)
        self._other_analysis['chinese'] = match
        self.log_debug('')
        return GreppedOut(match)

    @_logger
    def other_ip_address(self, show_code=False):
        """
        Find IP addresses in the decompiled source

        Parameters
        ----------
        show_code : bool, optional
            Show the full matched line, by default False
        
        Returns
        -------
        GreppedOut : object
            GreppedOut object

        Examples
        --------
        >>> from glorifiedgrep import GlorifiedAndroid
        >>> a = GlorifiedAndroid('/path/to/apk')
        >>> a.other_ip_address()
        """
        regex = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        g = self._run_rg(regex=regex, code=show_code)
        match = self._process_match(g)
        self._other_analysis['ipaddress'] = match
        self.log_debug('')
        return GreppedOut(match)

    @_logger
    def other_http_urls(self, show_code=False):
        """
        Find HTTP urls in the decompiled source

        Parameters
        ----------
        show_code : bool, optional
            Show the full matched line, by default False
        
        Returns
        -------
        GreppedOut : object
            GreppedOut object

        Examples
        --------
        >>> from glorifiedgrep import GlorifiedAndroid
        >>> a = GlorifiedAndroid('/path/to/apk')
        >>> a.other_http_urls()
        """
        regex = r'(?:http://)[\w.-]+(?:\.[\w\.-]+)+[\w\-\._~:/?#[.]@&\(\)\*\+]+'
        g = self._run_rg(regex=regex, code=show_code)
        match = self._process_match(g, is_url=True)
        self._other_analysis['http_url'] = match
        self.log_debug('')
        return GreppedOut(match)

    @_logger
    def other_all_urls(self, show_code=False):
        """
        Find all urls in the decompiled source

        Parameters
        ----------
        show_code : bool, optional
            Show the full matched line, by default False
        
        Returns
        -------
        GreppedOut : object
            GreppedOut object

        Examples
        --------
        >>> from glorifiedgrep import GlorifiedAndroid
        >>> a = GlorifiedAndroid('/path/to/apk')
        >>> a.other_all_urls()
        """
        regex = r'(?:http(s)?://)[\w.-]+(?:\.[\w\.-]+)+[\w\-\._~:/?#[.]@&\(\)\*\+]+|https?://localhost:?(\d+)?'
        g = self._run_rg(regex=regex, code=show_code)
        match = self._process_match(g, is_url=True)
        self._other_analysis['urls'] = match
        self.log_debug('')
        return GreppedOut(match)

    @_logger
    def other_file_urlhandler(self, show_code=False):
        """
        Find all ``file://`` urls in the decompiled source

        Parameters
        ----------
        show_code : bool, optional
            Show the full matched line, by default False
        
        Returns
        -------
        GreppedOut : object
            GreppedOut object

        Examples
        --------
        >>> from glorifiedgrep import GlorifiedAndroid
        >>> a = GlorifiedAndroid('/path/to/apk')
        >>> a.other_file_urlhandler()
        """
        regex = r'\"(file://.+)\"'
        g = self._run_rg(regex=regex, code=show_code, group="-r '$1'")
        match = self._process_match(g, is_url=True)
        self._other_analysis['file_handler'] = match
        self.log_debug('')
        return GreppedOut(match)

    @_logger
    def other_content_urlhandler(self, show_code=False):
        """
        Find all ``content://`` urls in the decompiled source

        Parameters
        ----------
        show_code : bool, optional
            Show the full matched line, by default False
        
        Returns
        -------
        GreppedOut : object
            GreppedOut object

        Examples
        --------
        >>> from glorifiedgrep import GlorifiedAndroid
        >>> a = GlorifiedAndroid('/path/to/apk')
        >>> a.other_content_urlhandler()
        """
        regex = r'\"(content://.+)\"'
        g = self._run_rg(regex=regex, code=show_code, group="-r '$1'")
        match = self._process_match(g, is_url=True)
        self._other_analysis['content_uri'] = match
        self.log_debug('')
        return GreppedOut(match)

    @_logger
    def other_websocket_urlhandler(self, show_code=False):
        """
        Find all ``ws://`` or ``wss://`` urls in the decompiled source

        Parameters
        ----------
        show_code : bool, optional
            Show the full matched line, by default False
        
        Returns
        -------
        GreppedOut : object
            GreppedOut object

        Examples
        --------
        >>> from glorifiedgrep import GlorifiedAndroid
        >>> a = GlorifiedAndroid('/path/to/apk')
        >>> a.other_websocket_urlhandler()
        """
        regex = r'\"(ws://.+|wss://.+)\"'
        g = self._run_rg(regex=regex, code=show_code, group="-r '$1'")
        match = self._process_match(g, is_url=True)
        self._other_analysis['websocket'] = match
        self.log_debug('')
        return GreppedOut(match)

    @_logger
    def other_secret_keys(self, show_code=False):
        """
        Find all urls in the decompiled source

        Parameters
        ----------
        show_code : bool, optional
            Show the full matched line, by default False
        
        Returns
        -------
        GreppedOut : object
            GreppedOut object

        Examples
        --------
        >>> from glorifiedgrep import GlorifiedAndroid
        >>> a = GlorifiedAndroid('/path/to/apk')
        >>> a.other_secret_keys()
        """
        regex = r'(-----(\bBEGIN\b|\bEND\b) ((\bRSA PRIVATE KEY\b)|(\bCERTIFICATE\b)|(\bOPENSSH PRIVATE KEY\b)|(\bDSA PRIVATE KEY\b)|(\bEC PRIVATE KEY\b)|(\bPGP PRIVATE KEY BLOCK\b))-----)'
        g = self._run_rg(regex=regex, code=show_code)
        match = self._process_match(g)
        self._other_analysis['secret_keys'] = match
        self.log_debug('')
        return GreppedOut(match)

    @_logger
    def other_aws_keys(self, show_code=False):
        """
        Find all AWS keys in the decompiled source

        Parameters
        ----------
        show_code : bool, optional
            Show the full matched line, by default False
        
        Returns
        -------
        GreppedOut : object
            GreppedOut object

        Examples
        --------
        >>> from glorifiedgrep import GlorifiedAndroid
        >>> a = GlorifiedAndroid('/path/to/apk')
        >>> a.other_aws_keys()
        """
        regex = r'AKIA[0-9A-Z]{16}'
        g = self._run_rg(regex=regex, code=show_code)
        match = self._process_match(g)
        self._other_analysis['aws_keys'] = match
        self.log_debug('')
        return GreppedOut(match)

    @_logger
    def other_github_token(self, show_code=False):
        """
        Find all Github tokens in the decompiled source

        Parameters
        ----------
        show_code : bool, optional
            Show the full matched line, by default False
        
        Returns
        -------
        GreppedOut : object
            GreppedOut object

        Examples
        --------
        >>> from glorifiedgrep import GlorifiedAndroid
        >>> a = GlorifiedAndroid('/path/to/apk')
        >>> a.other_github_token()
        """
        regex = r"[g|G][i|I][t|T][h|H][u|U][b|B].*[['|\"]0-9a-zA-Z]{35,40}['|\"]"
        g = self._run_rg(regex=regex, code=show_code)
        match = self._process_match(g)
        self._other_analysis['github_token'] = match
        self.log_debug('')
        return GreppedOut(match)

    @_logger
    def other_password_in_url(self, show_code=False):
        """
        Find all passwords in urls. Usually used for basic authentication

        Parameters
        ----------
        show_code : bool, optional
            Show the full matched line, by default False
        
        Returns
        -------
        GreppedOut : object
            GreppedOut object

        Examples
        --------
        >>> from glorifiedgrep import GlorifiedAndroid
        >>> a = GlorifiedAndroid('/path/to/apk')
        >>> a.other_password_in_url()
        """
        regex = r'(\w+://\w+:)(.+)@\w+\.?[\w|\.].*'
        g = self._run_rg(regex=regex, code=show_code)
        match = self._process_match(g)
        self._other_analysis['password_in_url'] = match
        self.log_debug('')
        return GreppedOut(match)

    @_logger
    def other_google_ads_import(self, show_code=False):
        """
        Find imports relevant to Google ads

        Parameters
        ----------
        show_code : bool, optional
            Show the full matched line, by default False
        
        Returns
        -------
        GreppedOut : object
            GreppedOut object

        Examples
        --------
        >>> from glorifiedgrep import GlorifiedAndroid
        >>> a = GlorifiedAndroid('/path/to/apk')
        >>> a.other_google_ads_import()
        """
        regex = r'^import com.google.android.gms.ads'
        g = self._run_rg(regex=regex, code=show_code)
        match = self._process_match(g)
        self._other_analysis['goole_ads_import'] = match
        self.log_debug('')
        return GreppedOut(match)

    @_logger
    def other_find_trackers_ads(self):
        """
        Find trackers included in the app. Currently it looks for 
        135 trackers.

        Parameters
        ----------
        show_code : bool, optional
            Show the full matched line, by default False
        
        Returns
        -------
        GreppedOut : object
            GreppedOut object

        Examples
        --------
        >>> from glorifiedgrep import GlorifiedAndroid
        >>> a = GlorifiedAndroid('/path/to/apk')
        >>> a.other_find_trackers_ads()
        """
        match = []
        if self.__class__.__name__ == 'GlorifiedAndroid':
            path = f'{self._output_dir}/resources'
        else:
            path = self._java_sources
        for k, v in self._TRACKERS.items():
            g = self._run_rg(regex=v, rg_options='-l', path=path)
            if len(g) > 0:
                match.append(k)
        self._other_analysis['trackers'] = match
        self.log_debug('')
        return GreppedOut(match)

    @_logger
    def other_ad_networks(self, show_code=False) -> dict:
        """
        Show imports of the popular android ad networks. 
        | `Reference <https://github.com/lioulei1317/Android-Demo/blob/master/javaapk.com-360Satety/src/com/anjoyo/anjoyosafety/util/AdManagerUtil.java>`__
        | `Reference <https://www.appbrain.com/stats/libraries/ad-networks>`__

        Parameters
        ----------
        show_code : bool, optional
            Show the full matched line, by default False
        
        Returns
        -------
        GreppedOut : object
            GreppedOut object

        Examples
        --------
        >>> from glorifiedgrep import GlorifiedAndroid
        >>> a = GlorifiedAndroid('/path/to/apk')
        >>> a.other_ad_networks()
        """
        match = {}
        if self.__class__.__name__ == 'GlorifiedAndroid':
            path = f'{self._output_dir}/sources'
        else:
            path = self._java_sources
        for k, v in self._AD_NETWORKS.items():
            g = self._run_rg(regex=v, rg_options='-l', path=path)
            if len(g) > 0:
                match[k.lower().replace(' ', '_')] = g
        self._other_analysis['trackers'] = match
        self.log_debug('')
        match['found'] = list(match.keys())
        return GreppedOut(match)
