from __future__ import annotations
from .androidcore import _AndroidCore
from ...logger import _logger
from ...out import GreppedOut
from .constants import _GrepConstants


class _OwaspMasvs(_AndroidCore, _GrepConstants):

    def all_owasp_analysis(self):
        """
        Property runs all available checks in _OwaspMasvs

        :return: Dictionary of all other analysis
        :rtype: dict

        >>> from glorifiedgrep import GlorifiedAndroid
        >>> a = GlorifiedAndroid('/path/to/apk')
        >>> a.all_owasp_analysis()
        """
        methods = [p for p in vars(
            _OwaspMasvs).keys() if not p.startswith('_')]
        [getattr(self, m)() for m in methods if m != 'all_owasp_analysis']
        self.log_debug('')
        return self._android_findings['owasp_analysis']

    @_logger
    def owasp_crypto_primitives(self, show_code=False) -> GreppedOut:
        """
        Locate uses of the cryptographic primitives of the most frequently used classes and interfaces 
        in decompiled code
        | `Reference <https://github.com/OWASP/owasp-masvs/blob/master/Document/0x08-V3-Cryptography_Verification_Requirements.md>`__
        | `Reference <https://github.com/OWASP/owasp-mstg/blob/master/Document/0x05e-Testing-Cryptography.md>`__
        | `Reference CWE <https://cwe.mitre.org/data/definitions/310.html>`__

        :param bool show_code: 
        
        :return: name, line number and match
        :rtype: dict
        Parameters
        ----------
        show_code : bool, optional
            See the full line of code, defaults to False
        
        Returns
        -------
        GreppedOut : object
            GreppedOut object

        Examples
        --------
        >>> from glorifiedgrep import GlorifiedAndroid
        >>> a = GlorifiedAndroid('/path/to/apk')
        >>> a.owasp_crypto_primitives()
        """
        regex = r'\b(Cipher|Mac|MessageDigest|Signature|Key|PrivateKey|PublicKey|SecretKey)\.\w+\(?.+\)?'
        g = self._run_rg(regex=regex, code=show_code)
        match = self._process_match(g, owasp_category=['M6'])
        self._owasp_analysis['crypto_primitives'] = match
        self.log_debug('')
        return GreppedOut(match)

    @_logger
    def owasp_crypto_imports(self, show_code=False) -> GreppedOut:
        """
        Locate uses of the Java cryptographic imports in decompiled code
        | `Reference <https://github.com/OWASP/owasp-masvs/blob/master/Document/0x08-V3-Cryptography_Verification_Requirements.md>`__
        | `Reference <https://github.com/OWASP/owasp-mstg/blob/master/Document/0x05e-Testing-Cryptography.md#verifying-the-configuration-of-cryptographic-standard-algorithms>`__
        | `Reference CWE <https://cwe.mitre.org/data/definitions/310.html>`__

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
        >>> a.owasp_crypto_imports()
        """
        regex = r'import (java.security.*|java.crypto.*)'
        g = self._run_rg(regex=regex, code=show_code)
        match = self._process_match(g, owasp_category=['M6'])
        self._owasp_analysis['crypto_imports'] = match
        self.log_debug('')
        return GreppedOut(match)

    @_logger
    def owasp_insecure_random(self, show_code=False) -> GreppedOut:
        """
        Locate uses of the weak Ranom Java class. SecureRandom should be used instead
        | `Reference <https://github.com/OWASP/owasp-masvs/blob/master/Document/0x08-V3-Cryptography_Verification_Requirements.md>`__
        | `Reference <https://github.com/OWASP/owasp-mstg/blob/master/Document/0x05e-Testing-Cryptography.md#static-analysis-1>`__
        | `Reference Android SDK <https://developer.android.com/reference/java/util/Random>`__

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
        >>> a.owasp_insecure_random()
        """
        regex = self._IGNORE_IMPORTS + r'(\bRandom\(.+\))'
        g = self._run_rg(regex=regex, code=show_code)
        match = self._process_match(g, owasp_category=['M6'])
        self._owasp_analysis['insecure_random'] = match
        self.log_debug('')
        return GreppedOut(match)

    @_logger
    def owasp_hardcoded_keys(self, show_code=False) -> GreppedOut:
        """
        Locate hardcoded encryption keys and bytes used by SecretKeySpec. The 
        decompiled code should be inspected to find hardcoded keys.
        | `Reference <https://github.com/OWASP/owasp-masvs/blob/master/Document/0x08-V3-Cryptography_Verification_Requirements.md>`__
        | `Reference <https://github.com/OWASP/owasp-mstg/blob/master/Document/0x05e-Testing-Cryptography.md#static-analysis-2>`__
        | `Reference CWE <https://cwe.mitre.org/data/definitions/321.html>`__

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
        >>> a.owasp_hardcoded_keys()
        """
        regex = r'^([^import].+)(SecretKeySpec)'
        g = self._run_rg(regex=regex, code=show_code)
        match = self._process_match(g, owasp_category=['M6'])
        self._owasp_analysis['hardcoded_keys'] = match
        self.log_debug('')
        return GreppedOut(match)

    @_logger
    def owasp_insecure_fingerprint_auth(self, show_code=False) -> GreppedOut:
        """
        Locate insecure .authenticate public method where the first parameter is 
        null. This results in purely event driven authentication and is not secure.
        | `Reference <https://github.com/OWASP/owasp-mstg/blob/master/Document/0x05f-Testing-Local-Authentication.md>`__
        | `Reference <https://github.com/OWASP/owasp-mstg/blob/master/Document/0x05f-Testing-Local-Authentication.md#static-analysis>`__
        | `Reference CWE <https://cwe.mitre.org/data/definitions/287.html>`__

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
        >>> a.owasp_insecure_fingerprint_auth()
        """
        regex = r'\.authenticate\(null,.+\)'
        g = self._run_rg(regex=regex, code=show_code)
        match = self._process_match(g, owasp_category=['M4'])
        self._owasp_analysis['improper_fingerprint_auth'] = match
        self.log_debug('')
        return GreppedOut(match)

    @_logger
    def owasp_world_read_write_files(self, show_code=False) -> GreppedOut:
        """
        Locate if shared preferences are world readable or world writeable
        | `Reference <https://github.com/OWASP/owasp-mstg/blob/master/Document/0x05d-Testing-Data-Storage.md>`__
        | `Reference <https://github.com/OWASP/owasp-mstg/blob/master/Document/0x05d-Testing-Data-Storage.md#shared-preferences>`__
        | `Reference CWE <https://cwe.mitre.org/data/definitions/922.html>`__

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
        >>> a.owasp_world_read_write_files()
        """
        regex = r'MODE_WORLD_WRITABLE|MODE_WORLD_READABLE'
        g = self._run_rg(regex=regex, code=show_code)
        match = self._process_match(g, owasp_category=['M1', 'M2', 'M4'])
        self._owasp_analysis['world_read_write_files'] = match
        self.log_debug('')
        return GreppedOut(match)

    @_logger
    def owasp_encrypted_sql_db(self, show_code=False) -> GreppedOut:
        """
        Locate usage of getWritableDatabase if a paramter is passed to 
        this method. This could indicate hardcoded passwords. 
        | `Reference <https://github.com/OWASP/owasp-mstg/blob/master/Document/0x05d-Testing-Data-Storage.md>`__
        | `Reference <hhttps://github.com/OWASP/owasp-mstg/blob/master/Document/0x05d-Testing-Data-Storage.md#typical-misuse-hard-coded-cryptographic-keys>`__
        | `Reference Android SDK <https://developer.android.com/reference/android/database/sqlite/SQLiteOpenHelper#getWritableDatabase()>`__
        | `Reference CWE <https://cwe.mitre.org/data/definitions/522.html>`__

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
        >>> a.owasp_external_storage()
        """
        regex = self._IGNORE_IMPORTS + r'(getWritableDatabase\(\"?\w+\))'
        g = self._run_rg(regex=regex, code=show_code)
        match = self._process_match(g, owasp_category=['M1', 'M2', 'M4'])
        self._owasp_analysis['encrypted_db'] = match
        self.log_debug('')
        return GreppedOut(match)

    @_logger
    def owasp_external_storage(self, show_code=False) -> GreppedOut:
        """
        Locate usage of getExternal method usage. This indicates sections of  code where the external storage of the Android device is being 
        interacted with. 
        | `Reference <https://github.com/OWASP/owasp-mstg/blob/master/Document/0x05d-Testing-Data-Storage.md>`__
        | `Reference <https://github.com/OWASP/owasp-mstg/blob/master/Document/0x05d-Testing-Data-Storage.md#static-analysis>`__
        | `Reference Android SDK <https://developer.android.com/training/data-storage/files>`__
        | `Reference CWE <https://cwe.mitre.org/data/definitions/200.html>`__

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
        >>> a.owasp_external_storage()
        """
        regex = r'getExternal.+\(.+\)'
        g = self._run_rg(regex=regex, code=show_code)
        match = self._process_match(g, owasp_category=['M1', 'M2', 'M4'])
        self._owasp_analysis['external_storage'] = match
        self.log_debug('')
        return GreppedOut(match)

    @_logger
    def owasp_external_cache_dir(self, show_code=False) -> GreppedOut:
        """
        Locate usage of getExternalCacheDir method usage. If the app is 
        using the external cache dir.
        | `Reference <https://github.com/OWASP/owasp-mstg/blob/master/Document/0x05d-Testing-Data-Storage.md>`__
        | `Reference <https://github.com/OWASP/owasp-mstg/blob/master/Document/0x05d-Testing-Data-Storage.md#static-analysis>`__
        | `Reference Android SDK <https://developer.android.com/reference/android/content/Context.html#getExternalCacheDir()>`__
        | `Reference CWE <https://cwe.mitre.org/data/definitions/287.html>`__

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
        >>> a.owasp_external_cache_dir()
        """
        regex = self._IGNORE_IMPORTS + r'(getExternalCacheDirs\(.+\))'
        g = self._run_rg(regex=regex, code=show_code)
        match = self._process_match(g, owasp_category='M4')
        self._owasp_analysis['external_cache_dir'] = match
        self.log_debug('')
        return GreppedOut(match)

    @_logger
    def owasp_get_secret_keys(self, show_code=False) -> GreppedOut:
        """
        Locate usage of getSecretKey and getPrivateKey methods.
        | `Reference <https://github.com/OWASP/owasp-mstg/blob/master/Document/0x05d-Testing-Data-Storage.md>`__
        | `Reference <https://github.com/OWASP/owasp-mstg/blob/master/Document/0x05d-Testing-Data-Storage.md#keychain>`__
        | `Reference Android SDK <https://developer.android.com/reference/java/security/KeyStore.PrivateKeyEntry?hl=es-419#getPrivateKey()>`__
        | `Reference Android SDK <https://developer.android.com/reference/java/security/KeyStore.SecretKeyEntry.html?hl=es-419#getSecretKey()>`__
        | `Reference CWE <https://cwe.mitre.org/data/definitions/200.html>`__

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
        >>> a.owasp_get_secret_keys()
        """
        regex = self._IGNORE_IMPORTS + r'(getSecretKey\(\)|getPrivateKey\(\))'
        g = self._run_rg(regex=regex, code=show_code)
        match = self._process_match(g, owasp_category=['M1', 'M2', 'M4'])
        self._owasp_analysis['get_secret_key'] = match
        self.log_debug('')
        return GreppedOut(match)

    @_logger
    def owasp_keychain_password(self, show_code=False) -> GreppedOut:
        """
        Locate usage of store(OutputStream... to check for hardcoded 
        passwords for keychains.
        | `Reference <https://github.com/OWASP/owasp-mstg/blob/master/Document/0x05d-Testing-Data-Storage.md>`__
        | `Reference <https://github.com/OWASP/owasp-mstg/blob/master/Document/0x05d-Testing-Data-Storage.md#keychain>`__
        | `Reference Android SDK <https://developer.android.com/reference/java/security/KeyStore.html?hl=es-419#store(java.io.OutputStream,%20char[])>`__
        | `Reference CWE <https://cwe.mitre.org/data/definitions/200.html>`__

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
        >>> a.owasp_keychain_password()
        """
        regex = r'store\(OutputStream.+\)'
        g = self._run_rg(regex=regex, code=show_code)
        match = self._process_match(g, owasp_category=['M1', 'M2', 'M4'])
        self._owasp_analysis['keychain_password'] = match
        self.log_debug('')
        return GreppedOut(match)

    @_logger
    def owasp_cloud_backup(self, show_code=False) -> GreppedOut:
        """
        Locate usage of BackupAgent and its variations in the decompiled  code
        | `Reference <https://github.com/OWASP/owasp-mstg/blob/master/Document/0x05d-Testing-Data-Storage.md>`__
        | `Reference <Xhttps://github.com/OWASP/owasp-mstg/blob/master/Document/0x05d-Testing-Data-Storage.md#cloud>`__
        | `Reference Android SDK <https://developer.android.com/reference/android/app/backup/BackupAgent>`__

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
        >>> a.owasp_cloud_backup()
        """
        regex = self._IGNORE_IMPORTS + r'(BackupAgent(\w+)?)'
        g = self._run_rg(regex=regex, code=show_code)
        match = self._process_match(g, owasp_category=['M1', 'M2', 'M4'])
        self._owasp_analysis['kv_backup'] = match
        self.log_debug('')
        return GreppedOut(match)

    @_logger
    def owasp_webview_ssl_ignore(self, show_code=False) -> GreppedOut:
        """
        Locate usage of onReceivedSslError which amy indicate cases 
        where SSL errors are being ingored by the application.
        | `Reference <https://github.com/OWASP/owasp-mstg/blob/master/Document/0x05g-Testing-Network-Communication.md>`__
        | `Reference <https://github.com/OWASP/owasp-mstg/blob/master/Document/0x05g-Testing-Network-Communication.md#webview-server-certificate-verification>`__
        | `Reference Android SDK <https://developer.android.com/reference/android/webkit/WebViewClient.html#onReceivedSslError(android.webkit.WebView,%20android.webkit.SslErrorHandler,%20android.net.http.SslError)>`__

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
        >>> a.owasp_webview_ssl_ignore()
        """
        regex = r'onReceivedSslError'
        g = self._run_rg(regex=regex, code=show_code)
        match = self._process_match(g, owasp_category=['M3'])
        self._owasp_analysis['webview_ignore_ssl'] = match
        self.log_debug('')
        return GreppedOut(match)

    @_logger
    def owasp_ssl_no_hostname_verification(self, show_code=False) -> GreppedOut:
        """
        Locate usage of onReceivedSslError which amy indicate cases 
        where SSL errors are being ingored by the application.
        | `Reference <https://github.com/OWASP/owasp-mstg/blob/master/Document/0x05g-Testing-Network-Communication.md>`__
        | `Reference <https://github.com/OWASP/owasp-mstg/blob/master/Document/0x05g-Testing-Network-Communication.md#hostname-verification>`__
        | `Reference Android SDK <https://developer.android.com/reference/javax/net/ssl/HostnameVerifier>`__

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
        >>> a.owasp_ssl_no_hostname_verification()
        """
        regex = r'public boolean verify\(String hostname, SSLSession session\)'
        g = self._run_rg(regex=regex, code=show_code)
        match = self._process_match(g, owasp_category=['M3'])
        self._owasp_analysis['ssl_no_hostname_verification'] = match
        self.log_debug('')
        return GreppedOut(match)

    @_logger
    def owasp_keystore_cert_pinning(self, show_code=False) -> GreppedOut:
        """
        Locate keystore ssl pinning in decompiled code.
        | `Reference <https://github.com/OWASP/owasp-mstg/blob/master/Document/0x05g-Testing-Network-Communication.md>`__
        | `Reference <https://github.com/OWASP/owasp-mstg/blob/master/Document/0x05g-Testing-Network-Communication.md#trustmanager>`__
        | `Reference Android SDK <https://developer.android.com/reference/javax/net/ssl/TrustManagerFactory.html?hl=uk#getTrustManagers()>`__

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
        >>> a.owasp_keystore_cert_pinning()
        """
        regex = self._IGNORE_IMPORTS + r'(getTrustManagers\(\))'
        g = self._run_rg(regex=regex, code=show_code)
        match = self._process_match(g, owasp_category=['M3'])
        self._owasp_analysis['keystore_cert_pinning'] = match
        self.log_debug('')
        return GreppedOut(match)

    @_logger
    def owasp_webview_cert_pinning(self, show_code=False) -> GreppedOut:
        """
        Locate SSL cert pinning in webviews.
        | `Reference <https://github.com/OWASP/owasp-mstg/blob/master/Document/0x05g-Testing-Network-Communication.md>`__
        | `Reference <https://github.com/OWASP/owasp-mstg/blob/master/Document/0x05g-Testing-Network-Communication.md#network-libraries-and-webviews>`__
        | `Reference Android SDK <https://developer.android.com/reference/javax/net/ssl/TrustManagerFactory.html?hl=uk#getTrustManagers()>`__

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
        >>> a.owasp_webview_cert_pinning()
        """
        regex = r'CN=\w+'
        g = self._run_rg(regex=regex, code=show_code)
        match = self._process_match(g, owasp_category=['M3'])
        self._owasp_analysis['webview_cert_pinning'] = match
        self.log_debug('')
        return GreppedOut(match)

    @_logger
    def owasp_properly_signed(self, show_code=False) -> GreppedOut:
        """
        Returns the command that can be used to check if an app is properly 
        signed.
        | `Reference <https://github.com/OWASP/owasp-mstg/blob/master/Document/0x05i-Testing-Code-Quality-and-Build-Settings.md>`__
        | `Reference <https://github.com/OWASP/owasp-mstg/blob/master/Document/0x05i-Testing-Code-Quality-and-Build-Settings.md#making-sure-that-the-app-is-properly-signed>`__
        | `Reference Android SDK <https://developer.android.com/reference/javax/net/ssl/TrustManagerFactory.html?hl=uk#getTrustManagers()>`__

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
        >>> a.owasp_properly_signed()
        """
        command = f'apksigner verify --verbose {self._apk_path}'
        final = [{'command': command, 'owasp_category': ['M7']}]
        self._owasp_analysis['properly_signed'] = final
        self.log_debug('')
        return GreppedOut(final)

    @_logger
    def owasp_debug_code(self, show_code=False) -> GreppedOut:
        """
        Locate StrictMode code in the decompiled code. This will indicate if dev 
        checks are left behind in the app.
        | `Reference <https://github.com/OWASP/owasp-mstg/blob/master/Document/0x05i-Testing-Code-Quality-and-Build-Settings.md>`__
        | `Reference <https://github.com/OWASP/owasp-mstg/blob/master/Document/0x05i-Testing-Code-Quality-and-Build-Settings.md#finding-debugging-code-and-verbose-error-logging>`__
        | `Reference Android SDK <https://developer.android.com/reference/android/os/StrictMode>`__

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
        >>> a.owasp_debug_code()
        """
        regex = r'StrictMode\.(setThreadPolicy|VmPolicy)'
        g = self._run_rg(regex=regex, code=show_code)
        match = self._process_match(g, owasp_category=['M7'])
        self._owasp_analysis['webview_cert_pinning'] = match
        self.log_debug('')
        return GreppedOut(match)

    @_logger
    def owasp_runtime_exception_handling(self, show_code=False) -> GreppedOut:
        """
        Locate common exceptions thrown by RuntimeException from decompiled code.
        | `Reference <https://github.com/OWASP/owasp-mstg/blob/master/Document/0x05i-Testing-Code-Quality-and-Build-Settings.md>`__
        | `Reference <https://github.com/OWASP/owasp-mstg/blob/master/Document/0x05i-Testing-Code-Quality-and-Build-Settings.md#testing-exception-handling>`__
        | `Reference Android SDK <https://developer.android.com/reference/java/lang/RuntimeException>`__

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
        >>> a.owasp_runtime_exception_handling()
        """
        regex = self._IGNORE_IMPORTS + r'(ActivityNotFoundException|AndroidRuntimeException|AnnotationTypeMismatchException|ArithmeticException|ArrayStoreException|BufferOverflowException|BufferUnderflowException|ClassCastException|CompletionException|ConcurrentModificationException|DOMException|DateTimeException|EmptyStackException|EnumConstantNotPresentException|FileSystemAlreadyExistsException|FileSystemNotFoundException|FileUriExposedException|GLException|ICUUncheckedIOException|IllegalArgumentException|IllegalMonitorStateException|IllegalStateException|IllformedLocaleException|IncompleteAnnotationException|IndexOutOfBoundsException|InflateException|LSException|MalformedParameterizedTypeException|MalformedParametersException|MediaCodec|MissingResourceException|NegativeArraySizeException|NetworkOnMainThreadException|NoSuchElementException|NoSuchPropertyException|NullPointerException|OperationCanceledException|ParcelFormatException|ParseException|ProviderException|ProviderNotFoundException|RSRuntimeException|RejectedExecutionException|RemoteViews|SQLException|SecurityException|StaleDataException|Surface|SurfaceHolder|TimeFormatException|TypeNotPresentException|UncheckedIOException|UndeclaredThrowableException|UnsupportedOperationException|UserManager|WindowManager|WindowManager|WrongMethodTypeException)'
        g = self._run_rg(regex=regex, code=show_code)
        match = self._process_match(g, owasp_category=['M7'])
        self._owasp_analysis['runtime_exception'] = match
        self.log_debug('')
        return GreppedOut(match)

    @_logger
    def owasp_code_check_permission(self, show_code=False) -> GreppedOut:
        """
        Locate common exceptions thrown by RuntimeException from decompiled code.
        | `Reference <https://github.com/OWASP/owasp-mstg/blob/master/Document/0x05i-Testing-Code-Quality-and-Build-Settings.md>`__
        | `Reference <https://github.com/OWASP/owasp-mstg/blob/master/Document/0x05h-Testing-Platform-Interaction.md#static-analysis>`__
        | `Reference Android SDK <https://developer.android.com/reference/android/content/Context.html#checkCallingOrSelfPermission(java.lang.String)>`__

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
        >>> a.owasp_code_check_permission()
        """
        regex = self._IGNORE_IMPORTS + r'(checkCallingOrSelfPermission)'
        g = self._run_rg(regex=regex, code=show_code)
        match = self._process_match(g, owasp_category=['M7'])
        self._owasp_analysis['code_check_permission'] = match
        self.log_debug('')
        return GreppedOut(match)

    @_logger
    def owasp_intent_parameter(self, show_code=False) -> GreppedOut:
        """
        Locate common exceptions thrown by RuntimeException from decompiled code.
        | `Reference <https://github.com/OWASP/owasp-mstg/blob/master/Document/0x05h-Testing-Platform-Interaction.md>`__
        | `Reference <https://github.com/OWASP/owasp-mstg/blob/master/Document/0x05h-Testing-Platform-Interaction.md#static-analysis-1>`__
        | `Reference Android SDK <https://developer.android.com/reference/android/net/Uri>`__

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
        >>> a.owasp_intent_parameter()
        """
        regex = r'(getQueryParameter|getQueryParameterNames|getQueryParameters)\(.+\)'
        g = self._run_rg(regex=regex, code=show_code)
        match = self._process_match(g, owasp_category=['M7'])
        self._owasp_analysis['intent_parameters'] = match
        self.log_debug('')
        return GreppedOut(match)

    @_logger
    def owasp_webview_loadurl(self, show_code=False) -> GreppedOut:
        """
        Locate where webviews are loading content from.
        | `Reference <https://github.com/OWASP/owasp-mstg/blob/master/Document/0x05h-Testing-Platform-Interaction.md>`__
        | `Reference <https://github.com/OWASP/owasp-mstg/blob/master/Document/0x05h-Testing-Platform-Interaction.md#static-analysis-4>`__
        | `Reference Android SDK <https://developer.android.com/reference/android/webkit/WebView.html#loadUrl(java.lang.String)>`__

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
        >>> a.owasp_webview_loadurl()
        """
        regex = self._IGNORE_IMPORTS + r'(\.loadUrl\(.+\))'
        g = self._run_rg(regex=regex, code=show_code)
        match = self._process_match(g, owasp_category=['M7'])
        self._owasp_analysis['webview_loadurl'] = match
        self.log_debug('')
        return GreppedOut(match)

    @_logger
    def owasp_webview_native_function(self, show_code=False) -> GreppedOut:
        """
        Identify addJavascriptInterface which will allow JS to access native 
        Java functions.
        | `Reference <https://github.com/OWASP/owasp-mstg/blob/master/Document/0x05h-Testing-Platform-Interaction.md>`__
        | `Reference <https://github.com/OWASP/owasp-mstg/blob/master/Document/0x05h-Testing-Platform-Interaction.md#overview-5>`__
        | `Reference Android SDK <https://developer.android.com/reference/android/webkit/WebView#addJavascriptInterface(java.lang.Object,%20java.lang.String)>`__

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
        >>> a.owasp_webview_native_function()
        """
        regex = self._IGNORE_IMPORTS + r'(addJavascriptInterface\(.+\))'
        g = self._run_rg(regex=regex, code=show_code)
        match = self._process_match(g, owasp_category=['M7'])
        self._owasp_analysis['webview_native_java'] = match
        self.log_debug('')
        return GreppedOut(match)
