from __future__ import annotations
from .androidcore import _AndroidCore
from ...out import GreppedOut
from ...logger import _logger
from .constants import _GrepConstants


class _CodeAnalysis(_AndroidCore, _GrepConstants):

    def all_code_analysis(self) -> GreppedOut:
        """
        Property runs all available checks in _CodeAnalysis

        :return: Dictionary of all other analysis

        >>> from glorifiedgrep import GlorifiedAndroid
        >>> a = GlorifiedAndroid('/path/to/apk')
        >>> a.all_code_analysis()
        """
        methods = [p for p in vars(
            _CodeAnalysis).keys() if not p.startswith('_')]
        [getattr(self, m)() for m in methods if m not in [
            'all_code_analysis', 'code_search']]
        self.log_debug('')
        return self._android_findings['code_analysis']

    @_logger
    def code_command_exec(self, show_code: bool = False) -> GreppedOut:
        """
        Find all commands executed in shell using /bin/sh or .exec() in the decompiled source

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
        >>> a.code_command_exec()
        """
        regex = r'/bin/sh.*|\.exec\(.+\)'
        match = self._run_rg_and_process(regex=regex, code=show_code)
        self._code_analysis['command_exec'] = match
        self.log_debug('')
        return GreppedOut(match)

    @_logger
    def code_create_tempfile(self, show_code: bool = False) -> GreppedOut:
        """
        Find all code which is using Java createTempFile 
        | `Reference <https://developer.android.com/reference/java/io/File>`__

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
        >>> a.code_create_tempfile()
        """
        regex = self._IGNORE_IMPORTS + r'(\.createTempFile\(.*\))'
        match = self._run_rg_and_process(regex=regex, code=show_code)
        self._code_analysis['temp_file'] = match
        self.log_debug('')
        return GreppedOut(match)

    @_logger
    def code_file_observer(self, show_code: bool = False) -> GreppedOut:
        """
        Find all instances of the FileObserver class being used. This 
        class is used to check for file access or change and fire and event.
        | `Reference <https://developer.android.com/reference/android/os/FileObserver>`__

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
        >>> a.code_file_observer()
        """
        regex = r'FileObserver'
        match = self._run_rg_and_process(regex=regex, code=show_code)
        self._code_analysis['file_observer'] = match
        self.log_debug('')
        return GreppedOut(match)

    @_logger
    def code_dynamic_dexclassloader(self, show_code: bool = False) -> GreppedOut:
        """
        Find all instances of DexClassLoader in the decompiled source. 
        This can be used to execute code not installed as part of an application. 
        | `Reference <https://developer.android.com/reference/dalvik/system/DexClassLoader>`__

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
        >>> a.code_dynamic_dexclassloader()
        """
        regex = r'\bDexClassLoader|\bloadDex\b|\bloadDexFile\b'
        match = self._run_rg_and_process(regex=regex, code=show_code)
        self._code_analysis['dexclassloader'] = match
        self.log_debug('')
        return GreppedOut(match)

    @_logger
    def code_dynamic_other_classloader(self, show_code: bool = False) -> GreppedOut:
        """
        Find all instances of BaseDexClassLoader, SecureClassLoader, 
        DelegateLastClassLoader, DexClassLoader, InMemoryDexClassLoader, PathClassLoader, 
        URLClassLoader, Classloader in the decompiled source. 
        This can be used to execute code not installed as part of an application. 
        | `Reference <https://developer.android.com/reference/java/lang/ClassLoader>`__

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
        >>> a.code_dynamic_other_classloader()
        """
        regex = r'\bBaseDexClassLoader|\bSecureClassLoader|\bDelegateLastClassLoader|\bInMemoryDexClassLoader|\bPathClassLoader|\bURLClassLoader|\bClassloader'
        match = self._run_rg_and_process(regex=regex, code=show_code)
        self._code_analysis['classloader_other'] = match
        self.log_debug('')
        return GreppedOut(match)

    @_logger
    def code_cipher_instance(self, show_code: bool = False) -> GreppedOut:
        """
        Find all instances of Cipher.getInstance in the decompiled source. 
        class provides the functionality of a cryptographic cipher for encryption and decryption. 
        It forms the core of the Java Cryptographic Extension (JCE) framework.
        | `Reference <https://developer.android.com/reference/javax/crypto/Cipher>`__

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
        >>> a.code_cipher_instance()
        """
        regex = r'(Cipher.getInstance\(\"(.+)\"\)|([A-Z]{3}/[A-Z]{3}/\w+))'
        g = self._run_rg(regex=regex, code=show_code, group="-r '$2$3'")
        match = self._process_match(g)
        self._code_analysis['cipher_instance'] = match
        self.log_debug('')
        return GreppedOut(match)

    @_logger
    def code_key_generator(self, show_code: bool = False) -> GreppedOut:
        """
        Find all instances of KeyGenerator and its methods in the decompiled source. 
        This class provides the functionality of a secret (symmetric) key generator
        | `Reference <https://developer.android.com/reference/javax/crypto/KeyGenerator>`__
        | `Reference <https://developer.android.com/reference/javax/crypto/SecretKey>`__

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
        >>> a.code_key_generator()
        """
        regex = r'^([^import].+)(KeyGenerator|SecretKey|generateKey)'
        match = self._run_rg_and_process(regex=regex, code=show_code)
        self._code_analysis['key_generators'] = match
        self.log_debug('')
        return GreppedOut(match)

    @_logger
    def code_webview_database(self, show_code: bool = False) -> GreppedOut:
        """
        This allows developers to determine whether any WebView used in the application has 
        stored any of the following types of browsing data and to clear any such stored data 
        for all WebViews in the application.
        | `Reference <https://developer.android.com/reference/android/webkit/WebViewDatabase>`__

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
        >>> a.code_webview_database()
        """
        regex = r'clearHttpAuthUsernamePassword|clearUsernamePassword|hasFormData|hasHttpAuthUsernamePassword|hasUsernamePassword'
        match = self._run_rg_and_process(regex=regex, code=show_code)
        self._code_analysis['webview_database'] = match
        self.log_debug('')
        return GreppedOut(match)

    @_logger
    def code_webview_js_enabled(self, show_code: bool = False) -> GreppedOut:
        """
        This method looks for any webview implementations where JavaScript is enabled.
        | `Reference <https://developer.android.com/reference/android/webkit/WebSettings>`__

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
        >>> a.code_webview_js_enabled()
        """
        regex = r'setJavaScriptEnabled\(.+\)'
        match = self._run_rg_and_process(regex=regex, code=show_code)
        self._code_analysis['webview_js_enabled'] = match
        self.log_debug('')
        return GreppedOut(match)

    @_logger
    def code_webview_debug_enabled(self, show_code: bool = False) -> GreppedOut:
        """
        This method looks to see if debug is enabled in webview.
        | `Reference <https://developer.android.com/reference/android/webkit/WebView.html#setWebContentsDebuggingEnabled(boolean)>`__

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
        >>> a.code_webview_debug_enabled()
        """
        regex = r'setWebContentsDebuggingEnabled'
        match = self._run_rg_and_process(regex=regex, code=show_code)
        self._code_analysis['webview_debug'] = match
        self.log_debug('')
        return GreppedOut(match)

    @_logger
    def code_webview_file_access(self, show_code: bool = False) -> GreppedOut:
        """
        This method looks for any webview implementations where the webview 
        has file access.
        | `Reference <https://developer.android.com/reference/android/webkit/WebSettings>`__

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
        >>> a.code_webview_file_access()
        """
        regex = r'(setAllowFileAccess|setAllowFileAccessFromFileURLs|setAllowUniversalAccessFromFileURLs)\(.+\)'
        match = self._run_rg_and_process(regex=regex, code=show_code)
        self._code_analysis['webview_file_access'] = match
        self.log_debug('')
        return GreppedOut(match)

    @_logger
    def code_webview_content_access(self, show_code: bool = False) -> GreppedOut:
        """
        This method looks for any webview implementations where the webview 
        has can access data from a content provider.
        | `Reference Android SDK <https://developer.android.com/reference/android/webkit/WebSettings.html#setAllowContentAccess(boolean)>`__
        | `Reference Android SDK <https://github.com/OWASP/owasp-mstg/blob/master/Document/0x05h-Testing-Platform-Interaction.md#static-analysis-4>`__

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
        >>> a.code_webview_content_access()
        """
        regex = r'setAllowContentAccess\(true\)'
        match = self._run_rg_and_process(regex=regex, code=show_code)
        self._code_analysis['webview_content_access'] = match
        self.log_debug('')
        return GreppedOut(match)

    @_logger
    def code_sql_select_raw_query(self, show_code: bool = False) -> GreppedOut:
        """
        This method looks for any SELECT queries in the decompiled code.

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
        >>> a.code_sql_select_raw_query()
        """
        regex = r'\"(SELECT\s.+)\"'
        g = self._run_rg(regex=regex, code=show_code, group="-r '$1'")
        match = self._process_match(g)
        self._code_analysis['sql_select_query'] = match
        self.log_debug('')
        return GreppedOut(match)

    @_logger
    def code_sql_query_other(self, show_code: bool = False) -> GreppedOut:
        """
        This method looks for any other SQL queries like INSERT, DROP etc 
        in the decompiled code.
        | `Reference <https://developer.android.com/reference/android/database/sqlite/SQLiteDatabase.html#execSQL(java.lang.String)>`__

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
        >>> a.code_sql_query_other()
        """
        regex = r'execSQL\(.+\)'
        match = self._run_rg_and_process(regex=regex, code=show_code)
        self._code_analysis['sql_other_query'] = match
        self.log_debug('')
        return GreppedOut(match)

    @_logger
    def code_sqlite_operations(self, show_code: bool = False) -> GreppedOut:
        """
        This getWritableDatabase and the getReadableDatabase methods db 
        instances for sqlite opertations. These calls can be followed to 
        check what data is being entered in the database.
        | `Reference <https://developer.android.com/reference/android/database/sqlite/SQLiteOpenHelper#getWritableDatabase()>`__

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
        >>> a.code_sqlite_operations()
        """
        regex = r'get(Writable|Readable)Database'
        match = self._run_rg_and_process(regex=regex, code=show_code)
        self._code_analysis['sqlite_operations'] = match
        self.log_debug('')
        return GreppedOut(match)

    @_logger
    def code_sqlcipher_password(self, show_code: bool = False) -> GreppedOut:
        """
        This getWritableDatabase and the getReadableDatabase methods from 
        sqlcipher classes (3rd party) takes the db password as their argument. 
        | `Reference <https://www.programcreek.com/java-api-examples/index.php?api=net.sqlcipher.database.SQLiteOpenHelper>`__

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
        >>> a.code_sqlcipher_password()
        """
        regex = r'get(Writable|Readable)Database\(.+\)'
        match = self._run_rg_and_process(regex=regex, code=show_code)
        self._code_analysis['sqlcipher_password'] = match
        self.log_debug('')
        return GreppedOut(match)

    @_logger
    def code_sql_injection_points(self, show_code: bool = False) -> GreppedOut:
        """
        This method looks for execquery. If user input is used in this query, 
        this will lead to SQL injection.
        | `Reference <http://find-sec-bugs.github.io/bugs.htm#CUSTOM_INJECTION>`__ 
        | `Reference <http://find-sec-bugs.github.io/bugs.htm#SQL_INJECTION>`__ 
        | `Reference <http://find-sec-bugs.github.io/bugs.htm#SQL_INJECTION_HIBERNATE>`__ 
        | `Reference <http://find-sec-bugs.github.io/bugs.htm#SQL_INJECTION_JDO>`__ 
        | `Reference <http://find-sec-bugs.github.io/bugs.htm#SQL_INJECTION_SPRING_JDBC>`__ 

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
        >>> a.code_sql_injection_points()
        """
        regex = r'execQuery|createQuery|executeQuery|newQuery|queryForObject'
        match = self._run_rg_and_process(regex=regex, code=show_code)
        self._code_analysis['sql_execquery'] = match
        self.log_debug('')
        return GreppedOut(match)

    @_logger
    def code_get_environment_var(self, show_code: bool = False) -> GreppedOut:
        """
        This method looks for usage of getenv in the decompiled code.
        | `Reference <https://github.com/OWASP/owasp-mstg/blob/master/Document/0x05j-Testing-Resiliency-Against-Reverse-Engineering.md#common-root-detection-methods>`__

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
        >>> a.code_get_environment_var()
        """
        regex = r'getenv\(.+\)'
        match = self._run_rg_and_process(regex=regex, code=show_code)
        self._code_analysis['getenv'] = match
        self.log_debug('')
        return GreppedOut(match)

    @_logger
    def code_debugger_check(self, show_code: bool = False) -> GreppedOut:
        """
        This method looks for usage of isDebuggerConnected in the decompiled code.
        | `Reference <https://github.com/OWASP/owasp-mstg/blob/master/Document/0x05j-Testing-Resiliency-Against-Reverse-Engineering.md#isdebuggerconnected>`__

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
        >>> a.code_debugger_check()
        """
        regex = r'isDebuggerConnected\(\)|ptrace\(.+\)'
        match = self._run_rg_and_process(regex=regex, code=show_code)
        self._code_analysis['check_debugger'] = match
        self.log_debug('')
        return GreppedOut(match)

    @_logger
    def code_debuggable_check(self, show_code: bool = False) -> GreppedOut:
        """
        This method looks for code what will check if the app is 
        debuggable at run time. 
        | `Reference <https://developer.android.com/reference/android/content/Context#getApplicationContext()>`__

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
        >>> a.code_debuggable_check()
        """
        regex = r'getApplicationInfo\(\).flags|ApplicationInfo\.FLAG_DEBUGGABLE|BuildConfig\.DEBUG'
        match = self._run_rg_and_process(regex=regex, code=show_code)
        self._code_analysis['check_debuggable'] = match
        self.log_debug('')
        return GreppedOut(match)

    @_logger
    def code_device_serial_number(self, show_code: bool = False) -> GreppedOut:
        """
        This method looks for Build.SERIAL which can sometimes be used 
        in addition with other things to build unique tokens.
        | `Reference <https://github.com/OWASP/owasp-mstg/blob/master/Document/0x05j-Testing-Resiliency-Against-Reverse-Engineering.md#imei--serial>`__

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
        >>> a.code_device_serial_number()
        """
        regex = r'\w+\.SERIAL'
        match = self._run_rg_and_process(regex=regex, code=show_code)
        self._code_analysis['serial_number'] = match
        self.log_debug('')
        return GreppedOut(match)

    @_logger
    def code_sql_java_implementation(self, show_code: bool = False) -> GreppedOut:
        """
        This method looks for any other SQL queries that are implemented 
        in Java. This searches for .query, .insert, .update and .delete methods.
        | `Reference <https://developer.android.com/training/data-storage/sqlite#java>`__

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
        >>> a.code_sql_java_implementation()
        """
        match = {}
        java_query = r'\.query\(.+\)'
        java_insert = r'\.insert\(.+\)'
        java_update = r'\.update\(.+\)'
        java_delete = r'\.delete\(.+\)'
        match['query'] = self._process_match(self._run_rg(
            regex=java_query, code=show_code))
        match['insert'] = self._process_match(self._run_rg(
            regex=java_insert, code=show_code))
        match['update'] = self._process_match(self._run_rg(
            regex=java_update, code=show_code))
        match['delete'] = self._process_match(self._run_rg(
            regex=java_delete, code=show_code))
        self._code_analysis['sql_java_implementation'] = match
        self.log_debug('')
        return GreppedOut(match)

    @_logger
    def code_stub_packed(self, show_code: bool = False) -> GreppedOut:
        """
        This method looks for indication that the application is packed.

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
        >>> a.code_stub_packed()
        """
        regex = r'StubApp'  # ! TODO this could be improved upon, add more packers here
        match = self._run_rg_and_process(regex=regex, code=show_code)
        if len(match) == 0:
            self._code_analysis['packed'] = False
        else:
            self._code_analysis['packed'] = match
        self.log_debug('')
        return GreppedOut(match)

    @_logger
    def code_api_builder(self, show_code: bool = False) -> GreppedOut:
        """
        This method makes a best effort to detect api string builders 
        within the decompiled Java code.

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
        >>> a.code_api_builder()
        """
        regex = r'(?:/[A-Za-z\d.][A-Za-z0-9-.]{0,61})+'
        match = self._run_rg_and_process(regex=regex, code=show_code)
        self._code_analysis['api_builder'] = match
        self.log_debug('')
        return GreppedOut(match)

    @_logger
    def code_shared_preferences(self, show_code: bool = False) -> GreppedOut:
        """
        This method discovers SharePreference and getSharePreference from the 
        decompiled code. Interface for accessing and modifying preference data returned 
        by Context.getSharedPreferences
        within the decompiled Java code.
        | `Reference <https://developer.android.com/reference/android/content/Context#getSharedPreferences(java.lang.String,%20int)>`__
        | `Reference <https://developer.android.com/reference/android/content/SharedPreferences>`__

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
        >>> a.code_shared_preferences()
        """
        regex = r'^([^import].+)(\bSharedPreferences\b|getSharedPreferences)'
        match = self._run_rg_and_process(regex=regex, code=show_code)
        self._code_analysis['shared_prefs'] = match
        self.log_debug('')
        return GreppedOut(match)

    @_logger
    def code_file_read(self, show_code: bool = False) -> GreppedOut:
        """
        This method looks for FileInputStream within the decompiled Java code 
        which would indicate which files the app is reading.
        | `Reference <https://github.com/OWASP/owasp-mstg/blob/master/Document/0x05d-Testing-Data-Storage.md#internal-storage>`__

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
        >>> a.code_file_read()
        """
        regex = r'^([^import].+)(FileInputStream\(.+\)|openFileOutput)'
        match = self._run_rg_and_process(regex=regex, code=show_code)
        self._code_analysis['file_read'] = match
        self.log_debug('')
        return GreppedOut(match)

    @_logger
    def code_file_write(self, show_code: bool = False) -> GreppedOut:
        """
        This method looks for getByes() method which can indicate files 
        being written by the app.
        | `Reference <https://developer.android.com/reference/java/io/FileOutputStream>`__

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
        >>> a.code_write_file()
        """
        regex = r'\.write\(\w+\.getBytes\(\)\)'
        match = self._run_rg_and_process(regex=regex, code=show_code)
        self._code_analysis['file_write'] = match
        self.log_debug('')
        return GreppedOut(match)

    @_logger
    def code_logging(self, show_code: bool = False) -> GreppedOut:
        """
        This method looks for the usage of Log class from Android SDK.
        | `Reference <https://developer.android.com/reference/android/util/Log>`__

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
        >>> a.code_logging()
        """
        regex = r'Log\.[vdiwe]\(.+\)'
        match = self._run_rg_and_process(regex=regex, code=show_code)
        self._code_analysis['logging'] = match
        self.log_debug('')
        return GreppedOut(match)

    @_logger
    def code_xor_encryption(self, show_code: bool = False) -> GreppedOut:
        """
        This method looks for XOR encryption operation within the 
        decompiled code.

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
        >>> a.code_xor_encryption()
        """
        regex = r'\w+\[.+\].+\^.+\w+\[.+\]'
        match = self._run_rg_and_process(regex=regex, code=show_code)
        self._code_analysis['xor_encryption'] = match
        self.log_debug('')
        return GreppedOut(match)

    @_logger
    def code_load_native_library(self, show_code: bool = False) -> GreppedOut:
        """
        This method identifies where native libaries and loaded in the 
        decompiled code.
        | `Reference Android SDK <https://developer.android.com/reference/java/lang/System#loadLibrary(java.lang.String)>`__

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
        >>> a.code_load_native_library()
        """
        regex = r'System\.load\(.+\)|System\.loadLibrary\(.+\)'
        match = self._run_rg_and_process(regex=regex, code=show_code)
        self._code_analysis['native'] = match
        self.log_debug('')
        return GreppedOut(match)

    @_logger
    def code_intent_parameters(self, show_code: bool = False) -> GreppedOut:
        """
        This method will identify usage of the getStringExtra which is 
        used to create parameters for intents.
        | `Reference Android SDK <https://developer.android.com/reference/android/content/Intent#getStringExtra(java.lang.String)>`__
        | `Reference OWASP <https://github.com/OWASP/owasp-mstg/blob/master/Document/0x05h-Testing-Platform-Interaction.md#broadcast-receivers>`__

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
        >>> a.code_intent_parameters()
        """
        regex = r'getStringExtra\(.+\)'
        match = self._run_rg_and_process(regex=regex, code=show_code)
        self._code_analysis['intent_param'] = match
        self.log_debug('')
        return GreppedOut(match)

    @_logger
    def code_tcp_sockets(self, show_code: bool = False) -> GreppedOut:
        """
        This method will identify TCP sockets being opened by the 
        decompiled code.
        | `Reference Android SDK <https://developer.android.com/reference/java/net/Socket>`__

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
        >>> a.code_tcp_sockets()
        """
        regex = r'^([^import].+)(\bSocket\(.*\)|MulticastSocket\(.*\)|ServerSocket\(.*\))'
        match = self._run_rg_and_process(regex=regex, code=show_code)
        self._code_analysis['tcp_socket'] = match
        self.log_debug('')
        return GreppedOut(match)

    @_logger
    def code_udp_sockets(self, show_code: bool = False) -> GreppedOut:
        """
        This method will identify UDP sockets being opened by the 
        decompiled code.
        | `Reference Android SDK <https://developer.android.com/reference/java/net/DatagramSocket>`__

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
        >>> a.code_udp_sockets()
        """
        regex = r'^([^import].+)(\bDatagram(Socket|Packet))'
        match = self._run_rg_and_process(regex=regex, code=show_code)
        self._code_analysis['udp_socket'] = match
        self.log_debug('')
        return GreppedOut(match)

    @_logger
    def code_create_sockets(self, show_code: bool = False) -> GreppedOut:
        """
        An InetSocketAddress is a special SocketAddress designed to represent 
        the standard TCP Protocol address, so it thus has methods to set/query 
        the host name, IP address, and Socket of the remote side of the connection 
        (or, in fact the local side too) 
        | `Reference Android SDK <https://developer.android.com/reference/java/net/InetSocketAddress>`__ 
        | `Reference Android SDK <https://stackoverflow.com/a/32357906/7402287>`__ 

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
        >>> a.code_create_sockets()
        """
        regex = r'new InetSocketAddress\(.+\)'
        match = self._run_rg_and_process(regex=regex, code=show_code)
        self._code_analysis['create_socket'] = match
        self.log_debug('')
        return GreppedOut(match)

    @_logger
    def code_system_service(self, show_code: bool = False) -> GreppedOut:
        """
        This method will identify systemservices being called.
        | `Reference Android SDK <https://developer.android.com/reference/android/app/Activity#getSystemService(java.lang.String)>`__

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
        >>> a.code_system_service()
        """
        regex = self._IGNORE_IMPORTS + r'(getSystemService\(.+\))'
        match = self._run_rg_and_process(regex=regex, code=show_code)
        self._code_analysis['system_service'] = match
        self.log_debug('')
        return GreppedOut(match)

    @_logger
    def code_make_http_request(self, show_code: bool = False) -> GreppedOut:
        """
        This method will identify when a HTTP connection is being made 
        in the decompiled code. 
        | `Reference Android SDK <https://developer.android.com/reference/java/net/HttpURLConnection>`__

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
        >>> a.code_make_http_request()
        """
        regex = r'^([^import].+)(HttpURLConnection|openConnection|\bHttpRequest\b)'
        match = self._run_rg_and_process(regex=regex, code=show_code)
        self._code_analysis['http_connection'] = match
        self.log_debug('')
        return GreppedOut(match)

    @_logger
    def code_http_request_methods(self, show_code: bool = False) -> GreppedOut:
        """
        This method will identify what HTTP request methods are being used. 
        | `Reference Android SDK <https://developer.android.com/reference/java/net/HttpURLConnection.html#setRequestMethod(java.lang.String)>`__

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
        >>> a.code_http_request_methods()
        """
        regex = r'^([^import].+)(setRequestMethod\(.+\))'
        match = self._run_rg_and_process(regex=regex, code=show_code)
        self._code_analysis['http_request_method'] = match
        self.log_debug('')
        return GreppedOut(match)

    @_logger
    def code_make_https_request(self, show_code: bool = False) -> GreppedOut:
        """
        This method will identify when a HTTPS connection is being made 
        in the decompiled code. 
        | `Reference Android SDK <https://developer.android.com/reference/javax/net/ssl/HttpsURLConnection>`__

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
        >>> a.code_make_http_request()
        """
        regex = r'^([^import].+)(HttpsURLConnection\b)'
        match = self._run_rg_and_process(regex=regex, code=show_code)
        self._code_analysis['https_connection'] = match
        self.log_debug('')
        return GreppedOut(match)

    @_logger
    def code_broadcast_messages(self, show_code: bool = False) -> GreppedOut:
        """
        This method will identify what broadcast messages are being 
        sent in the decompiled code. 
        | `Reference Android SDK <https://developer.android.com/guide/components/broadcasts>`__

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
        >>> a.code_broadcast_messages()
        """
        regex = r'sendBroadcast\(.*\)|sendOrderedBroadcast\(.*\)|sendStickyBroadcast\(.*\)'
        match = self._run_rg_and_process(regex=regex, code=show_code)
        self._code_analysis['broadcast_messages'] = match
        self.log_debug('')
        return GreppedOut(match)

    @_logger
    def code_services(self, show_code: bool = False) -> GreppedOut:
        """
        This method will identify what services are being started 
        or being bound to. 
        | `Reference Android SDK <https://developer.android.com/guide/components/services>`__

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
        >>> a.code_services()
        """
        regex = r'(startService|bindService)\(.*\)'
        match = self._run_rg_and_process(regex=regex, code=show_code)
        self._code_analysis['services'] = match
        self.log_debug('')
        return GreppedOut(match)

    @_logger
    def code_webview_get_request(self, show_code: bool = False) -> GreppedOut:
        """
        This method will identify webview get requests. 
        | `Reference Android SDK <https://developer.android.com/reference/android/webkit/WebView#loadData(java.lang.String,%20java.lang.String,%20java.lang.String)>`__

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
        >>> a.code_webview_get_request()
        """
        regex = r'\.loadData\(.*\)'
        match = self._run_rg_and_process(regex=regex, code=show_code)
        self._code_analysis['webview_get'] = match
        self.log_debug('')
        return GreppedOut(match)

    @_logger
    def code_webview_post_request(self, show_code: bool = False) -> GreppedOut:
        """
        This method will identify webview get requests. 
        | `Reference Android SDK <https://developer.android.com/reference/android/webkit/WebView#postUrl(java.lang.String,%20byte[])>`__

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
        >>> a.code_webview_post_request()
        """
        regex = r'\.postUrl\(.*\)'
        match = self._run_rg_and_process(regex=regex, code=show_code)
        self._code_analysis['webview_post'] = match
        self.log_debug('')
        return GreppedOut(match)

    @_logger
    def code_sim_information(self, show_code: bool = False) -> GreppedOut:
        """
        This method will identify where device sim card information 
        is being obtained. 
        | `Reference Android SDK <https://developer.android.com/reference/android/telephony/TelephonyManager#getSimOperator()>`__

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
        >>> a.code_sim_information()
        """
        regex = r'\.getSimOperator\(\)'
        match = self._run_rg_and_process(regex=regex, code=show_code)
        self._code_analysis['sim_info'] = match
        self.log_debug('')
        return GreppedOut(match)

    @_logger
    def code_device_id(self, show_code: bool = False) -> GreppedOut:
        """
        This method will identify where device id 
        is being obtained. 
        | `Reference Android SDK <https://developer.android.com/reference/android/telephony/TelephonyManager#getDeviceId()>`__

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
        >>> a.code_device_id()
        """
        regex = r'\.getDeviceId\(\)'
        match = self._run_rg_and_process(regex=regex, code=show_code)
        self._code_analysis['device_id'] = match
        self.log_debug('')
        return GreppedOut(match)

    @_logger
    def code_base64_decode(self, show_code: bool = False) -> GreppedOut:
        """
        This method will identify base64 decode operations. 

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
        >>> a.code_base64_decode()
        """
        regex = r'Base64\.decode\(.*\)'
        match = self._run_rg_and_process(regex=regex, code=show_code)
        self._code_analysis['base64_decode'] = match
        # self.log_debug('')
        return GreppedOut(match)

    @_logger
    def code_base64_encode(self, show_code: bool = False) -> GreppedOut:
        """
        This method will identify base64 encode operations. 

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
        >>> a.code_base64_encode()
        """
        regex = r'Base64\.encodeToString\(.*\)'
        match = self._run_rg_and_process(regex=regex, code=show_code)
        self._code_analysis['base64_encode'] = match
        self.log_debug('')
        return GreppedOut(match)

    @_logger
    def code_gps_location(self, show_code: bool = False) -> GreppedOut:
        """
        This method will identify where GPS locations are being used. 

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
        >>> a.code_gps_location()
        """
        regex = r'(getLastKnownLocation|requestLocationUpdates|getLatitude|getLongitude)\(.*\)'
        match = self._run_rg_and_process(regex=regex, code=show_code)
        self._code_analysis['gps'] = match
        self.log_debug('')
        return GreppedOut(match)

    @_logger
    def code_clipboard_manager(self, show_code: bool = False) -> GreppedOut:
        """
        This method will identify where valies are being set or 
        read from the clipboard. 
        | `Reference Android SDK <https://developer.android.com/reference/android/content/ClipboardManager>`__

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
        >>> a.code_clipboard_manager()
        """
        regex = r'^([^import].+)(ClipboardManager)'
        match = self._run_rg_and_process(regex=regex, code=show_code)
        self._code_analysis['clipboard'] = match
        self.log_debug('')
        return GreppedOut(match)

    @_logger
    def code_password_finder(self, show_code: bool = False) -> GreppedOut:
        """
        This method will identify possible passwords in the code. 

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
        >>> a.code_password_finder()
        """
        regex = r'Cryptor.decrypt\(\(String\)*|Cipher.getInstance\(*|SecretKeySpec*|javax.crypto.spec.SecretKeySpec|DES_KEY.*=*|SPECIAL_TOKEN*|private.*\.getBytes|getSecurityString*|securityPutString*|PUBLIC_KEY*|LIVE_KEY*|PRIVATE_KEY*|api_key|\sKEY.=|\siv.=|local.*KeySpec\\.<init>|byte\[\].*key'
        match = self._run_rg_and_process(regex=regex, code=show_code)
        self._code_analysis['passwords'] = match
        self.log_debug('')
        return GreppedOut(match)

    @_logger
    def code_apk_files(self, show_code: bool = False) -> GreppedOut:
        """
        This method will identify if calls to apk files are hardcoded. 

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
        >>> a.code_apk_files()
        """
        regex = r'\".*\.apk\"'
        match = self._run_rg_and_process(regex=regex, code=show_code)
        self._code_analysis['apk_calls'] = match
        self.log_debug('')
        return GreppedOut(match)

    @_logger
    def code_keystore_files(self, show_code: bool = False) -> GreppedOut:
        """
        This method will identify where Bouncy castle bks or jks files are being used. 

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
        >>> a.code_keystore_files()
        """
        regex = r'\.bks|\.jks'
        match = self._run_rg_and_process(regex=regex, code=show_code)
        self._code_analysis['bks_files'] = match
        self.log_debug('')
        return GreppedOut(match)

    @_logger
    def code_string_constants(self, show_code: bool = False) -> GreppedOut:
        """
        This method will create a dictionary of hardcoded string constants.

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
        >>> a.code_string_constants()
        """
        def match_handler() -> GreppedOut:
            match['file'] = file_path
            match['line'] = line[1]
            d = line[2].split('"')
            if len(d) == 3:
                match['var'] = d[0]
                match['val'] = d[1]
                final.append(match)

        regex = r'static final String (\w+)( = )(\".*\")'
        out = self._run_rg(regex=regex, group="-r '$1$3'", code=show_code)
        final = []
        for f in out:
            match = {}
            f = f.decode('utf-8')
            line = f.split(':')
            file_path = self._re_remove_dir_prefix(line[0])
            match_handler()
        self._code_analysis['string_constants'] = final
        self.log_debug('')
        return GreppedOut(final)

    @_logger
    def code_byte_constants(self, show_code: bool = False) -> GreppedOut:
        """
        This method will create a dictionary of hardcoded byte constants.

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
        >>> a.code_byte_constants()
        """
        def match_handler() -> GreppedOut:
            match['file'] = file_path
            match['line'] = line[1]
            d = line[2].split(' ')
            match['var'] = d[0]
            match['val'] = ' '.join(d[1:])
            final.append(match)

        regex = r'static final byte\[\] (\w+)( = )(.*;)'
        out = self._run_rg(regex=regex, group="-r '$1 $3'", code=show_code)
        final = []
        for f in out:
            match = {}
            f = f.decode('utf-8')
            line = f.split(':')
            # print(line)
            file_path = self._re_remove_dir_prefix(line[0])
            match_handler()
        self._code_analysis['byte_constants'] = final
        self.log_debug('')
        return GreppedOut(final)

    @_logger
    def code_hashing_algorithms(self, show_code: bool = False) -> GreppedOut:
        """
        This method will identify hashing algorithms being used. 

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
        >>> a.code_hashing_algorithms()
        """
        regex = r'MessageDigest\.getInstance\(.+\)'
        match = self._run_rg_and_process(regex=regex, code=show_code)
        self._code_analysis['hash_algorithm'] = match
        self.log_debug('')
        return GreppedOut(match)

    @_logger
    def code_weak_hashing(self, show_code: bool = False) -> GreppedOut:
        """
        This method will identify where weak hashing algorithems such as 
        MD5, MD4, SHA1 or any RC hashes are used. 
        | `Reference <https://developer.mozilla.org/en-US/docs/Web/Security/Weak_Signature_Algorithm>`__

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
        >>> a.code_weak_hashing()
        """
        regex = r'\.getInstance\(\"MD5\"\)|\.getInstance\(\"md5\"\)|\.getInstance\(\"SHA1\"\)|\.getInstance\(\"sha1\"\)|\.getInstance\(\"MD4\"\)|\.getInstance\(\"md4\"\)|\.getInstance\(\"RC[0-9]\"\)'
        match = self._run_rg_and_process(regex=regex, code=show_code)
        self._code_analysis['hash_weak'] = match
        self.log_debug('')
        return GreppedOut(match)

    @_logger
    def code_hashing_custom(self, show_code: bool = False) -> GreppedOut:
        """
        This method will identify custom hashing algorithms being used. 
        | `Reference <http://find-sec-bugs.github.io/bugs.htm#CUSTOM_MESSAGE_DIGEST>`__

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
        >>> a.code_hashing_custom()
        """
        regex = r'extends MessageDigest'
        match = self._run_rg_and_process(regex=regex, code=show_code)
        self._code_analysis['hash_custom'] = match
        self.log_debug('')
        return GreppedOut(match)

    @_logger
    def code_ssl_connections(self, show_code: bool = False) -> GreppedOut:
        """
        This method will identify if SSL is being used by the application. 
        | `Reference <http://find-sec-bugs.github.io/bugs.htm#SSL_CONTEXT>`__

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
        >>> a.code_ssl_connections()
        """
        regex = r'SSLContext\.getInstance\(.?[^T]+.?\)'
        match = self._run_rg_and_process(regex=regex, code=show_code)
        self._code_analysis['ssl'] = match
        self.log_debug('')
        return GreppedOut(match)

    @_logger
    def code_xml_processor(self, show_code: bool = False) -> GreppedOut:
        """
        This method will identify possible weaknesses in XML parsing and creation. 
        | `Reference <http://find-sec-bugs.github.io/bugs.htm#XXE_DTD_TRANSFORM_FACTORY>`__

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
        >>> a.code_xml_processor()
        """
        regex = r'^([^import].+)(TransformerFactory)'
        match = self._run_rg_and_process(regex=regex, code=show_code)
        self._code_analysis['xml_processing'] = match
        self.log_debug('')
        return GreppedOut(match)

    @_logger
    def code_xpath(self, show_code: bool = False) -> GreppedOut:
        """
        This method will identify if SSL is being used by the application. 
        | `Reference <http://find-sec-bugs.github.io/bugs.htm#XXE_XPATH>`__

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
        >>> a.code_xpath()
        """
        regex = r'newXPath'
        match = self._run_rg_and_process(regex=regex, code=show_code)
        self._code_analysis['ssl'] = match
        self.log_debug('')
        return GreppedOut(match)

    @_logger
    def code_null_cipher(self, show_code: bool = False) -> GreppedOut:
        """
        This method will identify nullciphers are being used. 
        | `Reference <http://find-sec-bugs.github.io/bugs.htm#NULL_CIPHER>`__

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
        >>> a.code_null_cipher()
        """
        regex = r'NullCipher'
        match = self._run_rg_and_process(regex=regex, code=show_code)
        self._code_analysis['null_cipher'] = match
        self.log_debug('')
        return GreppedOut(match)

    @_logger
    def code_static_iv(self, show_code: bool = False) -> GreppedOut:
        """
        This method will identify static IV's. 
        | `Reference <http://find-sec-bugs.github.io/bugs.htm#STATIC_IV>`__

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
        >>> a.code_static_iv()
        """
        regex = self._IGNORE_IMPORTS + r'(IvParameterSpec)'
        match = self._run_rg_and_process(regex=regex, code=show_code)
        self._code_analysis['static_iv'] = match
        self.log_debug('')
        return GreppedOut(match)

    @_logger
    def code_external_file_access(self, show_code: bool = False) -> GreppedOut:
        """
        This method will identify where external files are being used. 
        | `Reference <http://find-sec-bugs.github.io/bugs.htm#ANDROID_EXTERNAL_FILE_ACCESS>`__

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
        >>> a.code_external_file_access()
        """
        regex = r'getExternalFilesDir|Environment.getExternalStorageDirectory|getExternalStorageDirectory'
        match = self._run_rg_and_process(regex=regex, code=show_code)
        self._code_analysis['external_file_access'] = match
        self.log_debug('')
        return GreppedOut(match)

    @_logger
    def code_cookies(self, show_code: bool = False) -> GreppedOut:
        """
        This method will identify where cookies are being set. 
        | `Reference <http://find-sec-bugs.github.io/bugs.htm#INSECURE_COOKIE>`__

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
        >>> a.code_cookies()
        """
        regex = r'\bCookie\(.+\)'
        match = self._run_rg_and_process(regex=regex, code=show_code)
        self._code_analysis['cookies'] = match
        self.log_debug('')
        return GreppedOut(match)

    @_logger
    def code_object_deserialization(self, show_code: bool = False) -> GreppedOut:
        """
        This method will identify where cookies are being set. 
        | `Reference <http://find-sec-bugs.github.io/bugs.htm#OBJECT_DESERIALIZATION>`__

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
        >>> a.code_object_deserialization()
        """
        regex = self._IGNORE_IMPORTS + r'(new ObjectInputStream)'
        match = self._run_rg_and_process(regex=regex, code=show_code)
        self._code_analysis['deserialization'] = match
        self.log_debug('')
        return GreppedOut(match)

    @_logger
    def code_aws_query(self, show_code: bool = False) -> GreppedOut:
        """
        This method will identify where AWS queries are being made. 
        | `Reference <http://find-sec-bugs.github.io/bugs.htm#AWS_QUERY_INJECTION>`__

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
        >>> a.code_aws_query()
        """
        regex = r'AmazonSimpleDBClient'
        match = self._run_rg_and_process(regex=regex, code=show_code)
        self._code_analysis['aws_query'] = match
        self.log_debug('')
        return GreppedOut(match)

    @_logger
    def code_stack_trace(self, show_code: bool = False) -> GreppedOut:
        """
        This method will identify where AWS queries are being made. 
        | `Reference <http://find-sec-bugs.github.io/bugs.htm#INFORMATION_EXPOSURE_THROUGH_AN_ERROR_MESSAGE>`__

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
        >>> a.code_stack_trace()
        """
        regex = r'printStackTrace'
        match = self._run_rg_and_process(regex=regex, code=show_code)
        self._code_analysis['stack_trace'] = match
        self.log_debug('')
        return GreppedOut(match)

    @_logger
    def code_search(self, regex: str, rg_options: str = '', show_code: bool = False) -> GreppedOut:
        """
        Run any checks against the decompiled code. The regex should 
        be in raw string format

        :param str regex: Regex pattern
        :param str rg_options: ripgrep options, space seperated string, defaults to ''
        Parameters
        ----------
        show_code : bool, optional
            Show the full matched line, by default False

        Returns
        -------
        GreppedOut : object
            GreppedOut object

        Examples
        --------        """

        g = self._run_rg(
            regex=regex, rg_options=rg_options, code=show_code)
        match = self._process_match(g)
        self.log_debug('')
        return GreppedOut(match)

    @_logger
    def code_sdcard(self, show_code: bool = False) -> GreppedOut:
        """
        This method will identify strings matching sdcard usage. 

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
        >>> a.code_sdcard()
        """
        regex = r'sdcard'
        match = self._run_rg_and_process(regex=regex, code=show_code)
        self._code_analysis['sdcard'] = match
        self.log_debug('')
        return GreppedOut(match)

    @_logger
    def code_broadcast_send(self, show_code: bool = False) -> GreppedOut:
        """
        This method will identify code that indicates broadcast messages 
        being sent. 

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
        >>> a.code_broadcast_send()
        """
        regex = r'sendBroadcast|sendBroadcastAsUser|sendOrderedBroadcast|sendOrderedBroadcastAsUser|sendStickyBroadcast|sendStickyBroadcastAsUser|sendStickyOrderedBroadcast|sendStickyOrderedBroadcastAsUser'
        match = self._run_rg_and_process(regex=regex, code=show_code)
        self._code_analysis['broadcast_send'] = match
        self.log_debug('')
        return GreppedOut(match)

    @_logger
    def code_find_intents(self, show_code: bool = False) -> GreppedOut:
        """
        This method will identify intent builders. 

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
        >>> a.code_find_intents()
        """
        regex = r'Intent\s*[A-Za-z0-9_$]+\s*[=;]\s*new\s+Intent\(|Intent\s*[A-Za-z0-9_$]+\s*[=;]\s+getIntent\(|[A-Za-z0-9_$]+\s*[=;]\s*Intent\.parseUri\('
        match = self._run_rg_and_process(regex=regex, code=show_code)
        self._code_analysis['intents'] = match
        self.log_debug('')
        return GreppedOut(match)

    @_logger
    def code_intent_filters(self, show_code: bool = False) -> GreppedOut:
        """
        This identifies all the different types of intent filters

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
        >>> a.code_intent_filters()
        """
        match = {}
        for filters in self._RG_INTENT_EXTRAS:
            match[filters] = self._run_rg_and_process(
                regex=filters, code=show_code)
            self.log_debug(f'{filters}: ')
        self._code_analysis['intent_filters'] = match
        self.log_debug('')
        return GreppedOut(match)

    @_logger
    def code_parse_uri(self, show_code: bool = False) -> GreppedOut:
        """
        Identifies code that is parsing a URI. This could be related to 
        web urls, or content provider urls. 
        | `Reference <https://developer.android.com/reference/android/net/Uri#parse(java.lang.String)>`__

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
        >>> a.code_parse_uri()
        """
        regex = r'Uri\.parse'
        match = self._run_rg_and_process(regex=regex, code=show_code)
        self._code_analysis['uri_parse'] = match
        self.log_debug('')
        return GreppedOut(match)

    @_logger
    def code_database_interaction(self, show_code: bool = False) -> GreppedOut:
        """
        Identifies code that is reading database files. 
        | `Reference <https://developer.android.com/reference/android/database/Cursor>`__

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
        >>> a.code_database_interaction()
        """
        regex = r'Cursor\s\w+\s?='
        match = self._run_rg_and_process(regex=regex, code=show_code)
        self._code_analysis['db_cursor'] = match
        self.log_debug('')
        return GreppedOut(match)

    @_logger
    def code_phone_sensors(self, show_code: bool = False) -> GreppedOut:
        """
        Identifies code that initiates various sensors available by Android. 
        | `Reference <https://developer.android.com/guide/topics/sensors/sensors_motion#java>`__

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
        >>> a.code_phone_sensors()
        """
        regex = r'getDefaultSensor'
        match = self._run_rg_and_process(regex=regex, code=show_code)
        self._code_analysis['sensor'] = match
        self.log_debug('')
        return GreppedOut(match)

    @_logger
    def code_android_contacts_content_provider(self, show_code: bool = False) -> GreppedOut:
        """
        Idicates imports, or any other place where the ContactsContract class and 
        its providors are being used. This typically indicates that the app can read 
        various contact information from the phones contact list. 
        | `Reference <https://developer.android.com/reference/android/provider/ContactsContract>`__

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
        >>> a.code_android_contacts_content_provider()
        """
        regex = r'ContactsContract'
        match = self._run_rg_and_process(regex=regex, code=show_code)
        self._code_analysis['contact_content'] = match
        self.log_debug('')
        return GreppedOut(match)

    @_logger
    def code_read_sms_messages(self, show_code: bool = False) -> GreppedOut:
        """
        Searches for SmsMessage class which is typically used to read SMS messages 
        send to a device. 
        | `Reference <https://developer.android.com/reference/android/telephony/SmsMessage>`__

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
        >>> a.code_read_sms_messages()
        """
        regex = r'SmsMessage'
        match = self._run_rg_and_process(regex=regex, code=show_code)
        self._code_analysis['sms_read'] = match
        self.log_debug('')
        return GreppedOut(match)

    @_logger
    def code_regex_pattern(self, show_code: bool = False) -> GreppedOut:
        """
        Identifies code that compiles regex patterns. 
        | `Reference <https://developer.android.com/reference/java/util/regex/Pattern>`__

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
        >>> a.code_regex_pattern()
        """
        regex = r'Pattern\.compile\(.+\)'
        match = self._run_rg_and_process(regex=regex, code=show_code)
        self._code_analysis['regex_pattern'] = match
        self.log_debug('')
        return GreppedOut(match)

    @_logger
    def code_regex_matcher(self, show_code: bool = False) -> GreppedOut:
        """
        Identifies code that is processing regex. 
        | `Reference <https://developer.android.com/reference/java/util/regex/Matcher>`__

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
        >>> a.code_regex_matcher()
        """
        regex = r'Matcher\s\w+\s?='
        match = self._run_rg_and_process(regex=regex, code=show_code)
        self._code_analysis['regex_matcher'] = match
        self.log_debug('')
        return GreppedOut(match)

    @_logger
    def code_notification_manager(self, show_code: bool = False) -> GreppedOut:
        """
        Identifies code controls notifications. 
        | `Reference <https://developer.android.com/reference/android/app/NotificationManager>`__

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
        >>> a.code_notification_manager()
        """
        regex = self._IGNORE_IMPORTS + r'(NotificationManager)'
        match = self._run_rg_and_process(regex=regex, code=show_code)
        self._code_analysis['notification_manager'] = match
        self.log_debug('')
        return GreppedOut(match)

    @_logger
    def code_send_sms_text(self, show_code: bool = False) -> GreppedOut:
        """
        Identifies code can send SMS/Text messages. 
        | `Reference <https://developer.android.com/reference/android/app/NotificationManager>`__

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
        >>> a.code_send_sms_text()
        """
        regex = self._IGNORE_IMPORTS + \
            r'(sendTextMessage|sendMultipartTextMessage)'
        match = self._run_rg_and_process(regex=regex, code=show_code)
        self._code_analysis['sms'] = match
        self.log_debug('')
        return GreppedOut(match)

    @_logger
    def code_jar_urlconnection(self, show_code: bool = False) -> GreppedOut:
        """
        Identifies code that is using the JarURLConnection API. 
        | `Reference <https://developer.android.com/reference/java/net/JarURLConnection>`__

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
        >>> a.code_jar_urlconnection()
        """
        regex = self._IGNORE_IMPORTS + r'(JarURLConnection)'
        match = self._run_rg_and_process(regex=regex, code=show_code)
        self._code_analysis['jar_urlconnection'] = match
        self.log_debug('')
        return GreppedOut(match)

    @_logger
    def code_invisible_elements(self, show_code: bool = False) -> GreppedOut:
        """
        Identifies code will set the visibility of an element to invisible. 
        | `Reference <https://developer.android.com/reference/android/view/View.html#INVISIBLE>`__

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
        >>> a.code_invisible_elements()
        """
        regex = self._IGNORE_IMPORTS + r'(setVisibility\(4\))'
        match = self._run_rg_and_process(regex=regex, code=show_code)
        self._code_analysis['elements_invisible'] = match
        self.log_debug('')
        return GreppedOut(match)

    @_logger
    def code_trust_all_ssl(self, show_code: bool = False) -> GreppedOut:
        """
        Identifies code that willl allow all SSL connections to succeed without 
        verifying the hostname. This is a finding.  
        | `Reference <https://developer.android.com/reference/android/view/View.html#INVISIBLE>`__

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
        >>> a.code_trust_all_ssl()
        """
        regex = self._IGNORE_IMPORTS + \
            r'(TrustAllSSLSocket-Factory|AllTrustSSLSocketFactory|NonValidatingSSLSocketFactory|net\.SSLCertificateSocketFactory|ALLOW_ALL_HOSTNAME_VERIFIER|\.setDefaultHostnameVerifier\(|NullHostnameVerifier\()'
        match = self._run_rg_and_process(regex=regex, code=show_code)
        self._code_analysis['ssl_no_hostname_verify'] = match
        self.log_debug('')
        return GreppedOut(match)

    @_logger
    def code_root_access(self, show_code: bool = False) -> GreppedOut:
        """
        Identifies code that indicates if the app requests su access.

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
        >>> a.code_root_access()
        """
        regex = r'com.noshufou.android.su|com.thirdparty.superuser|eu.chainfire.supersu|com.koushikdutta.superuser|eu.chainfire.'
        match = self._run_rg_and_process(regex=regex, code=show_code)
        self._code_analysis['root_access'] = match
        self.log_debug('')
        return GreppedOut(match)

    @_logger
    def code_reflection(self, show_code: bool = False) -> GreppedOut:
        """
        Identifies code that allows reflections in Java. This is a finding. 
        Refer to the references for the risk and usage of reflections.  
        | `Reference <https://www.geeksforgeeks.org/reflection-in-java/>`__
        | `Reference <https://wiki.sei.cmu.edu/confluence/display/java/SEC05-J.+Do+not+use+reflection+to+increase+accessibility+of+classes%2C+methods%2C+or+fields>`__

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
        >>> a.code_reflection()
        """
        regex = self._IGNORE_IMPORTS + \
            r'\bArray\b|\bConstructor\b|\bField\b|\bMethod\b|\bModifier\b'
        match = self._run_rg_and_process(regex=regex, code=show_code)
        self._code_analysis['reflections'] = match
        self.log_debug('')
        return GreppedOut(match)

    @_logger
    def code_add_javascriptinterface(self, show_code: bool = False) -> GreppedOut:
        """
        Leads to vulnerabilities in android version jellybean and below
        | `Reference <https://wiki.sei.cmu.edu/confluence/pages/viewpage.action?pageId=87150717>`__

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
        >>> a.code_add_javascriptinterface()
        """
        regex = r'addJavascriptInterface'
        match = self._run_rg_and_process(regex=regex, code=show_code)
        self._code_analysis['javascript_interface'] = match
        self.log_debug('')
        return GreppedOut(match)

    @_logger
    def code_create_new_file(self, show_code: bool = False) -> GreppedOut:
        """
        Identifies code that creates new files in the android system.  
        | `Reference <https://developer.android.com/reference/java/io/File/>`__

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
        >>> a.code_create_new_file()
        """
        regex = r'\.createNewFile\(.*\)'
        match = self._run_rg_and_process(regex=regex, code=show_code)
        self._code_analysis['create_new_file'] = match
        self.log_debug('')
        return GreppedOut(match)

    @_logger
    def code_location_manager(self, show_code: bool = False) -> GreppedOut:
        """
        Identifies code that receives updated location information.  
        | `Reference <https://developer.android.com/reference/android/location/LocationManager>`__

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
        >>> a.code_location_manager()
        """
        regex = self._IGNORE_IMPORTS + r'LocationManager'
        match = self._run_rg_and_process(regex=regex, code=show_code)
        self._code_analysis['location_manager'] = match
        self.log_debug('')
        return GreppedOut(match)

    @_logger
    def code_location(self, show_code: bool = False) -> GreppedOut:
        """
        Identifies code that receives location information.  
        | `Reference <https://developer.android.com/reference/android/location/Location>`__

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
        >>> a.code_location()
        """
        regex = self._IGNORE_IMPORTS + r'\sLocation\s\w+'
        match = self._run_rg_and_process(regex=regex, code=show_code)
        self._code_analysis['location_manager'] = match
        self.log_debug('')
        return GreppedOut(match)

    @_logger
    def code_screenshots(self, show_code: bool = False) -> GreppedOut:
        """
        Identifies usage of Bitmap and BitmapFactory classes. Although these are for 
        bitmap compression and manipulation, they are often used to take screenshots.  
        | `Reference <https://developer.android.com/reference/android/graphics/Bitmap>`__
        | `Reference <https://developer.android.com/reference/android/graphics/BitmapFactory>`__

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
        >>> a.code_screenshots()
        """
        regex = self._IGNORE_IMPORTS + r'\bBitmap|\bBitmapFactory'
        match = self._run_rg_and_process(regex=regex, code=show_code)
        self._code_analysis['screenshots'] = match
        self.log_debug('')
        return GreppedOut(match)

    @_logger
    def code_call_log(self, show_code: bool = False) -> GreppedOut:
        """
        Identifies code that retreives call logs. May be possible malware behaviour. 
        | `Reference <https://developer.android.com/reference/android/provider/CallLog>`__

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
        >>> a.code_call_log()
        """
        regex = self._IGNORE_IMPORTS + r'\bCallLog'
        match = self._run_rg_and_process(regex=regex, code=show_code)
        self._code_analysis['call_log'] = match
        self.log_debug('')
        return GreppedOut(match)

    @_logger
    def code_camera_access(self, show_code: bool = False) -> GreppedOut:
        """
        Identifies code that accesses the camera and picture taking functionality. 
        | `Reference <https://developer.android.com/reference/android/hardware/Camera>`__
        | `Reference <https://developer.android.com/reference/android/hardware/camera2/package-summary>`__

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
        >>> a.code_camera_access()
        """
        regex = self._IGNORE_IMPORTS + \
            r'[^\"](\bCamera\b|\bCaptureRequest\b|\bCameraManager\b|\bCameraDevice\b)[^\"]'
        match = self._run_rg_and_process(regex=regex, code=show_code)
        self._code_analysis['camera_access'] = match
        self.log_debug('')
        return GreppedOut(match)

    @_logger
    def code_browser_db_access(self, show_code: bool = False) -> GreppedOut:
        """
        Identifies code that accesses the browser db. This db usually 
        includes browsing history.  
        | `Reference <https://developer.android.com/sdk/api_diff/23/changes/android.provider.Browser>`__

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
        >>> a.code_browser_db_access()
        """
        regex = r'BOOKMARKS_URI'
        match = self._run_rg_and_process(regex=regex, code=show_code)
        self._code_analysis['browser_db_access'] = match
        self.log_debug('')
        return GreppedOut(match)

    @_logger
    def code_database_query(self, show_code: bool = False) -> GreppedOut:
        """
        Identifies code that queries any database on the device.  
        | `Reference <https://developer.android.com/reference/android/database/sqlite/SQLiteDatabase#query(boolean,%20java.lang.String,%20java.lang.String[],%20java.lang.String,%20java.lang.String[],%20java.lang.String,%20java.lang.String,%20java.lang.String,%20java.lang.String)>`__

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
        >>> a.code_database_query()
        """
        regex = r'\.query\(.+\)'
        match = self._run_rg_and_process(regex=regex, code=show_code)
        self._code_analysis['database_query'] = match
        self.log_debug('')
        return GreppedOut(match)

    @_logger
    def code_boot_completed_persistance(self, show_code: bool = False) -> GreppedOut:
        """
        Identifies if the application uses BOOT_COMPLETED action which is 
        typically used to start a service or a receiver on reboot. This indicates 
        persistance.   
        | `Reference <https://developer.android.com/reference/android/content/Intent.html#ACTION_BOOT_COMPLETED>`__

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
        >>> a.code_boot_completed_persistance()
        """
        regex = r'BOOT_COMPLETED'
        match = self._run_rg_and_process(regex=regex, code=show_code,
                                         path=f'{self._output_dir}')
        self._code_analysis['boot_completed'] = match
        self.log_debug('')
        return GreppedOut(match)

    @_logger
    def code_accessibility_service(self, show_code: bool = False) -> GreppedOut:
        """
        Identifies if the application uses AccessibilityService and 
        its various classes. It also looks for the accessibilityEvent method.   
        | `Reference <https://developer.android.com/reference/android/accessibilityservice/package-summary>`__

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
        >>> a.code_accessibility_service()
        """
        regex = self._IGNORE_IMPORTS + \
            r'\bAccessibilityService|\bAccessibilityEvent|\bAccessibilityServiceInfo|\bAccessibilityManager|\baccessibilityEvent'
        match = self._run_rg_and_process(regex=regex, code=show_code)
        self._code_analysis['accessiblity'] = match
        self.log_debug('')
        return GreppedOut(match)

    @_logger
    def code_download_manager(self, show_code: bool = False) -> GreppedOut:
        """
        Identifies if the application uses the DownloadManager class to 
        download files from onlines services.   
        | `Reference <https://developer.android.com/reference/android/app/DownloadManager>`__

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
        >>> a.code_download_manager()
        """
        regex = self._IGNORE_IMPORTS + r'\bDownloadManager'
        match = self._run_rg_and_process(regex=regex, code=show_code)
        self._code_analysis['download_manager'] = match
        self.log_debug('')
        return GreppedOut(match)

    @_logger
    def code_mediastore(self, show_code: bool = False) -> GreppedOut:
        """
        Identifies if he MediaStore class or some of its common 
        subclasses are being used by the app. These classes are used to get 
        media file metadata from both internal and external storage.   
        | `Reference <https://developer.android.com/reference/android/provider/MediaStore>`__

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
        >>> a.code_mediastore()
        """
        regex = r'\bMediaStore\.?(Audio|Files|Images|Video|MediaColumns)\b'
        match = self._run_rg_and_process(regex=regex, code=show_code)
        self._code_analysis['mediastore'] = match
        self.log_debug('')
        return GreppedOut(match)

    @_logger
    def code_firebase_imports(self, show_code: bool = False) -> GreppedOut:
        """
        Identifies if he MediaStore class or some of its common 
        subclasses are being used by the app. These classes are used to get 
        media file metadata from both internal and external storage.   
        | `Reference <https://developer.android.com/studio/write/firebase>`__

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
        >>> a.code_firebase_imports()
        """
        regex = r'^import\s(.*firebase.*);'
        match = self._run_rg_and_process(regex=regex, code=show_code)
        self._code_analysis['firebase_imports'] = match
        self.log_debug('')
        return GreppedOut(match)

    @_logger
    def code_deserialization(self, show_code: bool = False) -> GreppedOut:
        """
        ObjectInputSteam when used with 'readObject' 'readObjectNodData' 'readResolve' 'readExternal'
        will likely result in a Deserialization vulnerability   
        | `Reference <https://www.owasp.org/index.php/Deserialization_Cheat_Sheet#WhiteBox_Review_3>`__

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
        >>> a.code_deserialization()
        """
        regex = r'ObjectInputSteam'
        match = self._run_rg_and_process(regex=regex, code=show_code)
        self._code_analysis['deserialization'] = match
        self.log_debug('')
        return GreppedOut(match)

    @_logger
    def code_sql_injection_user_input(self, show_code=False):
        """
        Find places in code where a variable is being concatanated with 
        a SQL statement

        Parameters
        ----------
        show_code : bool, optional
            Show the full matched line, by default False

        Returns
        -------
        GreppedOut : object
            GreppedOut object

        Examples
        --------        :rtype: dict

        >>> from glorifiedgrep import GlorifiedAndroid
        >>> a = GlorifiedAndroid('/path/to/apk')
        >>> a.code_sql_inection_points()
        """
        regex = r'(?:\"SELECT (?:[^;]|\n)*\"(?:(?: |\n|\t)*\+(?: |\n|\t)*)([A-Za-z][^\"\+; ]*)(?:[^;]|\n)*;)'
        g = self._run_rg(regex=regex, code=show_code, rg_options='--pcre2')
        match = self._process_match(g)
        self._code_analysis['sql_injection_points'] = match
        self.log_debug('')
        return GreppedOut(match)

    @_logger
    def code_websocket_usage(self, show_code: bool = False) -> GreppedOut:
        """
        Detects common Websockets init classes. 
        | `Reference <https://stackoverflow.com/questions/30547517/which-websocket-library-to-use-in-android-app>`__

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
        >>> a.code_websocket_usage()
        """
        regex = self._IGNORE_IMPORTS + r'\bWebSocket\b|\bWebSocketClient\b'
        match = self._run_rg_and_process(regex=regex, code=show_code)
        self._code_analysis['websockets'] = match
        self.log_debug('')
        return GreppedOut(match)

    @_logger
    def code_apache_http_get_request(self, show_code: bool = False) -> GreppedOut:
        """
        Detects the HttpGet method from the apache library. This is generally used 
        to make GET requests.  
        | `Reference <http://hc.apache.org/httpcomponents-client-ga/tutorial/html/fundamentals.html#d5e49>`__ 
        | `Reference <https://www.mkyong.com/java/apache-httpclient-examples/>`__

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
        >>> a.code_apache_http_get_request()
        """
        regex = r'new HttpGet\(.+\)'
        match = self._run_rg_and_process(regex=regex, code=show_code)
        self._code_analysis['apache_get'] = match
        self.log_debug('')
        return GreppedOut(match)

    @_logger
    def code_apache_http_post_request(self, show_code: bool = False) -> GreppedOut:
        """
        Detects the HttpPost method from the apache library. This is generally used 
        to make GET requests.  
        | `Reference <http://hc.apache.org/httpcomponents-client-ga/tutorial/html/fundamentals.html#d5e49>`__ 
        | `Reference <https://www.mkyong.com/java/apache-httpclient-examples/>`__

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
        >>> a.code_apache_http_post_request()
        """
        regex = r'new HttpPost\(.+\)'
        match = self._run_rg_and_process(regex=regex, code=show_code)
        self._code_analysis['apache_post'] = match
        self.log_debug('')
        return GreppedOut(match)

    @_logger
    def code_apache_http_other_request_methods(self, show_code: bool = False) -> GreppedOut:
        """
        Detects the HttpPut, HttpDelete, HttpHead, HttpTrace and HttpOptions methods 
        from the apache library. 
        | `Reference <http://hc.apache.org/httpcomponents-client-ga/tutorial/html/fundamentals.html#d5e49>`__ 
        | `Reference <https://www.mkyong.com/java/apache-httpclient-examples/>`__

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
        >>> a.code_apache_http_post_request()
        """
        regex = r'new (HttpPut|HttpDelete|HttpHead|HttpTrace|HttpOptions)\(.+\)'
        match = self._run_rg_and_process(regex=regex, code=show_code)
        self._code_analysis['apache_post'] = match
        self.log_debug('')
        return GreppedOut(match)

    @_logger
    def code_package_installed(self, show_code: bool = False) -> GreppedOut:
        """
        Detects the usage of the getInstalledPackages method from the PackageManager class. 
        | `Reference <https://developer.android.com/reference/kotlin/android/content/pm/PackageManager?hl=en#getinstalledpackages>`__ 

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
        >>> a.code_apache_http_post_request()
        """
        regex = r'\.getInstalledPackages\(.*\)'
        match = self._run_rg_and_process(regex=regex, code=show_code)
        self._code_analysis['installed_packages'] = match
        self.log_debug('')
        return GreppedOut(match)

    @_logger
    def code_system_file_exists(self, show_code: bool = False) -> GreppedOut:
        """
        Detects if the exists method from the File class is being called. 
        This method is typically used to check if the path in the class 
        constructor exists in the system.  
        | `Reference <https://developer.android.com/reference/kotlin/java/io/File?hl=en#exists>`__ 

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
        >>> a.code_apache_http_post_request()
        """
        regex = r'new File.+\.exists\(\)'
        match = self._run_rg_and_process(regex=regex, code=show_code)
        self._code_analysis['file_exists'] = match
        self.log_debug('')
        return GreppedOut(match)
