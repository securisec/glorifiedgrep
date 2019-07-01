import re

from .androidcore import _AndroidCore
from ...logger import _logger


class React(_AndroidCore):
    """
    Module to handle analysis of apps developed using React. React is 
    a JavaScript framework, and the React files are usually found in 
    unzipped_folder/assets/index.android.bundle. This class inherits 
    all properties from _AndroidCore.

    >>> from glorifiedgrep.android.modules.reactapp import React
    >>> r = React('/path/to/apk)
    """

    @_logger
    def _react_path(self) -> str:
        """
        Gets the path of the React app bundle

        :return: path of React app
        :rtype: str
        """

        path = f'{self._unzipped_path}/assets/index.android.bundle'
        self.log_debug(f'react path: {path}')
        return path

    @_logger
    def react_find_functions(self) -> dict:
        """
        Find a list of all global functions and their parameters

        :return: dict of line, function name and parameters
        :rtype: dict

        >>> r.react_find_functions()
        """

        regex = r'^function\s(\w+)\((.*)\)'
        match = self._run_rg(
            regex=regex, path=self._react_path(), group="'-r $1 $2'")
        functions = list()
        for m in match:
            f = dict()
            m = m.decode('utf-8').split()
            f['line'] = m[0].strip(':')
            f['name'] = m[1]
            if len(m) > 2:
                f['parameters'] = ''.join(m[2:]).split(',')
            else:
                f['parameters'] = None
            functions.append(self._pdict(f))
        self.log_debug('')
        return functions

    @_logger
    def react_find_urls(self, show_code: bool=False) -> dict:
        """
        Find all URL's inside the React code bundle

        :param show_code: Show the full matching line, defaults to False
        :param show_code: bool, optional
        :return: dict of line number and match
        :rtype: dict

        >>> r.react_find_urls()
        """

        regex = r'(?:http(s)?://)[\w.-]+(?:\.[\w\.-]+)+[\w\-\._~:/?#[.]@&\(\)\*\+]+|https?://localhost:?(\d+)?'
        match = self._run_rg(
            regex=regex, path=self._react_path(), code=show_code)
        found = list()
        for m in match:
            m = m.decode('utf-8').split(':')
            found.append(
                self._pdict({
                    'line': m[0],
                    'url': ':'.join(m[1:])
                })
            )
        self.log_debug('')
        return found

    @_logger
    def react_regex_constructor(self, show_code: bool=False) -> dict:
        """
        Find all RexExp constructors in the code

        :param show_code: Show the full matching line, defaults to False
        :param show_code: bool, optional
        :return: dict of line number and match
        :rtype: dict

        >>> r.react_regex_constructor()
        """

        regex = r'new RegExp\('
        match = self._run_rg(
            regex=regex, path=self._react_path(), code=show_code)
        found = list()
        for m in match:
            m = m.decode('utf-8').split(':')
            found.append(
                self._pdict({
                    'line': m[0],
                    'match': ':'.join(m[1:])
                })
            )
        self.log_debug('')
        return found

    @_logger
    def react_xmlhttprequest_constructor(self, show_code: bool=False) -> dict:
        """
        Find all XMLHttpRequest constructors in the code

        :param show_code: Show the full matching line, defaults to False
        :param show_code: bool, optional
        :return: dict of line number and match
        :rtype: dict

        >>> r.react_xmlhttprequest_constructor()
        """

        regex = r'new XMLHttpRequest\('
        match = self._run_rg(
            regex=regex, path=self._react_path(), code=show_code)
        found = list()
        for m in match:
            m = m.decode('utf-8').split(':')
            found.append(
                self._pdict({
                    'line': m[0],
                    'match': ':'.join(m[1:])
                })
            )
        self.log_debug('')
        return found

    @_logger
    def react_dev_global(self, show_code: bool=False) -> dict:
        """
        Find the __DEV__ variable and see what it is set to. 
        | `Reference <https://facebook.github.io/react-native/docs/javascript-environment.html>`__

        :param show_code: Show the full matching line, defaults to False
        :param show_code: bool, optional
        :return: dict of line number and match
        :rtype: dict

        >>> r.react_dev_global()
        """

        regex = r'__DEV__.+(true|false)'
        match = self._run_rg(
            regex=regex, path=self._react_path(), code=show_code)
        found = list()
        for m in match:
            m = m.decode('utf-8').split(':')
            found.append(
                self._pdict({
                    'line': m[0],
                    'match': ':'.join(m[1:])
                })
            )
        self.log_debug('')
        return found

    @_logger
    def react_console_statements(self, show_code: bool=False) -> dict:
        """
        Find all the console statements. This includes log, warn, error, trace etc.  
        | `Reference <https://facebook.github.io/react-native/docs/javascript-environment.html>`__

        :param show_code: Show the full matching line, defaults to False
        :param show_code: bool, optional
        :return: dict of line number and match
        :rtype: dict

        >>> r.react_console_statements()
        """

        regex = r'console\.(log|warn|error|info|trace|table|group|groupEnd)'
        match = self._run_rg(
            regex=regex, path=self._react_path(), code=show_code)
        found = self._pdict({
            'log': [],
            'warn': [],
            'error': [],
            'info': [],
            'trace': [],
            'table': [],
            'group': [],
            'groupEnd': []
        })
        for m in match:
            m = m.decode('utf-8').split(':')
            code = ':'.join(m[1:])
            key = re.findall(
                r'console\.(log|warn|error|info|trace|table|group|groupEnd)', code)[0]
            if key == 'log':
                found['log'].append(self._pdict({'line': m[0], 'match': code}))
            if key == 'warn':
                found['warn'].append(self._pdict(
                    {'line': m[0], 'match': code}))
            if key == 'error':
                found['error'].append(self._pdict(
                    {'line': m[0], 'match': code}))
            if key == 'info':
                found['info'].append(self._pdict(
                    {'line': m[0], 'match': code}))
            if key == 'trace':
                found['trace'].append(self._pdict(
                    {'line': m[0], 'match': code}))
            if key == 'table':
                found['table'].append(self._pdict(
                    {'line': m[0], 'match': code}))
            if key == 'group':
                found['group'].append(self._pdict(
                    {'line': m[0], 'match': code}))
            if key == 'groupEnd':
                found['groupEnd'].append(
                    self._pdict({'line': m[0], 'match': code}))
        self.log_debug('')
        return found
