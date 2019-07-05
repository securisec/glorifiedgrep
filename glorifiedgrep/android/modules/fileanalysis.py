import hashlib
import re
from pathlib import Path
import json
from collections import defaultdict

import xmltodict
import magic

from .androidcore import _AndroidCore
from ...logger import _logger


class _FileAnalysys(_AndroidCore):

    def all_file_analysis(self):
        """
        Property runs all available checks in _FileAnalysis

        :return: Dictionary of all analysis
        :rtype: dict

        >>> from glorifiedgrep import GlorifiedAndroid
        >>> a = GlorifiedAndroid('/path/to/apk')
        >>> a.all_file_analysis()
        """
        methods = [p for p in vars(
            _FileAnalysys).keys() if not p.startswith('_')]
        [getattr(self, m)() for m in methods if m != 'all_file_analysis']
        self.log_debug('')
        return self._android_findings['file_analysis']

    @_logger
    def file_hash_of_apk(self) -> dict:
        """
        Generates the MD5, SHA1 and SHA256 hashes of the APK.

        Returns
        -------
        dict
            Returns dict containing MD5, SHA1 and SHA256 hash of APK.

        Examples
        --------
        >>> from glorifiedgrep import GlorifiedAndroid
        >>> a = GlorifiedAndroid('/path/to/apk)
        >>> a.file_hash_of_apk()
        """
        # ignore this property is GlorifiedAndroid class is not calling it
        if self.__class__.__name__ == 'ParseManifest':
            return
        with open(self._apk_path, 'rb') as f:
            data = f.read()
        _hash_dict = self._file_analysis['hash'] = {}
        _hash_dict['md5'] = hashlib.md5(data).hexdigest()
        _hash_dict['sha1'] = hashlib.sha1(data).hexdigest()
        _hash_dict['sha256'] = hashlib.sha256(data).hexdigest()
        self._file_analysis['hash'] = _hash_dict
        self.log_debug('')
        return _hash_dict

    @_logger
    def file_native_code(self) -> list:
        """
        Returns a string of available native code compitability if present

        Returns
        -------
        list
            List of native code presence

        Examples
        --------
        >>> from glorifiedgrep import GlorifiedAndroid
        >>> a = GlorifiedAndroid('/path/to/apk)
        >>> a.file_native_code()
        """
        # ignore this property is GlorifiedAndroid class is not calling it
        if self.__class__.__name__ == 'ParseManifest':
            return
        self.log_debug('')
        return [str(x).split('/')[-1] for x in self._get_paths_from_unzipped(
            path=f'{self._unzipped_path}/lib', glob_pattern='*', is_file=False
        )]

    @_logger
    def file_get_file_types(self, describe: bool = False, exclude: list = ['']) -> dict:
        """
        Returns the magic values of all files found after unzipping the APK. 
        Keys are sorted by mime values of the files

        Parameters
        ----------
        describe : bool, optional
            Get full description of file. Defaults to False
        exclude : list, optional
            Exclude the file extensions in an array. Defaults to None

        Returns
        -------
        dict
            Dictionary of all files and their magic headers

        Examples
        --------
        >>> from glorifiedgrep import GlorifiedAndroid
        >>> a = GlorifiedAndroid('/path/to/file')
        >>> a.file_get_file_types(exclude=['xml', 'png'])
        """
        # ! WINDOWS has path problems here
        # TODO change this with Pathlib for windows support
        def cdict(): return defaultdict(cdict)
        found = cdict()
        for p in self._get_paths_from_unzipped(self._unzipped_path):
            p = str(p)
            key = magic.from_file(p, mime=True)
            if key in found:
                if describe:
                    found[key].append(
                        {'file': p, 'description': magic.from_file(p)})
                else:
                    found[key].append(p)
            else:
                found[key] = []
                if describe:
                    found[key].append(
                        {'file': p, 'description': magic.from_file(p)})
                else:
                    found[key].append(p)
        self._file_analysis['file_types'] = found
        self.log_debug('')
        if exclude[0] != '':
            if not isinstance(exclude, list):
                raise TypeError('Exclude is an array of file extensions')
            if describe:
                return {k: list(x for x in found[k] if not any(s in x['file'] for s in exclude)) for k in found }
            else:
                return {k: list(x for x in found[k] if not any(s in x for s in exclude)) for k in found }
        return dict(found)

    @_logger
    def file_get_java_classes(self) -> list:
        """
        Returns a list of found JAVA classes

        Returns
        -------
        list
            JAVA classes

        Examples
        --------
        >>> a = GlorifiedAndroid('/path/to/apk')
        >>> a.file_get_java_classes()
        """
        # ! WINDOWS this will have the same problems as get_file_types
        # TODO change this with pathlib for windows support
        found = []
        for i in self._get_paths_from_unzipped(f'{self._java_sources}',
                                               glob_pattern='**/*.java'):
            i = (re.sub(f'{self._java_sources}', '', str(i)))
            found.append(i.replace('/', '.'))
        self._file_analysis['java_classes'] = found
        self.log_debug('')
        return found

    @_logger
    def file_kivy_app(self) -> bool:
        """
        This method checks to see if the app is a Kivy compiled application. 
        Kivy is a python framework for application development

        Returns
        -------
        bool
            True if kivy app, else False

        Examples
        --------
        >>> a = GlorifiedAndroid('/path/to/apk')
        >>> a.file_kivy_app()
        """
        for k in self.file_get_java_classes():
            if 'kivy' in k:
                self.log_debug('')
                return True
        self.log_debug('')
        return False

    @_logger
    def file_react_app(self) -> bool:
        """
        This method checks to see if the app is developed using the Facebook 
        React framework

        Returns
        -------
        bool
            True if React app, else False

        Examples
        --------
        >>> a = GlorifiedAndroid('/path/to/apk')
        >>> a.file_react_app()
        """
        for f in self._get_paths_from_unzipped(path=f'{self._output_dir}/unzipped',
                                               glob_pattern='**/*'):
            if 'index.android.bundle' in str(f):
                return True
        self.log_debug('')
        return False

    @_logger
    def file_other_langs(self) -> dict:
        """
        Checks to see if any other frameworks is being used in this app

        Returns
        -------
        dict
            Dict of other android development frameworks

        Examples
        --------
        >>> a = GlorifiedAndroid('/path/to/apk')
        >>> a.file_other_langs()
        """
        self.log_debug('')
        return {'kivy': self.file_kivy_app(),
                'react': self.file_react_app()}

    @_logger
    def file_xml_files(self) -> list:
        """
        Returns a list of found xml files

        Returns
        -------
        list
            Array of XML files

        Examples
        --------
        >>> a = GlorifiedAndroid('/path/to/apk')
        >>> a.file_xml_files()files
        """
        found = [self._re_remove_dir_prefix(str(x)) for x in self._get_paths_from_unzipped(
            f'{self._output_dir}/resources', glob_pattern='**/*.xml')]
        self._file_analysis['xml_files'] = found
        self.log_debug('')
        return found

    @_logger
    def file_js_files(self) -> list:
        """
        Returns a list of found js files

        Returns
        -------
        list
            Array of JS files

        Examples
        --------
        >>> a = GlorifiedAndroid('/path/to/apk')
        >>> a.file_js_files()files
        """
        found = [re.sub(f'{self._output_dir}/', '', str(x)
                        ) for x in self._get_paths_from_unzipped(
            f'{self._output_dir}', glob_pattern='**/*.js')]
        self._file_analysis['js_files'] = found
        self.log_debug('')
        return found

    @_logger
    def file_html_files(self) -> list:
        """
        Returns a list of found html files

        Returns
        -------
        list
            Array of HTML files

        Examples
        --------
        >>> a = GlorifiedAndroid('/path/to/apk')
        >>> a.file_html_files()files
        """
        found = [self._re_remove_dir_prefix(str(x)) for x in self._get_paths_from_unzipped(
            f'{self._output_dir}', glob_pattern='**/*.html')]
        self._file_analysis['html_files'] = found
        self.log_debug('')
        return found

    @_logger
    def file_jar_files(self) -> list:
        """
        Returns a list of found jar files

        Returns
        -------
        list
            Array of JAR files

        Examples
        --------
        >>> a = GlorifiedAndroid('/path/to/apk')
        >>> a.file_jar_files()files
        """
        found = [self._re_remove_dir_prefix(str(x)) for x in self._get_paths_from_unzipped(
            f'{self._output_dir}', glob_pattern='**/*.jar')]
        self._file_analysis['jar_files'] = found
        self.log_debug('')
        return found

    @_logger
    def file_resource_xml(self) -> list:
        """
        Returns a list of found xml files from the resources directory. 
        These files usually contains configuration options and may 
        contain secrets.

        Returns
        -------
        list
            Array of resource xml files

        Examples
        --------
        >>> a = GlorifiedAndroid('/path/to/apk')
        >>> a.file_resource_xml()files
        """
        found = [self._re_remove_dir_prefix(str(x)) for x in self._get_paths_from_unzipped(
            f'{self._output_dir}/resources/res/xml', glob_pattern='**/*.xml')]
        self._file_analysis['resource_xml_files'] = found
        self.log_debug('')
        return found

    @_logger
    def file_interesting(self) -> list:
        """
        Returns a list of found bks keystore files

        Returns
        -------
        list
            Array of interesting filetypes

        Examples
        --------
        >>> a = GlorifiedAndroid('/path/to/apk')
        >>> a.file_interesting()
        """
        found = []
        for ext in ['.bks', '.db', '.crt', '.properties']:
            found += [self._re_remove_dir_prefix(str(x)) for x in self._get_paths_from_unzipped(
                f'{self._output_dir}', glob_pattern=f'**/*{ext}')]
        self._file_analysis['interesting_files'] = found
        self.log_debug('')
        return found

    @_logger
    def file_res_strings(self) -> list:
        """
        This method looks enumerates the strings found in sources/res/values/strings.xml.

        Returns
        -------
        list
            Array of found strings

        Examples
        --------
        >>> a = GlorifiedAndroid('/path/to/apk')
        >>> a.file_res_strings()
        """
        s = []
        with open(f'{self._output_dir}/resources/res/values/strings.xml', 'r') as f:
            data = json.loads(json.dumps(
                xmltodict.parse(f.read(), attr_prefix='')))
        for i in data['resources']['string']:
            try:
                s.append({i['@name']: i['#text']})
            except KeyError:
                continue
        self._file_analysis['res_strings'] = s
        self.log_debug('')
        return s

    @_logger
    def file_activities_handling_passwords(self) -> list:
        """
        This method enumerates the xml files found in sources/res/layout/ and 
        looks for the textPassword value to see which activities handle passwords.

        Returns
        -------
        list

        Examples
        --------
        >>> a = GlorifiedAndroid('/path/to/apk')
        >>> a.file_activities_handling_passwords()
        """
        final = []
        for i in self._get_paths_from_unzipped(
                f'{self._output_dir}/resources/res/layout', '*.xml'):
            with open(i, 'r') as f:
                if 'android:inputType="textPassword"' in f.read():
                    activity = Path(i).name
                    final.append(activity)
        self.log_debug('')
        return final

    @_logger
    def file_database_file_paths(self) -> list:
        """
        This method enumerates for sqlite database files, and returns 
        a list of their paths

        Returns
        -------
        list
            a list of database file paths

        Examples
        --------
        >>> a = GlorifiedAndroid('/path/to/apk')
        >>> a.file_database_file_paths()
        """
        self.log_debug('')
        return self.file_get_file_types().get('application/x-sqlite3')

    @_logger
    def file_shared_libs_file_paths(self) -> list:
        """
        This method enumerates for shared objects, and returns 
        a list of their paths

        Returns
        -------
        list
            a list of database file paths

        Examples
        --------
        >>> a = GlorifiedAndroid('/path/to/apk')
        >>> a.file_shared_libs_file_paths()
        """
        self.log_debug('')
        return self.file_get_file_types().get('application/x-sharedlib')
