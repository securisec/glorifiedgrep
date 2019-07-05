import json
import logging
import os
import platform
import re
import subprocess
from pathlib import Path
from shutil import rmtree, which
from tempfile import gettempdir
from textwrap import dedent
from zipfile import ZipFile

from .exceptions import *
from ...__version__ import __version__


class _AndroidCore():
    """
    The purpose of this class is to prepare the APK for analysis and 
    offer helper functions to other classes.
    """

    def __init__(self, apk_path: str = None, output_dir: str = None, project_dir: str = None,
                 rg_path: str = 'rg', jadx_path: str = 'jadx', clean_dir: bool = False):
        """
        The init method for the whole GlorifiedAndroid module. This is interted throughout

        :param str apk_path: Path to the APK
        :param str output_dir: Output dir for decompilation and unzipping, defaults to /tmp/glorified_android
        :param str project_dir: Project directory used for already decompiled and processed apks, defaults to None
        :param str rg_path: path to ripgrep. Defaults to looking for it in path
        :param str jadx_path: path to jadx. Defaults to looking for it in path
        :param bool clean_dir: delete the output directory before processing
        :raises NotValidPythonVersion: Raises if python version 3 is not used
        :raises DifferentAPKExists: Raises if decompiled APK is different than what is already decompiled
        :raises DependentBinaryMissing: Raises if ripgrep, or jadx is not found

        >>> # The default output directory is temp/GlorifiedAndroid folder. This can be 
        >>> # overriden using output_dir='some/path'
        >>> a = GlorifiedAndroid('/path/to/apk', output_dir='/out/dir')

        Typically, the prefix for the file path is removed when processing 
        filepaths in the various code analysis classes. This can be adjusted using 

        >>> a.dir_prefix = ''

        If **ripgrep** or **jadx** is not in path, analysis will not be complete. 
        To pass a user defined path for either jadx or rg, the GlorifiedAndroid class can be 
        instantiated as follows. 

        >>> a = GlorifiedAndroid('/path/to/apk', jadx_path='path/to/jadx', rg_path='/path/to/rg')
        """
        logging.debug(f'GlorifiedAndroid version: {__version__}')
        # place holder dictionaries to hold processing data
        self._android_findings = {
            'manifest_analysis': {},
            'code_analysis': {},
            'file_analysis': {},
            'cert_analysis': {},
            'owasp_analysis': {},
            'other_analysis': {}
        }
        #: Dict object that holds manifest analysis
        self._manifest_analysis = self._android_findings['manifest_analysis']
        #: Dict object that holds code analysis
        self._code_analysis = self._android_findings['code_analysis']
        #: Dict object that holds file analysis
        self._file_analysis = self._android_findings['file_analysis']
        #: Dict object that holds cert analysis
        self._cert_analysis = self._android_findings['cert_analysis']
        #: Dict object that holds OWASP analysis
        self._owasp_analysis = self._android_findings['owasp_analysis']
        #: Dict object that holds other analysis
        self._other_analysis = self._android_findings['other_analysis']
        #: Logging debug method binder
        self.log_debug = logging.debug
        #: Logging warning method binder
        self.log_warning = logging.warning
        #: Logging error method binder
        self.log_error = logging.error
        #: Logging info method binder
        self.log_info = logging.info
        #: Logging exception method binder
        self.log_exception = logging.exception
        #: Delete specified our specified output dir. Bool
        self._clean_dir = clean_dir
        self._jadx_path = os.path.expanduser(jadx_path)

        try:
            self._project_dir = os.path.expanduser(project_dir)
        except TypeError:
            self._project_dir = None
        logging.debug(f'PROJECT_DIR: {self._project_dir}')

        # if self._project_dir is None and apk_path is None:
        #     raise Exception('Specify either apk_path or project_dir')
        # elif self._project_dir is not None and apk_path is not None:
        #     raise Exception('Specify either apk_path or project_dir')

        if self._project_dir is not None:
            with open(f'{self._project_dir}/decompiled') as f:
                #: path for apk
                self._apk_path = f.read().splitlines()[0]
            logging.debug(f'APK_PATH: {self._apk_path}')
            #: decompile output director
            self._output_dir = self._project_dir
            logging.debug(f'OUTPUT_DIR: {self._output_dir}')
        else:
            try:
                self._apk_path = os.path.expanduser(apk_path)
            except TypeError:
                self._apk_path = None
            logging.debug(f'APK_PATH: {self._apk_path}')
            #: decompile output director
            try:
                self._output_dir = os.path.expanduser(output_dir)
            except TypeError:
                self._output_dir = None
            logging.debug(f'OUTPUT_DIR: {self._output_dir}')

        self._os_type = platform.system()
        #: Can control the timeout value for how long it takes to process decompilation
        self.decompile_timeout = 600
        #: can be set to True to handle only matching lines from whitelist
        self.match_only = False
        #: is an array and can be used to filed out file path matches. These are file paths
        self.FILTER = []

        # Checks for correct python version
        if platform.python_version()[0] != '3':
            logging.exception(NotValidPythonVersion)
            raise NotValidPythonVersion(
                'GlorifiedAndroid only works with python 3')

        #: Create temp directory if no output_dir is specified
        if self._output_dir is None:
            if self._os_type == 'Linux' or self._os_type == 'Darwin':
                self._output_dir = '/tmp/GlorifiedAndroid'
            elif self._os_type == 'Windows':
                self._output_dir = '{}/GlorifiedAndroid'.format(gettempdir())
            if not os.path.exists(self._output_dir):
                os.makedirs(self._output_dir)
                logging.debug(f'Temp dir created in {self._output_dir}')
            else:
                logging.debug(f'Directory already exists {self._output_dir}')
        else:
            if not os.path.exists(self._output_dir):
                os.makedirs(self._output_dir)
                logging.debug(f'Temp dir created in {self._output_dir}')
            else:
                logging.debug(f'Directory already exists {self._output_dir}')

        #: path to manifest file
        self._manifest_path = f'{self._output_dir}/resources/AndroidManifest.xml'
        #: unzipped dir
        self._unzipped_path = f'{self._output_dir}/unzipped'
        logging.debug(f'Unzipped path: {self._unzipped_path}')
        #: directory to decompiled JAVA source
        self._java_sources = f'{self._output_dir}/sources'

        for check in [rg_path, self._jadx_path]:
            # Does a basic sanity check to make sure required binaries exist
            if which(check) == None:
                raise DependentBinaryMissing('Required binary missing')
        #: jadx commadn to run
        self._jadx = f'{self._jadx_path} --deobf -d {self._output_dir}'
        self._ripgrep = os.path.expanduser(rg_path)
        # Check if ripgrep is installed
        if 'ripgrep' not in subprocess.getoutput('rg --version').splitlines()[0]:
            raise RipGrepNotFound('ripgrep not found.\nPlease install ripgrep')
        logging.debug(f'Binary paths: {self._jadx}, {self._ripgrep}')

        #: Path to APK
        if self._apk_path is not None:
            logging.debug('Decompiling and unzipping')
            self._decompile_apk()
            self._unzip_apk()

        # hack to find .RSA file when it is not standard name
        # only check this if the main GlorifiedAndroid class is called.
        if self.__class__.__name__ == 'GlorifiedAndroid':
            _cert_name = str(Path([x for x in os.listdir(
                f'{self._unzipped_path}/META-INF') if x.endswith('.RSA')][0]))
            self._cert_path = f'{self._unzipped_path}/META-INF/{_cert_name}'
        # path to CERT.RSA

        #: Use this to make dirpath in output shorter. Is used in an re.sub function. Default is self._outputdir+/
        self.dir_prefix = f'{self._output_dir}/'

        self.log_debug(f'{self.__class__}')

    def _run(self, command: str):
        """
        Function simply runs a command passed to it and returns a 
        list of its output

        :param command str: Command being run on the shell
        :return: List of commands output
        :rtype: list
        """
        output = subprocess.getoutput(command)
        logging.debug(f'Command ran: {command}')
        logging.debug('')
        return output

    def _run_rg(self, rg_options='', regex=None, code=False, group='', path=None):
        """
        Method to run ripgrep recursively

        :param str grep_option: ripgrep options, defaults to '-o'
        :param str regex: Regex for ripgrep, defaults to None
        :param str path: Optionally specify different path to grep
        :return: List of stdout from ripgrep
        :rtype: list
        """
        if path is None:
            path = f'{self._java_sources}'
        if code:
            command = f'{self._ripgrep} --hidden --no-heading -n {rg_options} "{regex}" {path}'
        else:
            command = f'{self._ripgrep} --hidden --no-heading -n -o {rg_options} "{regex}" {group} {path}'
        output = subprocess.Popen(command, stdout=subprocess.PIPE, shell=True)
        out, err = output.communicate()
        logging.debug(f'Grep command: {command}')
        return out.splitlines()

    def _process_match(self, data, is_url=False, owasp_category=None):
        """
        Processes the output from ripgrep and returns a dict of filename, line number
        and match

        :param list data: outoput of ripgrep command
        :param bool is_url: set to True if is url
        :param str owasp_category: Category the category under which this falls in owasp
        :return: dict of file name, line number and match
        :rtype: dict
        """
        def match_handler():
            match['file'] = file_path
            match['line'] = d[1]
            if is_url:
                match['match'] = dedent(':'.join(d[2:]))
            else:
                match['match'] = dedent(d[2])
            if owasp_category is not None:
                match['owasp_top_10'] = owasp_category
            final.append(match)
        final = []
        for d in data:
            try:
                match = {}
                d = d.decode('utf-8')
                d = d.split(':')
                file_path = self._re_remove_dir_prefix(d[0])
                if self.match_only == False:
                    if not any(white in file_path for white in self.FILTER):
                        match_handler()
                elif self.match_only:
                    if any(white in file_path for white in self.FILTER):
                        match_handler()
            except ValueError:
                pass
        return final

    def _run_rg_and_process(self, regex: str, code: bool, path: str = None, rg_options: str = ''):
        """
        Method that combines the run rg and process output functions

        :param str regex: Regex
        :param bool code: Show code
        :return: line, match and file
        :rtype: list
        """
        out = self._run_rg(regex=regex, code=code,
                           path=path, rg_options=rg_options)
        return self._process_match(out)

    def _re_remove_dir_prefix(self, string):
        """
        This method is used to remove the file path prefix from results. Defaults to 
        self._output_dir which can be overridden with self.dir_prefix

        :param str string: String to sub
        :return: string
        :rtype: str
        """
        return re.sub(f'{self.dir_prefix}', '', string)

    def _decompile_apk(self):
        """
        Decompiles the APK

        :raises DifferentAPKExists: If another APK already exists, raise exception
        """
        # delete old output dir
        if self._clean_dir == True:
            rmtree(self._output_dir)

        if not os.path.exists(f'{self._output_dir}/decompiled'):
            logging.info('Decompiling the APK')
            try:
                p = subprocess.check_output(f'{self._jadx} {self._apk_path}',
                                            shell=True, stderr=subprocess.DEVNULL,
                                            timeout=self.decompile_timeout)
                # write a placeholder to indicate decompilation is already done
                with open(f'{self._output_dir}/decompiled', 'w+') as f:
                    f.write(self._apk_path)
            except subprocess.CalledProcessError:
                with open(f'{self._output_dir}/decompiled', 'w+') as f:
                    f.write(self._apk_path)
                self.log_error('Errors in decompilation, but completed')
        else:
            # check if the apk is the same as that is being passed
            with open(f'{self._output_dir}/decompiled', 'r') as f:
                com = f.read().splitlines()
                if com[0] != self._apk_path:
                    raise DifferentAPKExists(
                        f'\nA different APK has been decompiled already.\nSet a new GlorifiedAndroid(output_dir='') or remove by setting clean_dir=True')
            logging.debug('App already decompiled')

    def _unzip_apk(self):
        """
        Unzips the APK
        """
        if not os.path.exists(self._unzipped_path):
            os.makedirs(self._unzipped_path)
            unzip = ZipFile(self._apk_path, 'r')
            unzip.extractall(self._unzipped_path)
            unzip.close()
        else:
            logging.debug('App is already unzipped')

    def _get_paths_from_unzipped(self, path: str, glob_pattern='**/*', is_file=True):
        """
        Is a generator that will return all the file paths from a 
        specified director

        :param str s: Directory path
        :param str glob_pattern: Pattern to get directory list from. Defaults to ``**/*``
        """
        g = Path(path).glob(glob_pattern)
        for i in g:
            if is_file:
                if i.is_file():
                    yield i
            else:
                yield i
