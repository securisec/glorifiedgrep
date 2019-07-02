from __future__ import annotations
from typing import Iterable
import base64
import json
import textwrap
import sqlite3

import jks
import xmltodict

from .androidcore import _AndroidCore
from ...logger import _logger

try:
    import lief  # TODO installation https://github.com/lief-project/LIEF/issues/214
except ImportError:
    print('Cannot import lief. Different build needs for py 3.7\n'
          'https://github.com/lief-project/LIEF/issues/214')
    pass


def _print_pem(der_bytes, cert_type):
    """
    Pretty prints pem keys and certificates
    """
    cert = ''
    cert += "-----BEGIN %s-----\n" % cert_type
    cert += "\r\n".join(textwrap.wrap(base64.b64encode(der_bytes).decode('ascii'), 64)) + '\n'
    cert += "-----END %s-----\n" % cert_type
    return cert


class JKS:
    """
    Process and get various information from jks files

    :param jks_file str: File path to jks file
    :param jks_password str: password to the jks file

    >>> from glorifiedgrep.android.modules.utils import JKS
    >>> j = JKS('/path/to/file', 'secretpassword')
    """

    def __init__(self, jks_file: str, jks_password: str):
        """
        The init function of the JKS class
        
        Parameters
        ----------
        jks_file : str
            The path to the .jks file
        jks_password : str
            The password for the jks file
        """
        self._core = _AndroidCore(None)
        self.jks_file = jks_file
        self.jks_password = jks_password
        self.keystore = jks.KeyStore.load(self.jks_file, self.jks_password)
        self._core.log_debug(self.__class__)

    @_logger
    def jks_key_alias(self) -> list:
        """
        Get the keystore alias from jks file

        Returns
        -------
        list
            jks keystore aliases

        Examples
        --------
        >>> j.jks_key_alias()
        """
        match = []
        for alias, pk in self.keystore.private_keys.items():
            match.append(pk.alias)
        self._core.log_debug('')
        return match

    @_logger
    def jks_private_key(self) -> list:
        """
        Get the private key from jks files

        Returns
        -------
        list
            jks private keys if password is correct

        Examples
        --------
        >>> j.jks_private_key()
        """
        match = []
        for alias, pk in self.keystore.private_keys.items():
            try:
                if pk.algorithm_oid == jks.util.RSA_ENCRYPTION_OID:
                    match.append(_print_pem(pk.pkey, "RSA PRIVATE KEY"))
                else:
                    match.append(_print_pem(pk.pkey_pkcs8, "PRIVATE KEY"))
            except TypeError:
                pass
        self._core.log_debug('')
        return match

    @_logger
    def jks_certificate(self) -> list:
        """
        Get the certificate from the jks file

        Returns
        -------
        list
            jks certificates

        Examples
        --------
        >>> j.jks_certificate()
        """
        match = []
        for alias, pk in self.keystore.private_keys.items():
            for c in pk.cert_chain:
                match.append(_print_pem(c[1], "CERTIFICATE"))
        self._core.log_debug('')
        return match


class BKS:
    """
    Process and get various information from bks files

    :param bks_file str: File path to bks file
    :param bks_password str: password to the bks file

    >>> from glorifiedgrep.android.modules.utils import BKS
    >>> b = BKS('/path/to/file', 'secretpassword')
    """

    def __init__(self, bks_file, bks_password):
        self._core = _AndroidCore(None)
        self.bks_file = bks_file
        self.bks_password = bks_password
        self.ks = jks.bks.BksKeyStore.load(self.bks_file, self.bks_password)
        self._core.log_debug(self.__class__)

    @_logger
    def bks_certificate(self) -> list:
        """
        Prints the certificate from the bks file

        Returns
        -------
        list
            bks certificates

        Examples
        --------
        >>> b.bks_certificate()
        """
        match = []
        for alias, pk in self.ks.certs.items():
            match.append(_print_pem(pk.cert, 'CERTIFICATE'))
        self._core.log_debug('')
        return match

    @_logger
    def bks_keystore_type(self) -> list:
        """
        Prints the keystore type of the bks file

        Returns
        -------
        list
            bks keystore type

        Examples
        --------
        >>> b.bks_keystore_type()
        """
        match = []
        for alias, pk in self.ks.certs.items():
            match.append(print(pk.type))
        self._core.log_debug('')
        return match

    @_logger
    def bks_keystore_alias(self) -> list:
        """
        Prints the keystore alias of the bks file

        Returns
        -------
        list
            bks keystore aliases

        Examples
        --------
        >>> b.bks_keystore_alias()
        """
        match = []
        for alias, pk in self.ks.certs.items():
            match.append(alias)
        self._core.log_debug('')
        return match


class NativeELFAnalysis():
    """
    Class is used to handle the processing and analysis of 
    native libraries included in the APK. It relies of lief 
    to handle the processing. To install lief for py 3.7, follow 
    instructions at https://github.com/lief-project/LIEF/issues/214

    :param elf_path str: path to the lib file

    >>> from glorifiedgrep.android.modules.utils import NativeELFAnalysis
    >>> n = NativeELFAnalysis('/path/to/file.so')
    """

    def __init__(self, elf_path: str):
        self._core = _AndroidCore(None)
        self.elf_path = elf_path
        self._binary = lief.ELF.parse(self.elf_path)
        self._core.log_debug(self.__class__)

    @_logger
    def elf_header_info(self) -> lief._pylief.ELF.Header:
        """
        Returns a lief header object with information obtained 
        from the binaries header
        
        Returns
        -------
        _pylief.ELF.Header : object
            Header object object

        Examples
        --------
        >>> n.elf_header_info()
        """

        self._core.log_debug('')
        return self._binary.header

    @_logger
    def elf_imported_symbols(self) -> list:
        """
        Returns a list of imported symbols from the binary

        Returns
        -------
        list
            list of imports from the binary

        Examples
        --------
        >>> n.elf_imported_symbols()
        """

        self._core.log_debug('')
        return list(x.name for x in self._binary.imported_symbols)

    @_logger
    def elf_exported_symbols(self) -> list:
        """
        Returns a list of exported symbols from the binary

        Returns
        -------
        list
            Array of exports from the binary

        Examples
        --------
        >>> n.elf_exported_symbols()
        """
        self._core.log_debug('')
        return list(x.name for x in self._binary.exported_symbols)

    @_logger
    def elf_strings_from_binary(self) -> list:
        """
        Returns a list of strings from the binary

        Returns
        -------
        list
            Array of strings from the binary

        Examples
        --------
        >>> n.elf_strings_from_binary()
        """

        self._core.log_debug('')
        return self._binary.strings

    @_logger
    def elf_libraries_binary(self) -> list:
        """
        Returns a list of libraries the binary is linked with

        Returns
        -------
        list
            Liked libraries

        Examples
        --------
        >>> n.elf_libraries_binary()
        """

        self._core.log_debug('')
        return self._binary.libraries


class NativeDEXAnalysis():
    """
    Class is used to handle the processing and analysis of 
    dex files obtained from unzipping an APK. It relies of lief 
    to handle the processing. To install lief for py 3.7, follow 
    instructions at https://github.com/lief-project/LIEF/issues/214

    :param dex_path str: path to the lib file

    >>> from glorifiedgrep.android.modules.utils import NativeELFAnalysis
    >>> n = NativeDEXAnalysis('/path/to/classes.dex')
    """

    def __init__(self, dex_path: str):
        """
        This class analyzes native dex files that are not decompiled
        
        Parameters
        ----------
        dex_path : str
            Path to dex file
        """
        self._core = _AndroidCore(None)
        self.dex_path = dex_path
        self._binary = lief.DEX.parse(self.dex_path)
        self._core.log_debug(self.__class__)

    @_logger
    def dex_parse(self) -> lief._pylief.DEX.File:
        """
        Parse the dex file and returns a lief dex file object

        Returns
        -------
        GreppedOut : object
            GreppedOut object

        Examples
        --------
        >>> n.dex_parse()
        """

        self._core.log_debug('')
        return self._binary

    @_logger
    def dex_classes(self) -> Iterable[dict]:
        """
        Parse the dex file and returns a list of class names 
        and other information

        Returns
        -------
        Iteratable
            Returns a generator of dictionaries containing the name, full_name, package_name
            source_file, and method keys

        Examples
        --------
        >>> n.dex_dex_classes()
        """

        self._core.log_debug('')
        for c in self._binary.classes:
            yield dict(zip(
                ['name', 'full_name', 'package_name', 'source_file', 'methods'],
                [c.name, c.pretty_name, c.package_name, c.source_filename,
                 [m.name for m in c.methods]]
            ))

    @_logger
    def dex_strings(self) -> Iterable[list]:
        """
        Parse the dex file and returns a generator of string values

        Returns
        -------
        Iteratable
            Returns a generator of strings

        Examples
        --------
        >>> n.dex_dex_strings()
        """

        self._core.log_debug('')
        for s in self._binary.strings:
            yield s

    @_logger
    def dex_methods(self) -> Iterable[dict]:
        """
        Parse the dex file and returns a dictionary of method information

        Returns
        -------
        Iteratable
            Returns a generator of dictionaries containing the name, class, 
            parameters and return_type keys

        Examples
        --------
        >>> n.dex_dex_methods()
        """

        self._core.log_debug('')
        for m in self._binary.methods:
            yield dict(zip(
                ['name', 'class', 'parameters', 'return_type'],
                [m.name, m.cls.pretty_name,
                 [str(x) for x in m.prototype.parameters_type], str(m.prototype.return_type)]
            ))

    @_logger
    def dex_info(self) -> Iterable[lief._pylief.DEX.File.classes]:
        """
        Parse the dex file and returns a lief dex file object

        Returns
        -------
        Iteratable
            Returns a generator of containing the class names and their 
            associated methods

        Examples
        --------
        >>> n.dex_dex_info()
        """

        self._core.log_debug('')
        for c in self._binary.classes:
            yield c


class SQL(_AndroidCore):
    """
    Class is used to process, and extract various information 
    from sqlite3 db files. It uses python sqlite3 standard 
    library. 

    :param db_path str: path to the db file

    >>> from glorifiedgrep.android.modules.utils import SQL
    >>> s = SQL('/path/to/sql_db')
    """

    def __init__(self, db_path: str):
        """
        The init method for the SQL class
        
        Parameters
        ----------
        db_path : str
            Path to a valid sqlite3 database file
        """
        self._core = _AndroidCore(None)
        self.db_path = db_path
        self._connection = sqlite3.connect(self.db_path)
        self._cursor = self._connection.cursor()
        self._core.log_debug(self.__class__)

    @_logger
    def sqldb_tables(self) -> list:
        """
        Get all the table names from the db file

        Returns
        -------
        list
            A list of table names

        Examples
        --------
        >>> s.sqldb_tables()
        """

        self._cursor.execute(
            "SELECT name FROM sqlite_master WHERE type='table';")
        self._core.log_debug('')
        return list(map(
            lambda x: x[0], self._cursor.fetchall()
        ))

    @_logger
    def sqldb_table_column_names(self, table_name: str) -> list:
        """
        Get all the column names for the specified table.

        Parameters
        ----------
        table_name : str
            An existing table name

        Returns
        -------
        list
            A list of column names from the specified table

        Examples
        --------
        >>> s.sqldb_table_column_names()
        """

        self._cursor.execute(f'SELECT * from {table_name}')
        self._core.log_debug('')
        return list(map(
            lambda x: x[0], self._cursor.description
        ))

    @_logger
    def sqldb_table_data(self, table_name: str) -> list:
        """
        Get all the data from the specified table.

        Parameters
        ----------
        table_name : str
            An existing table name

        Returns
        -------
        list
            Dumps an arry of table data

        Examples
        --------
        >>> s.sqldb_table_data()
        """

        self._cursor.execute(f'SELECT * from {table_name}')
        self._core.log_debug('')
        return self._cursor.fetchall()

    @_logger
    def sqldb_dump_database(self) -> list:
        """
        Dumps a list of all sql commands. Similar to 
        ``sqlite3 file.db .dump``

        Returns
        -------
        list
            An array of all dumped data

        Examples
        --------
        >>> s.sqldb_dump_database()
        """

        self._core.log_debug('')
        return [x for x in self._connection.iterdump()]


class Utils(_AndroidCore):
    """
    General class for helpful utilities while working with 
    unzipped or decompiled files

    >>> from glorifiedgrep.android.modules.utils import Utils
    >>> u = Utils()
    """

    def __init__(self):
        self._core = _AndroidCore(None)
        self._core.log_debug(self.__class__)

    @_logger
    def utils_xml_to_dict(self, file_path: str) -> dict:
        """
        Parse xml file and return as a dict object

        Parameters
        ----------
        file_path : str
            Path to a valid XML file

        Returns
        -------
        list
            A dictionary object representing the xml file

        Examples
        --------
        >>> u.utils_xml_to_dict('/path/to/file.xml)
        """

        with open(file_path, 'r') as f:
            self._core.log_debug('')
            return dict(xmltodict.parse(
                f.read(), process_namespaces=True, attr_prefix=''))
