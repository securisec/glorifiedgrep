
class NotValidPythonVersion(Exception):
    """
    Raise an exception is python version is not valid
    """
    pass


class DifferentAPKExists(Exception):
    """
    Raises this exception if the APK that is already decompiled is 
    not the same as the one being decompiled
    """
    pass


class DependentBinaryMissing(Exception):
    """
    Raises this exception if ripgrep is missing in Linux or OSX
    """
    pass


class RipGrepNotFound(Exception):
    """
    Raises this exception if ripgrep is not found
    """

    pass
