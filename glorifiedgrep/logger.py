import logging
import platform
import subprocess
from functools import wraps
from timeit import default_timer

class Logger:
    """
    Class handles logging config
    """

    def __init__(self, verbose: bool=True, log_path: str=None):
        """GlorifiedGrep logging function. Can control verbosity of the logging 
        (Info or Debug) and optionally write to file.

        Parameters
        ----------
        verbose : bool, optional
            Controls if logging should be debug, defaults to False, by default True
        log_path : str, optional
            Path to write log files to, defaults to None, by default None

        Examples
        --------
        >>> from glorifiedgrep.logger import Logger
        >>> Logger(verbose=True, log_path='/path/to/logfile')
        """
        self.log_verbose = verbose
        self.log_path = log_path

        # Starts the logging process
        logger = logging.getLogger()
        # Controls if logging should be verbose or informational
        if self.log_verbose:
            logger.setLevel(logging.DEBUG)
        else:
            logger.setLevel(logging.INFO)
        stream_handler = logging.StreamHandler()
        stream_formatter = logging.Formatter(
            '%(asctime)-15s %(levelname)-8s %(module)s.%(funcName)s:%(lineno)-4s %(message)s', datefmt='%A %d %H:%M:%S')
        stream_handler.setFormatter(stream_formatter)
        logger.addHandler(stream_handler)
        # If log_path is not None, it will also log to a file path provided.
        if self.log_path is not None:
            file_handler = logging.FileHandler(self.log_path, mode='w+')
            file_formatter = logging.Formatter(
                '%(asctime)-15s %(levelname)-8s %(module)s.%(funcName)s:%(lineno)-4s %(message)s', datefmt='%A %d %H:%M:%S')
            file_handler.setFormatter(file_formatter)
            logger.addHandler(file_handler)

        logging.debug('Python version: {}'.format(
            platform.python_version()
        ))
        # logs OS relevant information
        system_type = platform.system()
        if system_type == 'Linux':
            logging.debug('OS information: {}'.format(
                (platform.linux_distribution())))
        elif system_type == 'Windows':
            logging.debug('OS information: {}'.format((platform.win32_ver())))
        elif system_type == 'Darwin':
            logging.debug('OS information: {}'.format((platform.mac_ver())))
        logging.debug('OS type: {}'.format(system_type))
        # log JAVA version
        logging.debug(subprocess.getoutput('java -version').splitlines()[0])

def _logger(func):
    """
    Logger decorator
    """
    @wraps(func)
    def l(*args, **kwargs):
        try:
            start = default_timer()
            o = func(*args, **kwargs)
            end = default_timer()
            rt = str(round(end - start, 4)) + ' seconds'
            logging.debug(f'{func.__name__} runtime {rt}')
            return o
        except:
            logging.exception('')
            raise
    return l
