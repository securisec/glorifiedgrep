import logging


class GreppedOut:
    """
    Thre GreppedOut class is generally used to capture the output 
    of code analysis methods and offers various helper attributes 
    and properties.
    
    Returns
    -------
    object
    """
    def __init__(self, data):
        self.out = data

    @property
    def count(self) -> int:
        """
        A count of the number of items either in the array or dict
        that is returned. This is a property.

        Returns
        -------
        int
            Count of items
        """
        return len(self.out)

    def in_file(self, path: str) -> 'GreppedOut':
        """
        Only include matches from the files which partially 
        matches the path argument. This method can be chained 
        for multiple file paths.
        
        Returns
        -------
        GreppedOut : object
            GreppedOut object
        """
        if isinstance(self.out, list):
            self.out = [x for x in self.out if path in x['file']]
            return self
        else:
            logging.warning('Method output is not an array')
            return False

    def exclude_file(self, path: str) -> 'GreppedOut':
        """
        Exclude matches from the files which partially 
        matches the path argument. This method can be chained 
        for multiple file paths.
        
        Returns
        -------
        GreppedOut : object
            GreppedOut object
        """
        if isinstance(self.out, list):
            self.out = [x for x in self.out if path not in x['file']]
            return self
        else:
            logging.warning('Method output is not an array')
            return False

    def __repr__(self):
        return repr(self.out)
