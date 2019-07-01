

class GlorifiedGrepCore(object):
    pass


class GreppedOut:
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
        if isinstance(self.out, list):
            self.out = [x for x in self.out if path in x['file']]
            return self

    def exclude_file(self, path: str) -> 'GreppedOut':
        if isinstance(self.out, list):
            self.out = [x for x in self.out if path not in x['file']]
            return self

    def __repr__(self):
        return repr(self.out)
