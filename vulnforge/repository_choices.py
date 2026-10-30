"""Short-lived display metadata. A choice never authorizes a connection."""
from collections import OrderedDict
import time


class RepositoryChoices:
    def __init__(self):
        self.entries=OrderedDict()

    def _prune(self):
        now=time.monotonic()
        for key,(expires,_) in list(self.entries.items()):
            if expires<=now:self.entries.pop(key,None)

    def put(self,session_hash,organization,items):
        self._prune()
        if len(items)>2000:raise ValueError('Repository selection exceeds limit')
        key=(session_hash,organization)
        self.entries.pop(key,None)
        while self.entries and (len(self.entries)>=128 or
                sum(len(value[1]) for value in self.entries.values())+len(items)>5000):
            self.entries.popitem(last=False)
        self.entries[key]=(time.monotonic()+300,tuple(row['full_name'] for row in items))

    def get(self,session_hash,organization):
        self._prune()
        entry=self.entries.get((session_hash,organization))
        return {'items':[{'full_name':name} for name in entry[1]] if entry else [],
                'requires_refresh':entry is None,'expires_in':max(0,int(entry[0]-time.monotonic())) if entry else 0}

    def clear_session(self,session_hash):
        for key in list(self.entries):
            if key[0]==session_hash:self.entries.pop(key,None)
