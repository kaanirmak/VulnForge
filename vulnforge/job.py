"""Provider boundary for a single server-authorized queue claim."""
import inspect


class GuardedProvider:
    def __init__(self,provider,check):
        self._provider=provider
        self._check=check

    def __getattr__(self,name):
        value=getattr(self._provider,name)
        if not inspect.iscoroutinefunction(value):
            return value
        async def guarded(*args,**kwargs):
            self._check()
            result=await value(*args,**kwargs)
            self._check()
            return result
        return guarded


class JobStore:
    """Small worker API: no global row listings, queue administration or raw SQL.

    Database-role enforcement remains separate; this is an application boundary.
    """
    REPO_METHODS=frozenset(('repository','upsert_repo','save_finding','replace_inventory',
        'resolve_missing_dependencies','save_impact','reconcile_impacts','invalidate_impacts',
        'impact_advisory_ids','save_remediation','has_remediation','remediation_policy','start_scan','audit_event'))
    SCAN_METHODS=frozenset(('set_scan_commit','finish_scan','record_scan_finding','scan'))
    PUBLIC_METHODS=frozenset(('advisory','source_advisories','save_advisory'))

    def __init__(self,store,job):
        self._store=store
        self._repo=job['repo']
        self._installation=job['installation_id']

    def transaction(self):
        return self._store.transaction()

    def enqueue(self,kind,repo,payload,key,delay=0):
        self._repo_check(repo)
        return self._store.enqueue(kind,repo,payload,key,delay)

    def _repo_check(self,repo):
        if repo!=self._repo: raise PermissionError('Repository outside job scope')

    def __getattr__(self,name):
        if name not in self.REPO_METHODS|self.SCAN_METHODS|self.PUBLIC_METHODS:
            raise PermissionError('Operation outside job scope')
        method=getattr(self._store,name)
        def scoped(*args,**kwargs):
            if name in self.REPO_METHODS:
                self._repo_check(args[0] if args else kwargs.get('repo',kwargs.get('name')))
                if name=='upsert_repo':
                    installation=args[1] if len(args)>1 else kwargs.get('installation_id')
                    if installation!=self._installation:
                        raise PermissionError('Installation outside job scope')
            if name in self.SCAN_METHODS:
                scan_id=args[0] if args else kwargs.get('scan_id')
                with self._store.conn() as c:
                    row=c.execute('SELECT repo FROM scans WHERE id=?',(scan_id,)).fetchone()
                    if row is None or row['repo']!=self._repo:
                        raise PermissionError('Scan outside job scope')
                    # Keep validation and mutation in the same guarded transaction.
                    return method(*args,**kwargs)
            return method(*args,**kwargs)
        return scoped
