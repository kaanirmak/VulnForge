"""Read-only SQLite snapshot -> empty PostgreSQL database, preserving IDs and evidence."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sqlite3
from urllib.parse import quote

from .db import Store
from .database import DatabaseError

TABLES=('users','organizations','memberships','repositories','deliveries','jobs','findings','dependency_inventory','remediations',
        'scans','scan_findings','audit_events','suppressions','advisories','advisory_aliases',
        'advisory_impacts','runner_reports','repository_ownership','auth_states','user_sessions','invitations','remediation_policies',
        'runner_policies','runner_receipts','runner_token_uses','connection_intents')
SERIAL_TABLES=('jobs','findings','remediations','audit_events','advisory_impacts')


def fingerprint(rows,columns):
    """Order-independent digest of exact scalar row values, never returned as records."""
    encoded=(json.dumps([row[column] for column in columns],ensure_ascii=True,separators=(',',':')) for row in rows)
    return hashlib.sha256('\n'.join(sorted(encoded)).encode()).hexdigest()


def import_sqlite(source_path, target_url):
    if not target_url.startswith(('postgresql://','postgres://')):
        raise ValueError('An empty PostgreSQL target is required')
    source=Path(source_path).resolve(strict=True)
    if not source.is_file(): raise ValueError('A SQLite database file is required')
    target=Store(target_url)
    # mode=ro prevents accidental creation/writes; a transaction pins the source
    # snapshot even if an unrelated reader is present. Operators must stop writers
    # for an actual cutover, so no post-snapshot updates can be lost.
    connection=sqlite3.connect('file:'+quote(str(source),safe='/')+'?mode=ro',uri=True,isolation_level=None)
    connection.row_factory=sqlite3.Row
    counts={}
    try:
        connection.execute('BEGIN')
        known={row['name'] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if not {'repositories','jobs','findings'}<=known:
            raise ValueError('Source is not a supported VulnForge database')
        with target.transaction(), target.conn() as c:
            c.execute('LOCK TABLE '+','.join(TABLES)+' IN ACCESS EXCLUSIVE MODE')
            if any(c.execute(f'SELECT COUNT(*) FROM {table}').fetchone()[0] for table in TABLES):
                raise ValueError('PostgreSQL target must be empty; no records were overwritten')
            # Preserve the snapshot's immutable connection epochs. This
            # migration-account-only operation is transactional; runtime
            # ownership changes must always rotate them.
            c.execute('ALTER TABLE repository_ownership DISABLE TRIGGER repository_connection_ownership')
            for table in TABLES:
                columns=[row['column_name'] for row in c.execute('''SELECT column_name FROM information_schema.columns
                    WHERE table_schema='public' AND table_name=? ORDER BY ordinal_position''',(table,)).fetchall()]
                if table not in known:
                    counts[table]=0
                    continue
                source_columns=[row['name'] for row in connection.execute(f'PRAGMA table_info({table})')]
                if source_columns!=columns:
                    raise ValueError('SQLite schema differs from the supported migration baseline')
                rows=connection.execute(f'SELECT * FROM {table}').fetchall()
                names=','.join('"'+name.replace('"','""')+'"' for name in columns)
                statement=f'INSERT INTO {table} ({names}) VALUES ('+','.join('?' for _ in columns)+')'
                for row in rows: c.execute(statement,tuple(row))
                imported=c.execute(f'SELECT * FROM {table}').fetchall()
                if len(rows)!=len(imported) or fingerprint(rows,columns)!=fingerprint(imported,columns):
                    raise DatabaseError('Migration verification failed; target transaction rolled back')
                counts[table]=len(rows)
            for table in SERIAL_TABLES:
                highest=c.execute(f'SELECT COALESCE(MAX(id),0) FROM {table}').fetchone()[0]
                if 'sqlite_sequence' in known:
                    row=connection.execute('SELECT seq FROM sqlite_sequence WHERE name=?',(table,)).fetchone()
                    if row: highest=max(highest,row[0])
                c.execute("SELECT setval(pg_get_serial_sequence(?, 'id'), ?, ?)",(table,max(1,highest),highest>0))
            c.execute('ALTER TABLE repository_ownership ENABLE TRIGGER repository_connection_ownership')
        connection.execute('ROLLBACK')  # release read-only snapshot, never modify source
    finally:
        connection.close()
    return {'verified':True,'tables':counts,'source_modified':False,
            'note':'running leases and all evidence preserved; review jobs before starting workers'}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source',required=True,help='Read-only SQLite source file')
    args=parser.parse_args()
    url=os.getenv('DATABASE_URL','')
    try:
        result=import_sqlite(args.source,url)
    except (ValueError,DatabaseError,sqlite3.Error,OSError):
        parser.exit(2,'Migration failed; source/target details and customer records are not printed. Check the runbook.\n')
    print(json.dumps(result,sort_keys=True))


if __name__=='__main__': main()
