"""Database dialect boundary and checksummed, transactional schema migrations."""
from collections.abc import Mapping
from importlib.resources import files
import hashlib
import sqlite3
import time
import re


class DatabaseError(RuntimeError):
    pass


class Record(Mapping):
    """SQLite Row-compatible mapping, including legacy numeric column access."""
    def __init__(self,names,values):
        self.names=tuple(names);self.values=tuple(values)
    def __getitem__(self,key):
        return self.values[key] if isinstance(key,int) else self.values[self.names.index(key)]
    def __iter__(self): return iter(self.names)
    def __len__(self): return len(self.names)


def qmark_to_postgres(statement):
    """Translate only unquoted parameter markers, never data or quoted literals."""
    parts=[];quote=None;i=0
    while i<len(statement):
        char=statement[i]
        if quote:
            parts.append('%%' if char=='%' else char)
            if char==quote:
                if i+1<len(statement) and statement[i+1]==quote:
                    parts.append(statement[i+1]);i+=1
                else: quote=None
        elif char in ("'",'"'):
            quote=char;parts.append(char)
        elif char=='?': parts.append('%s')
        elif char=='%': parts.append('%%')
        else: parts.append(char)
        i+=1
    return ''.join(parts)


class PostgresConnection:
    def __init__(self,dsn):
        try: import psycopg
        except ImportError:
            raise DatabaseError('Install the postgres optional dependency group') from None
        self.driver=psycopg
        def row_factory(cursor):
            names=[column.name for column in cursor.description] if cursor.description else []
            return lambda values:Record(names,values)
        try:
            self.raw=psycopg.connect(dsn,autocommit=True,row_factory=row_factory,connect_timeout=10)
            self.raw.execute('SET search_path TO public')
            self.raw.execute("SET statement_timeout='30s'")
            self.raw.execute("SET lock_timeout='20s'")
        except psycopg.Error:
            if hasattr(self,'raw'): self.raw.close()
            raise DatabaseError('PostgreSQL connection failed; connection details are not logged') from None

    def execute(self,statement,params=None):
        try:
            sql=qmark_to_postgres(statement) if params is not None else statement
            return self.raw.execute(sql,params)
        except self.driver.Error as exc:
            # Driver errors can include customer values and DSNs in their detail.
            state=exc.sqlstate if exc.sqlstate and exc.sqlstate.isalnum() else 'unknown'
            raise DatabaseError(f'PostgreSQL operation failed (SQLSTATE {state})') from None
    def close(self): self.raw.close()


def connect_database(target,backend):
    if backend=='postgresql': return PostgresConnection(target)
    connection=sqlite3.connect(target,timeout=20,isolation_level=None)
    connection.row_factory=sqlite3.Row
    connection.execute('PRAGMA foreign_keys=ON')
    connection.execute('PRAGMA busy_timeout=20000')
    connection.execute('PRAGMA journal_mode=WAL')
    return connection


def migration_scripts(backend):
    root=files('vulnforge').joinpath('migrations')
    scripts=sorted((item for item in root.iterdir() if item.name.endswith('.'+backend+'.sql')),key=lambda p:p.name)
    return [(int(item.name.split('_',1)[0]),item.read_text(encoding='utf-8')) for item in scripts]


def split_sql(script):
    """Split controlled migration SQL outside literals, dollar bodies and comments."""
    statements=[];buffer=[];quote=None;block=0;i=0
    while i<len(script):
        if block:
            if script.startswith('/*',i): block+=1;i+=2
            elif script.startswith('*/',i): block-=1;i+=2
            else: i+=1
            continue
        if quote:
            if script.startswith(quote,i):
                buffer.append(quote);i+=len(quote)
                if quote in ("'",'"') and script.startswith(quote,i): buffer.append(quote);i+=1
                else: quote=None
            else: buffer.append(script[i]);i+=1
            continue
        if script.startswith('--',i):
            end=script.find('\n',i);i=len(script) if end<0 else end+1;buffer.append('\n');continue
        if script.startswith('/*',i): block=1;i+=2;buffer.append(' ');continue
        char=script[i]
        if char in ("'",'"'): quote=char;buffer.append(char);i+=1;continue
        if char=='$':
            match=re.match(r'\$(?:[A-Za-z_][A-Za-z0-9_]*)?\$',script[i:])
            if match: quote=match.group();buffer.append(quote);i+=len(quote);continue
        if char==';':
            statement=''.join(buffer).strip()
            if statement: statements.append(statement)
            buffer=[]
        else: buffer.append(char)
        i+=1
    if quote or block: raise DatabaseError('Unterminated migration SQL literal or comment')
    tail=''.join(buffer).strip()
    if tail: statements.append(tail)
    return statements


def verify_migrations(connection,backend,security=False):
    query=('SELECT version,checksum FROM vf_security.migration_history()' if security else
           'SELECT version,checksum FROM public.schema_migrations' if backend=='postgresql' else
           'SELECT version,checksum FROM schema_migrations')
    applied={row['version']:row['checksum'] for row in connection.execute(query).fetchall()}
    expected={version:hashlib.sha256(script.encode()).hexdigest() for version,script in migration_scripts(backend)}
    if applied!=expected: raise DatabaseError('Database migrations must be applied by the migration account')


def migrate_database(connection,backend):
    pg=backend=='postgresql'
    if pg: connection.execute('SELECT pg_advisory_lock(72419301)')
    try:
        connection.execute('BEGIN' if pg else 'BEGIN IMMEDIATE')
        try:
            connection.execute('''CREATE TABLE IF NOT EXISTS schema_migrations (
                version INTEGER PRIMARY KEY, checksum TEXT NOT NULL, applied_at DOUBLE PRECISION NOT NULL)''')
            applied={row['version']:row['checksum'] for row in connection.execute('SELECT version,checksum FROM schema_migrations').fetchall()}
            scripts=migration_scripts(backend)
            if set(applied)-{version for version,_ in scripts}:
                raise DatabaseError('Database schema is newer than this application')
            for version,script in scripts:
                checksum=hashlib.sha256(script.encode()).hexdigest()
                if version in applied:
                    if applied[version]!=checksum: raise DatabaseError('Applied migration checksum mismatch')
                    continue
                if pg:
                    statements=split_sql(script)
                else:
                    # SQLite's parser knows trigger BEGIN/END bodies; a bare
                    # semicolon splitter would cut a trigger in half.
                    statements=[];buffer=''
                    for char in script:
                        buffer+=char
                        if char==';' and sqlite3.complete_statement(buffer):
                            statements.append(buffer);buffer=''
                    if buffer.strip():
                        statements.extend(split_sql(buffer))
                for statement in statements: connection.execute(statement)
                connection.execute('INSERT INTO schema_migrations VALUES(?,?,?)',(version,checksum,time.time()))
            connection.execute('COMMIT')
        except BaseException:
            connection.execute('ROLLBACK')
            raise
    finally:
        if pg: connection.execute('SELECT pg_advisory_unlock(72419301)')
