"""
runner.py

Repeatedly invokes the codeql docker container to analyze
all downloaded package contents.

Outputs results to postgresql.
"""

import argparse
import psycopg2
import subprocess
import os
import tempfile
import sys
import re
import concurrent.futures
import urllib.parse

def main():
    pg_host = os.getenv('POSTGRES_HOST')
    if not pg_host:
        print('POSTGRES_HOST must be set', file=sys.stderr)
        exit(1)
    pg_port = os.getenv('POSTGRES_PORT')
    if not pg_port:
        print('POSTGRES_PORT must be set', file=sys.stderr)
        exit(1)
    pg_database = os.getenv('POSTGRES_DB')
    if not pg_database:
        print('POSTGRES_DB must be set', file=sys.stderr)
        exit(1)
    pg_user = os.getenv('POSTGRES_USER')
    if not pg_user:
        print('POSTGRES_USER must be set', file=sys.stderr)
        exit(1)
    pg_pwd = os.getenv('POSTGRES_PASSWORD')
    if not pg_pwd:
        print('POSTGRES_PASSWORD must be set', file=sys.stderr)
        exit(1)
    input_dir = os.getenv('INPUT_DIR')
    if not input_dir:
        print('INPUT_DIR must be set', file=sys.stderr)
        exit(1)
    output_dir = os.getenv('OUTPUT_DIR')
    if not output_dir:
        print('OUTPUT_DIR must be set', file=sys.stderr)
        exit(1)

    port = int(pg_port)

    pg_conn = psycopg2.connect(
        user=pg_user,
        password=pg_pwd,
        database=pg_database,
        host=pg_host,
        port=port,
    )
    pg_conn: psycopg2.extensions.connection

    curr = pg_conn.cursor()
    curr: psycopg2.extensions.cursor

    curr.execute('COMMIT; BEGIN TRANSACTION;')

    # list the directories to look in
    dirs_to_explore = list(map(lambda x: os.path.join(input_dir, x), os.listdir(input_dir)))
    print(f'Found {len(dirs_to_explore)} dirs to explore')

    output_dir = os.path.abspath(output_dir)
    
    # record the version of codeql in output_dir
    proc_version = subprocess.run(
            [
                'codeql',
                'version',
            ],
            check=True,
            encoding='utf8',
            stdout=subprocess.PIPE,
    )

    pat = re.compile(r'Version:\s(.+)\.$', re.MULTILINE)
    mat = pat.search(proc_version.stdout)

    codeql_version = mat.group(1)
    print(f'Using CodeQL Version {codeql_version}')

    # write version record
    with open(os.path.join(output_dir, 'codeql.version'), mode='w') as fout:
        fout.write(codeql_version + '\n')

    def create_db_for(d):
        root = os.path.abspath(os.path.join(d, 'package'))

        out_dir = os.path.join(output_dir, os.path.split(d)[1])
        
        # if already exists then exit
        if os.path.isdir(out_dir):
            print('output dir already exists, not overwriting: ', out_dir, file=sys.stderr)
            return

        # add .tmp to the output dir, so if the program is killed while working then
        # partially-created dirs do not exist
        out_tmpdir = out_dir + '.tmp'

        os.mkdir(out_tmpdir)

        db_loc = os.path.join(out_tmpdir, 'database')

        proc1 = subprocess.run(
            [
                'codeql',
                'database',
                'create',
                '--language=javascript',
                '-s', d,
                db_loc,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        if proc1.returncode != 0:
            sout = proc1.stdout.decode('ascii')
            if 'No JavaScript or TypeScript code found.' in sout:
                # expected, ignore
                pass
            else:
                print('returncode was nonzero:', proc1.returncode)
                print(sout)
                print(proc1.stderr.decode('ascii'))
                os.unlink(out_tmpdir)
                return
        else:
            # completed successfully, move the generated dir into place
            os.rename(out_tmpdir, out_dir)

    print('Creating databases...')
    executor = concurrent.futures.ThreadPoolExecutor(max_workers=6)
    futures = [executor.submit(create_db_for, d) for d in dirs_to_explore]
    for i, _ in enumerate(concurrent.futures.as_completed(futures)):
        print(f'{i}/{len(dirs_to_explore)}')

    print('All databases created.')

    print('Sanity check, ensure all package/version are accounted-for')

    db_dirs = list(map(lambda x: os.path.join(output_dir, x), os.listdir(output_dir)))
    print(f'pre-filter, found {len(db_dirs)} dirs')
    db_dirs = list(filter(lambda x: os.path.isdir(x), db_dirs))

    print(f'Found {len(db_dirs)} dirs with a database')

    if len(db_dirs) == 0:
        print('Should have found at least 1 dir, quitting')
        exit(1)

    def do_query(db_dir):
        query_path = '/opt/regulator/constant_regexp_string_extraction.ql'
        bqrs_path = os.path.join(db_dir, 'constant_regexp_string_extraction.bqrs')
        db_path = os.path.join(db_dir, 'database')
        cache_path = '/opt/regulator/compilation_cache'

        if os.path.exists(bqrs_path):
            print('.bqrs exists, skipping... generation')
        else:
            proc = subprocess.run(
                [
                    'codeql',
                    'query',
                    'run',
                    '-o', bqrs_path + '.tmp', # output
                    '-d', db_path,   # database
                    '-j', '4',       # threads
                    f'--compilation-cache={cache_path}',
                    query_path,
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            if proc.returncode != 0:
                sout = proc.stdout.decode('ascii')
                print('returncode was nonzero:', proc.returncode)
                print(sout)
                print(proc.stderr.decode('ascii'))
                os.unlink(bqrs_path + '.tmp')
                return
            else:
                # completed successfully, move the output into place
                os.rename(bqrs_path + '.tmp', bqrs_path)
        
        csv_path = os.path.join(db_dir, 'constant_regexp_string_extraction.csv')
        proc2 = subprocess.run(
            [
                'codeql',
                'bqrs',
                'decode',
                '-o', csv_path + '.tmp',
                '--format=csv',
                bqrs_path,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        if proc2.returncode != 0:
            sout = proc2.stdout.decode('ascii')
            print('returncode was nonzero:', proc2.returncode)
            print(sout)
            print(proc2.stderr.decode('ascii'))
            os.unlink(csv_path + '.tmp')
            return
        else:
            # completed successfully, move the output into place
            os.rename(csv_path + '.tmp', csv_path)


    # perform the query over each dir
    print('performing query...')
    futures = [executor.submit(do_query, d) for d in db_dirs]
    for i, _ in enumerate(concurrent.futures.as_completed(futures)):
        print(f'{i}/{len(dirs_to_explore)}')

    # db_dir_with_package_version_id = []
    # for db_dir in db_dirs:
    #     # get the <package-name>_<version> part
    #     _, pn_ver = os.path.split(db_dir)
    #     package_id, version = pn_ver.rsplit('_', maxsplit=1)

    #     package_id = urllib.parse.unquote(package_id)

    #     # ensure it's in the database as package_version
    #     curr.execute('SELECT id FROM package_version WHERE package_id=%s AND version=%s', [package_id, version])
    #     rows = curr.fetchall()

    #     if len(rows) > 1:
    #         print(f'Found multiple package_version IDs for {package_id} - {version}')
    #         exit(1)
    #     if len(rows) == 0:
    #         print(f'Found no package_version ID for {package_id} - {version}')
    #         exit(1)
        
    #     print(f'found id = {rows[0]}')


    

if __name__ == '__main__':
    main()

