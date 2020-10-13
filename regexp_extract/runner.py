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

    for i, d in enumerate(dirs_to_explore):
        print(f'{i}/{len(dirs_to_explore)}')

        root = os.path.abspath(os.path.join(d, 'package'))

        out_dir = os.path.join(output_dir, os.path.split(d)[1])
        # if already exists then exit

        if os.path.isdir(out_dir):
            print('output dir already exists, not overwriting: ', out_dir, file=sys.stderr)
            continue

        os.mkdir(out_dir)

        db_loc = os.path.join(out_dir, 'database')

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


        proc1.check_returncode()

    curr.execute('ROLLBACK')


if __name__ == '__main__':
    main()

