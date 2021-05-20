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
import shutil
import csv
import threading
import psutil
import time
import uuid


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

    curr.execute("""
        CREATE TABLE IF NOT EXISTS regexps (
            id      SERIAL PRIMARY KEY,
            pattern BYTEA NOT NULL,
            flags   BYTEA NOT NULL 
        )
    """)

    curr.execute("""
        CREATE INDEX IF NOT EXISTS idx_regexps_pattern ON regexps USING hash (pattern)
    """)

    curr.execute("""
        CREATE TABLE IF NOT EXISTS regexp_literals (
            id SERIAL PRIMARY KEY,
            package_version_id INTEGER NOT NULL,
            file_path TEXT NOT NULL,
            line_start INTEGER NOT NULL,
            line_end INTEGER NOT NULL,
            col_start INTEGER NOT NULL,
            col_end INTEGER NOT NULL,
            regexp_id INTEGER NOT NULL,
            CONSTRAINT fk_regexp_id
                FOREIGN KEY (regexp_id)
                    REFERENCES regexps(id)
        )
    """)

    curr.execute("""
        CREATE INDEX IF NOT EXISTS idx_regexp_literals_package_version_id ON regexp_literals(package_version_id) 
    """)

    curr.execute("""
        CREATE INDEX IF NOT EXISTS idx_regexp_literals_regexp_id ON regexp_literals(regexp_id)
    """)

    curr.execute("""
        CREATE TABLE IF NOT EXISTS regexp_dynamics (
            id SERIAL PRIMARY KEY,
            package_version_id INTEGER NOT NULL,
            file_path TEXT NOT NULL,
            line_start INTEGER NOT NULL,
            line_end INTEGER NOT NULL,
            col_start INTEGER NOT NULL,
            col_end INTEGER NOT NULL,
            regexp_id INTEGER NOT NULL,
            call_type TEXT NOT NULL,
            CONSTRAINT fk_regexp_id
                FOREIGN KEY (regexp_id)
                    REFERENCES regexps(id)
        )
    """)

    curr.execute("""
        CREATE INDEX IF NOT EXISTS idx_regexp_dynamics_package_version_id ON regexp_dynamics(package_version_id) 
    """)

    curr.execute("""
        CREATE INDEX IF NOT EXISTS idx_regexp_dynamics_regexp_id ON regexp_dynamics(regexp_id)
    """)

    curr.execute('COMMIT; BEGIN TRANSACTION;')

    print('[*] Connected to postgresql')

    curr.execute(
        """
        SELECT pd.package_id, pv.version
        FROM package_downloads pd
        LEFT JOIN package_version pv
            ON pd.package_id = pv.package_id
        WHERE pd.package_id NOT LIKE \'@types/%\'
        ORDER BY downloads DESC LIMIT 10000
        """
    )

    # list the directories to look in
    dirs_downloaded = set(map(lambda x: os.path.join(input_dir, x), os.listdir(input_dir)))
    print(f'Found {len(dirs_downloaded)} dirs of packages downloaded')

    dirs_to_explore = set()
    for package_id, version in curr:
        dir = os.path.join(input_dir, urllib.parse.quote(package_id, safe='') + '_' + urllib.parse.quote(version, safe=''))
        if not os.path.isdir(dir):
            print(f'Did not find expected dir {dir}', file=sys.stderr)
            exit(1)
        dirs_to_explore.add(dir)

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

    pat = re.compile(r'CodeQL command-line toolchain release (.+)\.\s*$', re.MULTILINE)
    print(proc_version.stdout)
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
            # print('output dir already exists, not overwriting: ', out_dir, file=sys.stderr)
            return

        # add .tmp to the output dir, so if the program is killed while working then
        # partially-created dirs do not exist
        out_tmpdir = out_dir + '.tmp'

        os.mkdir(out_tmpdir)

        db_loc = os.path.join(out_tmpdir, 'database')

        print('creating database', d)
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
            if 'No JavaScript or TypeScript code found.' in sout or 'Only found JavaScript or TypeScript files that were empty or contained syntax errors' in sout:
                # expected, ignore this
                print(f'No JS/TS found in {os.path.split(d)[-1]}')
                open(os.path.join(out_tmpdir, '.no-js-files'), mode='w').close()
                os.rename(out_tmpdir, out_dir)
            else:
                print('returncode was nonzero!!!:', proc1.returncode)
                print(sout)
                print(proc1.stderr.decode('ascii'))
                shutil.rmtree(out_tmpdir)
                raise Exception("returncode was nonzero")
        else:
            # completed successfully, move the generated dir into place
            os.rename(out_tmpdir, out_dir)

    executor = concurrent.futures.ThreadPoolExecutor(max_workers=3)
    """
    print('Creating databases...')
    futures = [executor.submit(create_db_for, d) for d in dirs_to_explore]
    for i, result in enumerate(concurrent.futures.as_completed(futures)):
        result.result()
        if i % 10 == 0:
            print(f'(creating databases) {i}/{len(dirs_to_explore)}')

    print('All databases created.')
    """

    print('Sanity check, ensure all package/version are accounted-for')

    db_dirs = list(map(lambda x: os.path.join(output_dir, x), os.listdir(output_dir)))
    db_dirs = list(filter(lambda x: os.path.isdir(x), db_dirs))

    print(f'Found {len(db_dirs)} dirs with a database')

    if len(db_dirs) == 0:
        print('Should have found at least 1 dir, quitting')
        exit(1)

    db_dir_with_package_version_id = []
    for db_dir in db_dirs:
        # get the <package-name>_<version> part
        _, pn_ver = os.path.split(db_dir)
        package_id, version = pn_ver.rsplit('_', maxsplit=1)

        package_id = urllib.parse.unquote(package_id)

        # ensure it's in the database as package_version
        curr.execute('SELECT id FROM package_version WHERE package_id=%s AND version=%s', [package_id, version])
        rows = curr.fetchall()

        if len(rows) > 1:
            print(f'Found multiple package_version IDs for {package_id} - {version}')
            exit(1)
        if len(rows) == 0:
            print(f'Found no package_version ID for {package_id} - {version}')
            exit(1)

        id_ = int(rows[0][0])

        db_dir_with_package_version_id.append((db_dir, id_))


    def do_queries(db_dir, id_):
        timeout_secs = 10 * 60 # 10-minute timeout, idk
        csv_paths = []
        
        tmp_db = None
        for qpath in ['regexp_literal.ql', 'constant_regexp_string_extraction.ql']:
            query_name = (os.path.split(qpath)[-1]).rsplit('.', maxsplit=1)[0]

            query_path = os.path.join('/opt/regulator/queries/', qpath)

            bqrs_path = os.path.join(db_dir, f'{query_name}.bqrs')
            sentinel_already_processed_path = os.path.join(db_dir, f'{query_name}.already_ingested')
            sentinel_timeout = os.path.join(db_dir, f'{query_name}.{timeout_secs}.timeout')

            db_path = os.path.join(db_dir, 'database')
            cache_path = '/opt/regulator/compilation_cache'

            if os.path.exists(os.path.join(db_dir, '.no-js-files')):
                # there's no javascript here, skip
                print('no javascript, skipping...')
                continue

            if os.path.exists(sentinel_already_processed_path):
                print('already ingested this, skipping...')
                continue

            if os.path.exists(sentinel_timeout):
                print('previous timeout, skipping...')
                continue

            # too much mem is in use, wait for things to process...
            while psutil.virtual_memory().percent > 80:
                print('low mem, waiting....')
                time.sleep(10)
            
            # NOTE: I'm not sure if output dir is growing in size b/c of database bloat..?
            # so this function copies the db_dir to a temporary directory and returns the
            # destination
            if tmp_db is None:
                t1 = time.time()
                dest = os.path.join('/opt/regulator/tmp', 'regulator_db_tmp_' + str(uuid.uuid4()))
                shutil.copytree(os.path.join(db_dir, 'database'), dest)
                tmp_db = dest

            if not os.path.exists(bqrs_path):
                print('querying', db_dir)
                try:
                    print(f'executing {query_name} on {tmp_db}')
                    proc = subprocess.run(
                        [
                            'codeql',
                            'query',
                            'run',
                            '-o', bqrs_path + '.tmp', # output
                            '-d', tmp_db,   # database
                            '-j', '1',       # threads
                            f'--compilation-cache={cache_path}',
                            query_path,
                        ],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        timeout=timeout_secs, # 10 minute timeout; after that this will probably not complete?
                    )
                except subprocess.TimeoutExpired:
                    print('timeout expired')
                    open(sentinel_timeout, mode='w').close()
                    continue
                if proc.returncode != 0:
                    sout = proc.stdout.decode('ascii')
                    print('returncode was nonzero:', proc.returncode)
                    print(sout)
                    print(proc.stderr.decode('ascii'))
                    os.unlink(bqrs_path + '.tmp')
                    continue
                else:
                    # completed successfully, move the output into place
                    os.rename(bqrs_path + '.tmp', bqrs_path)

            csv_path = os.path.join(db_dir, f'{query_name}.csv')
            if not os.path.exists(csv_path):
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
                    continue
                else:
                    # completed successfully, move the output into place
                    os.rename(csv_path + '.tmp', csv_path)
                    csv_paths.append(csv_path)

        if tmp_db is not None:
            shutil.rmtree(tmp_db)

        return (csv_paths, id_)

    def insert_regexp_literals_from_csv(csv_paths, pv_id):            
        # we should have the CSV file by now, so attempt to open it &
        # send the results to postgresql
        my_curr = pg_conn.cursor()
        my_curr: psycopg2.extensions.cursor

        my_curr.execute("BEGIN TRANSACTION")

        for csv_path in csv_paths:
            # we know that the CSV file name is {query_name}.csv, so extract that
            query_name = os.path.split(csv_path)[-1].rsplit('.', maxsplit=1)[0]

            sentinel_already_processed_path = os.path.join(
                os.path.dirname(csv_path),
                f'{query_name}.already_ingested',
            )

            # if we already have entries for this package_version then quit
            if 'regexp_literal' in csv_path:
                my_curr.execute(
                    "SELECT COUNT(*) FROM regexp_literals WHERE package_version_id = %s",
                    [pv_id]
                )
            elif 'constant_regexp' in csv_path:
                my_curr.execute(
                    "SELECT COUNT(*) FROM regexp_dynamics WHERE package_version_id = %s",
                    [pv_id]
                )
            else:
                raise Exception('Unreachable state')

            if my_curr.fetchone()[0] > 0:
                print('already processed regexps here')
                my_curr.close()
                continue

            # this should never occur
            if os.path.exists(sentinel_already_processed_path):
                raise Exception('Unreachable state')

            with open(csv_path, mode='r', newline='') as csvfile:
                reader = csv.reader(csvfile)
                next(reader) # skip the header
                for row in reader:
                    file_path, \
                        col_start, \
                        col_end, \
                        line_start, \
                        line_end, \
                        pattern, \
                        flags = row[:7]

                    # Is this already in the regex db? get ID
                    my_curr.execute(
                        """
                        SELECT id FROM regexps WHERE pattern = %s AND flags = %s
                        """,
                        [pattern.encode('utf8'), flags.encode('utf8')]
                    )

                    maybe_id = my_curr.fetchall()
                    regexp_id = None
                    if len(maybe_id) > 0:
                        # already inserted
                        regexp_id = maybe_id[0][0]
                    else:
                        # does not exist, insert
                        my_curr.execute(
                            "INSERT INTO regexps (pattern, flags) VALUES (%s,%s) RETURNING id",
                            [pattern.encode('utf8'), flags.encode('utf8')]
                        )
                        regexp_id = my_curr.fetchone()[0]
                    
                    # step 2 -- insert
                    if 'regexp_literal' in csv_path:
                        my_curr.execute(
                            """
                            INSERT INTO regexp_literals (
                                package_version_id,
                                file_path,
                                line_start,
                                line_end,
                                col_start,
                                col_end,
                                regexp_id
                            ) VALUES (%s,%s,%s,%s,%s,%s,%s)
                            """,
                            [pv_id, file_path, line_start, line_end, col_start, col_end, regexp_id]
                        )
                    else:
                        call_type = row[7]
                        my_curr.execute(
                            """
                            INSERT INTO regexp_dynamics (
                                package_version_id,
                                file_path,
                                line_start,
                                line_end,
                                col_start,
                                col_end,
                                regexp_id,
                                call_type
                            ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
                            """,
                            [pv_id, file_path, line_start, line_end, col_start, col_end, regexp_id, call_type]
                        )
            # end `with` structure
        # end for each csv_path

        # remove the dust-files and add sentinel
        for csv_path in csv_paths:
            # we know that the CSV file name is {query_name}.csv, so extract that
            query_name = os.path.split(csv_path)[-1].rsplit('.', maxsplit=1)[0]

            sentinel_already_processed_path = os.path.join(
                os.path.dirname(csv_path),
                f'{query_name}.already_ingested',
            )

            bqrs_path = os.path.join(
                os.path.dirname(csv_path),
                f'{query_name}.bqrs'
            )

            os.unlink(bqrs_path)
            os.unlink(csv_path)
            open(sentinel_already_processed_path, mode='w').close()


        my_curr.execute("COMMIT")
        my_curr.close()


    # perform the query over each dir
    print('performing query...')
    csvs_to_investigate = []

    futures = [executor.submit(do_queries, d, id_) for d, id_ in db_dir_with_package_version_id]
    for i, result in enumerate(concurrent.futures.as_completed(futures)):
        result_ = result.result()
        if result_ is not None:
            csv_paths, pv_id_ = result_
            insert_regexp_literals_from_csv(csv_paths, pv_id_)
        if i % 10 == 0:
            print(f'(running queries) {i}/{len(dirs_to_explore)}')
    
    print('finishing inserts...')
    executor.shutdown(wait=True)
    print('done')


if __name__ == '__main__':
    main()

