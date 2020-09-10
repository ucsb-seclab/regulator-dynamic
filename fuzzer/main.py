#
# main.py
#
# Author: Robert McLaughlin <robert349@ucsb.edu>
#
# Entrypoint for bulk fuzzing of regular expressions.
#
# Expected format for input file is one regexp to fuzz
# per line. First the regexp source as base64, then a space
# character, then the flags as raw ascii.
#

import argparse
import psycopg2
import subprocess
import time
import base64
import os
import sys
import re
import random
import multiprocessing
import uuid
import typing

bytewidth_pat = re.compile(r'^SUMMARY (\d)-byte ')
maxcost_pat = re.compile(r'^.+Total=(\d+).+?$')
strlen_pat = re.compile(r'SUMMARY.+?len=(\d+) ')
witness_pat = re.compile(r'width=\d\s+word="(.+)"\s+Total=')
work_time_pat = re.compile(r'Work-Time:\s+([0-9.]+)\s')

def claim_one_regexp(db: psycopg2.extensions.connection, my_id: uuid.UUID) -> typing.Tuple[int, bytes, bytes]:
    """
    Picks one unclaimed regexp, marks it as claimed, then returns the regexp details.

    Returns None if there are no unclaimed regexps left.

    Returns (id, pattern, flags)
    """
    curr: psycopg2.extensions.cursor = db.cursor()
    curr.execute(
        """
        SELECT id, pattern, flags
        FROM regexp_work_queue
        WHERE worker = NULL
        ORDER BY random()
        LIMIT 1
        FOR UPDATE
        """
    )

    all_results = curr.fetchall()

    if len(all_results) < 0:
        return None

    id_, pattern, flags = all_results[0]

    curr.execute(
        """
        UPDATE regexp_work_queue
        SET worker = %s, time_claimed = NOW()::timestamp
        WHERE id = %s
        """,
        (str(my_id), id_)
    )

    db.commit()

    return (id_, pattern, flags)


def main():
    parser = argparse.ArgumentParser(
        description='Driver for bulk fuzzing of regular expressions for slowdowns',
    )

    parser.add_argument(
        '-p', '--postgres',
        type=str,
        help='The postgresql server, as <host>:<port> (default: postgres:5432)',
        default='postgres:5432',
    )

    parser.add_argument(
        '-pu', '--postgres-user',
        type=str,
        help='The postgresql user (if not found, consults POSTGRES_USER env var)',
    )

    parser.add_argument(
        '-pd', '--postgres-database',
        type=str,
        help='The postgresql database (if not found, consults POSTGRES_DB env var)',
    )

    parser.add_argument(
        '-pp', '--postgres-password',
        type=str,
        help='The postgresql password (default empty, if not found, consults POSTGRES_PASSWORD)',
        default=''
    )


    parser.add_argument(
        '-l', '--lengths',
        type=str,
        help='The range of string lengths to fuzz (default: 4-30)',
        default='4-30',
    )

    parser.add_argument(
        '-m', '--threads',
        type=int,
        help='The number of threads to use (default: #cores - 1 or 1, whichever is greater)',
        default=-1,
    )

    parser.add_argument(
        '-t', '--timeout',
        type=int,
        help='How many seconds to fuzz each regexp for',
        default=120,
    )

    parser.add_argument(
        '-e', '--etimeout',
        type=int,
        help='Cease fuzzing of a specific fuzz-length if no progress was made within this many seconds',
        default=30,
    )

    parser.add_argument(
        '-w', '--widths',
        type=str,
        help='The widths to fuzz (either "1", "2", or "1,2")',
        default="1,2",
    )

    parser.add_argument(
        '-d', '--debug',
        help='Enable debug mode',
        action='store_true'
    )

    args = parser.parse_args()

    if not args.postgres_user:
        args.postgres_user = os.environ["POSTGRES_USER"] or None

    if not args.postgres_password:
        args.postgres_password = os.environ["POSTGRES_PASSWORD"] or None

    if not args.postgres_database:
        args.postgres_database = os.environ["POSTGRES_DB"] or None

    if args.threads == -1:
        # use default, which is all but one
        args.threads = max(multiprocessing.cpu_count() - 1, 1)
    print(f'Using {args.threads} threads')

    width_lo, width_hi = map(int, args.lengths.split('-'))
    lengths = list(range(width_lo, width_hi + 1))

    widths = list(map(lambda x: int(x.strip()), args.widths.split(',')))

    host, port = args.postgres.split(':')

    # open the database
    db: psycopg2.extensions.connection = psycopg2.connect(
        user=args.postgres_user,
        password=args.postgres_password,
        database=args.postgres_database,
        host=host,
        port=port,
    )

    # identify myself uniquely
    my_id = uuid.uuid4()

    print(f'my id: {str(my_id)}')

    # loop: keep asking for more regexps
    with db.cursor() as curr:
        curr: psycopg2.extensions.cursor
        while True:
            next_regex = claim_one_regexp(db, my_id)

            if next_regex is None:
                # Nothing found left in the database
                print('Nothing left to fuzz, quitting')
                break

            id_, pattern, flags = next_regex
            print(f'Fuzzing #{id_} regexp {pattern} with flags {flags}')

            # map from "len-bytewidth" to row id
            ids = {}

            # prime the database for each length and width
            for charwidth in widths:
                for l in lengths:
                    curr.execute(
                        """
                        INSERT INTO analysis_result (regexp_id, strlen, width, maxcost, exec_time)
                        VALUES (%s, %s, %s, %s, INTERVAL %s)
                        """,
                        (
                            regexp_id,
                            l,
                            charwidth,
                            0,
                            '0 second'
                        )
                    )
                    ids[f"{l}-{charwidth}"] = curr.lastrowid

            db.commit()

            prog_args = [
                'build/fuzzer',
                '-m', str(args.threads),
                '-t', str(args.timeout),
                '-l', ','.join(map(str, lengths)),
                '-e', str(args.etimeout),
                '-b', base64.b64encode(source).decode('ascii'),
                '-f', flags.decode('ascii'),
                '-w', ','.join(map(str, widths)),
            ]

            if args.debug:
                prog_args.append('--debug')

            prog = subprocess.Popen(
                prog_args,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            last_commit = time.time()
            while prog.poll() is None:
                line = prog.stdout.readline().decode('utf8').strip()

                if not line.startswith('SUMMARY'):
                    # not interesting line
                    print(line)
                    continue

                if random.randint(0, 100) < 10:
                    print(line)

                mat1 = bytewidth_pat.search(line)
                w = int(mat1.group(1))

                mat2 = maxcost_pat.search(line)
                c = int(mat2.group(1))

                mat3 = strlen_pat.search(line)
                l = int(mat3.group(1))

                mat4 = witness_pat.search(line)
                witness = mat4.group(1)

                mat5 = work_time_pat.search(line)
                work_time = float(mat5.group(1))

                id_ = ids[f"{l}-{w}"]
                assert id_ is not None
                curr.execute(
                    """
                    UPDATE analysis_result
                    SET maxcost=%s, witness_utf8=%s, exec_time=interval %s
                    WHERE id=%s
                    """,
                    (c, witness.encode('ascii'), f"{work_time} second", id_)
                )

                if time.time() > last_commit + 10:
                    # commit every 10 seconds for good measure
                    last_commit = time.time()
                    db.commit()

            if prog.returncode != 0:
                if prog.returncode == 15:
                    print('Not an irregexp...')
                else:
                    print('crashed? return code =', prog.returncode)
                    print(prog.stderr.read().decode('utf8'))
                    exit(1)

            prog.kill()

    db.commit()
    db.close()


if __name__ == '__main__':
    main()
