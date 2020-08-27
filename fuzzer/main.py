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
import sqlite3
import subprocess
import time
import base64
import os
import sys
import re
import random

bytewidth_pat = re.compile(r'^SUMMARY (\d)-byte ')
maxcost_pat = re.compile(r'^.+Total=(\d+).+?$')
strlen_pat = re.compile(r'SUMMARY.+?len=(\d+) ')
witness_pat = re.compile(r'width=\d\s+word="(.+)"\s+Total=')

def main():
    parser = argparse.ArgumentParser(
        description='Driver for bulk fuzzing of regular expressions for slowdowns',
    )

    parser.add_argument(
        '-b', '--database',
        type=str,
        help='Path to sqlite database to use for input queue / output',
        required=True,
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
        help='The number of threads to use',
        default=4,
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

    width_lo, width_hi = map(int, args.lengths.split('-'))
    lengths = list(range(width_lo, width_hi + 1))

    widths = list(map(lambda x: int(x.strip()), args.widths.split(',')))

    # Read the queue of regular expressions to process

    # open the database
    db = sqlite3.connect(args.database)
    curr = db.cursor()

    # gather the queue of all regular expressions to process
    curr.execute("SELECT id, pattern, flags FROM regexps")
    regexp_queue = curr.fetchall()

    # create the right tables in the database
    curr.execute(
        """
        CREATE TABLE IF NOT EXISTS fuzz_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            regexp_id INTEGER NOT NULL,
            strlen INTEGER NOT NULL,
            bytewidth INTEGER NOT NULL,
            maxcost INTEGER NOT NULL,
            witness TEXT
        )
        """
    )
    db.commit()

    # begin fuzz process
    print(f'Beginning fuzz. {len(regexp_queue)} regexp items to process.')
    
    for i, (regexp_id, source, flags) in enumerate(regexp_queue):
        print(f'Fuzzing {i} / {len(regexp_queue)} regexp {source} with flags \'{flags}\'')

        # map from "len-bytewidth" to row id
        ids = {}

        # prime the sqlite database for each length and width
        for charwidth in widths:
            for l in lengths:
                curr.execute(
                    """
                    INSERT INTO fuzz_results (regexp_id, strlen, bytewidth, maxcost)
                    VALUES (?,?,?,?)
                    """,
                    (
                        regexp_id,
                        l,
                        charwidth,
                        0
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
            '-f', flags,
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

            id_ = ids[f"{l}-{w}"]
            assert id_ is not None
            curr.execute("UPDATE fuzz_results SET maxcost=?, witness=? WHERE id=?", (c, witness, id_))

            if time.time() > last_commit + 5:
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

    curr.close()
    db.close()


if __name__ == '__main__':
    main()
