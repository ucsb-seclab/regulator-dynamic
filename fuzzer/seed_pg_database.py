"""
seed_pg_database.py

Author: Robert McLaughlin <robert349@ucsb.edu>

Seeds a postgresql database for bulk fuzzing by workers.
"""

import psycopg2
import sqlite3
import argparse
import os
import sys
import typing


def seed(
        sqlite_db: sqlite3.Connection,
        postgres_db: psycopg2.extensions.connection,
        limit: int = None,
    ):
    """
    Seed the postgres database.
    """

    print('Seeding...')

    with postgres_db.cursor() as curr:
        curr: psycopg2.extensions.cursor
        curr.execute(
            """
            CREATE TABLE IF NOT EXISTS regexp_work_queue (
                id             integer PRIMARY KEY NOT NULL,
                pattern        bytea NOT NULL,
                flags          bytea NOT NULL,
                worker         uuid DEFAULT NULL,
                time_claimed   timestamp without time zone DEFAULT NULL,
                time_completed timestamp without time zone DEFAULT NULL
            )
            """
        )
        curr.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_regexp_worker ON regexp_work_queue (worker)
            """
        )
        curr.execute(
            """
            DO $$ BEGIN
                CREATE TYPE byte_width AS ENUM ('one', 'two');
            EXCEPTION
                WHEN duplicate_object THEN null;
            END $$;
            """
        )
        curr.execute(
            """
            CREATE TABLE IF NOT EXISTS analysis_result (
                id           serial PRIMARY KEY,
                regexp_id    integer NOT NULL REFERENCES regexp_work_queue (id),
                width        byte_width NOT NULL,
                strlen       integer NOT NULL,
                maxcost      bigint NOT NULL,
                witness_utf8 bytea,
                exec_time    interval
            )
            """
        )
    postgres_db.commit()

    sq_curr = sqlite_db.cursor()
    sq_curr.execute("SELECT id, pattern, flags FROM regexps ORDER BY random()")

    with postgres_db.cursor() as pg_curr:
        pg_curr: psycopg2.extensions.cursor

        n_added = 0
        for id_, pattern, flags in sq_curr:
            pg_curr.execute(
                """
                INSERT INTO regexp_work_queue (id, pattern, flags) VALUES (%s,%s,%s)
                """,
                (id_, pattern, flags)
            )
            n_added += 1
            if limit is not None and n_added >= limit:
                break

    postgres_db.commit()

    print('done')


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        '-s', '--sqlite',
        type=str,
        help='Path to sqlite database which contains extracted regexps',
        required=True,
    )

    parser.add_argument(
        '-p', '--postgres',
        type=str,
        help='The postgresql server, as <host>:<port>',
        required=True,
    )

    parser.add_argument(
        '-pu', '--postgres-user',
        type=str,
        help='The postgresql user',
        required=True,
    )

    parser.add_argument(
        '-pd', '--postgres-database',
        type=str,
        help='The postgresql database',
        required=True,
    )

    parser.add_argument(
        '-pp', '--postgres-password',
        type=str,
        help='The postgresql password (default empty)',
        default=''
    )

    parser.add_argument(
        '-n', '--limit',
        type=int,
        help='Limit the number of regexps added (default all)',
        default=None
    )


    args = parser.parse_args()

    host, port = args.postgres.split(':')
    port = int(port)

    pg_conn = psycopg2.connect(
        user=args.postgres_user,
        password=args.postgres_password,
        database=args.postgres_database,
        host=host,
        port=port,
    )

    sq_conn = sqlite3.connect(args.sqlite)

    seed(sq_conn, pg_conn, args.limit)

if __name__ == '__main__':
    main()
