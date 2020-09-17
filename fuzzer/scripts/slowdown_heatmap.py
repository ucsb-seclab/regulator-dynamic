"""
slowdown_heatmap.py

Author: Robert McLaughlin <robert349@ucsb.edu>

Displays an interesting heatmap about slow-downs
"""

import psycopg2
import matplotlib.pyplot as plt
import matplotlib.colors as colors
import numpy as np
import argparse

def main():
    parser = argparse.ArgumentParser()

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
        help='The postgresql password',
        default='',
        required=True,
    )

    args = parser.parse_args()

    host, port = args.postgres.split(':')

    db: psycopg2.extensions.connection = psycopg2.connect(
        user=args.postgres_user,
        password=args.postgres_password,
        database=args.postgres_database,
        host=host,
        port=port,
    )

    curr: psycopg2.extensions.cursor = db.cursor()

    xs = []
    ys = []

    curr.execute(
        """
        SELECT strlen, maxcost
        FROM analysis_result
        WHERE width='one'
        ORDER BY random()
        LIMIT 100000
        """
    )

    max_maxcost = 0

    for x, y in curr:
        xs.append(x)
        max_maxcost = max(max_maxcost, y)
        ys.append(y)

    curr.close()
    db.close()

    xbins = list(range(4, 30 + 2))
    ybins = np.logspace(1, np.ceil(np.log10(max_maxcost)), len(xbins))

    plt.hist2d(xs, ys, bins=[xbins, ybins], cmap='PuRd', norm=colors.LogNorm())
    cb = plt.colorbar()
    cb.set_label('Number of regexps')
    plt.yscale('log')
    plt.xlabel('Subject Length')
    plt.ylabel('Maximum Cost')
    plt.title('2D Histogram: Regexp Cost Functions')
    plt.show()


if __name__ == '__main__':
    main()
