import subprocess
import numpy as np
import matplotlib
import matplotlib.pyplot as plt
import argparse
import re
import random

elapsed_pat = re.compile(r'Elapsed:\s+(\d+?\.?\d+)')
total_pat = re.compile(r'Total=(\d+)')

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        'REGEXP',
        help='The regular expression'
    )

    parser.add_argument(
        '-l','--length',
        type=int,
        help='The string length to fuzz',
        required=True,
    )

    parser.add_argument(
        '-t','--timeout',
        type=int,
        default=120,
        help='The max number of seconds to fuzz',
    )

    parser.add_argument(
        '--runs',
        type=int,
        default=1,
        help='The number of re-seeded runs to make (default 1)',
    )

    parser.add_argument(
        '-d', '--debug',
        action='store_true'
    )

    parser.add_argument(
        '-b', '--byte-width',
        type=int,
        default=1,
        help='The number of bytes to fuzz (default 1)',
    )

    args = parser.parse_args()

    if args.REGEXP == '':
        print('ERROR: regexp is required\n')
        parser.print_help()
        exit(1)
    
    if args.length <= 0:
        print('ERROR: length must be positive\n')
        parser.print_help()
        exit(1)

    if args.timeout <= 0:
        print('ERROR: timeout must be positive\n')
        parser.print_help()
        exit(1)

    if args.byte_width not in [1, 2]:
        print('ERROR: byte width must be either 1 or 2\n')
        parser.print_help()
        exit(1)

    # figure out the current commit hash
    git_prog = subprocess.run(
        [
            'git',
            'rev-parse',
            '--short',
            'HEAD'
        ],
        stdout=subprocess.PIPE,
        check=True,
    )

    commit = git_prog.stdout.decode('ascii').strip()

    git_prog2 = subprocess.run(
        [
            'git',
            'status',
            '--porcelain',
            '--untracked-files=no'
        ],
        stdout=subprocess.PIPE,
        check=True,
    )

    clean = len(git_prog2.stdout.strip()) == 0

    # Tracks fuzz progress over time on two parallel arrays
    fuzz_progress_past_runs = []

    plt.ion()
    fig = plt.figure()
    ax = fig.add_subplot(111)

    for i in range(args.runs):
        fuzz_progress_elapsed = []
        fuzz_progress_maxcost = []

        prog_args = [
            './build/fuzzer',
            '-l', str(args.length),
            '-r', args.REGEXP,
            '-t', str(args.timeout),
            '-s', str(i * 2 + 100),
            '-w', str(args.byte_width)
        ]

        if args.debug:
            prog_args.append('--debug')

        print(prog_args)
        prog = subprocess.Popen(
            prog_args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        print('started ...')

        while prog.poll() is None:
            print('polling...')
            line = prog.stdout.readline().decode('ascii').strip()
            if line == '':
                continue

            if 'found opcount' in line:
                break
            
            print(line)

            if 'DEBUG' in line:
                continue

            elapsed_line = ''
            summary_line = ''

            if line.startswith('Elapsed'):
                elapsed_line = line
                summary_line = prog.stdout.readline().decode('ascii').strip()
            else:
                print(line)
                print('UNKNOWN OUTPUT')
                exit(1)

            print(summary_line)

            # Find out how much time has elapsed
            mat1 = elapsed_pat.search(elapsed_line)
            if mat1 is None:
                print('WHAT', elapsed_line)
            elapsed = float(mat1.group(1))

            # Find out what the max-cost string is
            mat2 = total_pat.search(summary_line)
            maxcost = int(mat2.group(1))

            fuzz_progress_elapsed.append(elapsed)
            fuzz_progress_maxcost.append(maxcost)

            ax.clear()
            ax.set_title('Fuzzing Progress (l={0}) {1}\ncommit={2}{3}'.format(
                args.length,
                args.REGEXP,
                commit,
                '' if clean else '*',
            ))
            ax.set_xlabel('Seconds elapsed')
            ax.set_ylabel('Greatest known execution cost')

            for old_elapsed, old_maxcost in fuzz_progress_past_runs:
                ax.plot(old_elapsed, old_maxcost)

            ax.plot(fuzz_progress_elapsed, fuzz_progress_maxcost)
            fig.canvas.draw()
            fig.canvas.flush_events()

        fuzz_progress_past_runs.append((fuzz_progress_elapsed, fuzz_progress_maxcost))

        prog.kill()

    input('Press enter to exit...')

if __name__ == '__main__':
    main()
