import subprocess
import numpy as np
import matplotlib
import matplotlib.pyplot as plt
import argparse
import re
import random

total_pat = re.compile(r'Total=(\d+)')
len_pat = re.compile(r' len=(\d+)')

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        'REGEXP',
        help='The regular expression'
    )

    parser.add_argument(
        '-l','--lengths',
        type=str,
        help='The string length range to fuzz (default 4-30)',
        default='4-30',
    )

    parser.add_argument(
        '-t','--timeout',
        type=int,
        default=120,
        help='The max number of seconds to fuzz',
    )

    parser.add_argument(
        '-d', '--debug',
        action='store_true'
    )

    parser.add_argument(
        '-m', '--threads',
        help='The number of worker threads to use (default 4)',
        type=int,
        default=4,
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
    
    if args.timeout <= 0:
        print('ERROR: timeout must be positive\n')
        parser.print_help()
        exit(1)

    if args.byte_width not in [1, 2]:
        print('ERROR: byte width must be either 1 or 2\n')
        parser.print_help()
        exit(1)

    width_lo, width_hi = map(int, args.lengths.split('-'))

    if width_lo > width_hi:
        print('ERROR: width range didn\'t make sense')
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

    plt.ion()
    fig = plt.figure()
    ax = fig.add_subplot(111)

    fuzz_progress_lengths = list(range(width_lo, width_hi + 1))
    fuzz_progress_maxcosts = [0 for _ in range(width_lo, width_hi + 1)]

    prog_args = [
        './build/fuzzer',
        '-l', ','.join(map(str, fuzz_progress_lengths)),
        '-r', args.REGEXP,
        '-t', str(args.timeout),
        '-w', str(args.byte_width),
        '-m', str(args.threads),
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
        line = prog.stdout.readline().decode('ascii').strip()
        if line == '':
            continue

        if 'found opcount' in line:
            break
        
        print(line)

        if 'DEBUG' in line:
            continue

        summary_line = ''

        if line.startswith('SUMMARY'):
            summary_line = line
        else:
            print(line)
            print('UNKNOWN OUTPUT')
            exit(1)

        # figure out for which length this summary describes
        mat1 = len_pat.search(summary_line)
        l = int(mat1.group(1))

        # and what total it's at
        mat2 = total_pat.search(summary_line)
        t = int(mat2.group(1))

        fuzz_progress_maxcosts[l - width_lo] = t

        ax.clear()
        ax.set_title('Fuzzing Progress (l={0}-{1}) {2}\ncommit={3}{4}'.format(
            width_lo,
            width_hi,
            args.REGEXP,
            commit,
            '' if clean else '*',
        ))
        ax.set_xlabel('String Length')
        ax.set_ylabel('Greatest known execution cost')

        ax.bar(fuzz_progress_lengths, fuzz_progress_maxcosts)
        fig.canvas.draw()
        fig.canvas.flush_events()


    prog.kill()

    input('Press enter to exit...')

if __name__ == '__main__':
    main()
