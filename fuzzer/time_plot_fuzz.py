import subprocess
import numpy as np
import matplotlib
import matplotlib.pyplot as plt
import argparse
import re

elapsed_pat = re.compile(r'Elapsed:\s+(\d+?\.?\d+) ')
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

    prog = subprocess.Popen(
        [
            './build/fuzzer',
            '-l', str(args.length),
            '-r', args.REGEXP,
            '-t', str(args.timeout),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    # Tracks fuzz progress over time on two parallel arrays
    fuzz_progress_elapsed = []
    fuzz_progress_maxcost = []

    plt.ion()
    fig = plt.figure()
    ax = fig.add_subplot(111)

    while prog.poll() is None:
        line = prog.stdout.readline().decode('ascii').strip()
        if 'found opcount' in line:
            break
        
        print(line)

        # Find out how much time has elapsed
        mat1 = elapsed_pat.search(line)
        elapsed = float(mat1.group(1))

        # Find out what the max-cost string is
        mat2 = total_pat.search(line)
        maxcost = int(mat2.group(1))

        fuzz_progress_elapsed.append(elapsed)
        fuzz_progress_maxcost.append(maxcost)

        ax.clear()
        ax.set_title('Fuzzing Progress (l={0}) {1}'.format(args.length, args.REGEXP))
        ax.set_xlabel('Seconds elapsed')
        ax.set_ylabel('Greatest known execution cost')

        ax.plot(fuzz_progress_elapsed, fuzz_progress_maxcost)
        fig.canvas.draw()
        fig.canvas.flush_events()

        # plt.plot(fuzz_progress_elapsed, fuzz_progress_maxcost)
        # plt.draw()

    prog.kill()

    input('Press enter to exit...')

if __name__ == '__main__':
    main()
