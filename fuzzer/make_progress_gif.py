import tempfile
import os
import os.path
import subprocess
import argparse
import re
import random

best_guess_pat = re.compile(r"^1-byte.+word=\"(.+)\" Total=")

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

    # Tracks fuzz progress over time on two parallel arrays
    fuzz_best_attempts = []

    prog_args = [
        './build/fuzzer',
        '-l', str(args.length),
        '-r', args.REGEXP,
        '-t', str(args.timeout),
        '-w', str(args.byte_width)
    ]

    if args.debug:
        prog_args.append('--debug')

    prog = subprocess.Popen(
        prog_args,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    while prog.poll() is None:
        line = prog.stdout.readline().decode('ascii').strip()
        if line == '':
            continue

        if 'found opcount' in line:
            break

        print(line)

        if line.startswith('DEBUG'):
            continue

        if 'Slowest' not in line:
            continue

        mat = best_guess_pat.search(line)
        word = mat.group(1)

        if not fuzz_best_attempts or fuzz_best_attempts[-1] != word:
            fuzz_best_attempts.append(word)

        print(fuzz_best_attempts)

    with tempfile.TemporaryDirectory() as tmpdir:
        for i, guess in enumerate(fuzz_best_attempts):
            jpg_name = os.path.join(tmpdir, str(i).rjust(3, '0') + '.jpg')
            subprocess.run(
                [
                    'convert',
                    '-background', 'white',
                    '-fill', 'black',
                    '-font', 'Liberation-Mono',
                    '-pointsize', '70',
                    'label:' + guess,
                    jpg_name,
                ],
                check=True,
            )
            if i == len(fuzz_best_attempts) - 1:
                # dupe the last one a few times
                for j in range(3):
                    jpg_name = os.path.join(tmpdir, str(i + j).rjust(3, '0') + '.jpg')
                    subprocess.run(
                        [
                            'convert',
                            '-background', 'white',
                            '-fill', 'black',
                            '-font', 'Liberation-Mono',
                            '-pointsize', '70',
                            'label:' + guess,
                            jpg_name,
                        ],
                        check=True,
                    )

        fout = os.path.join(os.path.dirname(__file__), 'out.gif')

        subprocess.run(
            [
                'convert',
                '-delay', '150',
                '-loop', '0',
                '-dispose', 'previous',
                os.path.join(tmpdir, '*.jpg'),
                fout
            ],
            check=True,
        )


    input('Press enter to exit...')

if __name__ == '__main__':
    main()
