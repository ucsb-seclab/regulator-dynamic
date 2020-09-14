#!/usr/bin/python3
"""
copy_headers.py

Author: Robert McLaughlin <robert349@ucsb.edu>

Copies relevant headers from a node install to
deps/ which makes development a bit easier.
"""

import argparse
import sys
import os
import os.path
import shutil


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        '-o', '--output',
        help='Output directory',
        type=str,
        required=True
    )

    parser.add_argument(
        'NODE_SRC',
        help="The root directory of a nodejs source repository"
    )

    args = parser.parse_args()
    if not os.path.isdir(args.NODE_SRC):
        print('not a directory:', args.NODE_SRC, file = sys.stderr)
        exit(1)
    
    if not os.path.isdir(args.output):
        print('making dir ', args.output)
        os.makedirs(args.output)

    path = os.path.abspath(args.NODE_SRC)

    print('copying v8 headers from', path)

    # paths to search recursively for headers
    src_v8_paths = [
        (os.path.join(path, 'deps', 'v8', 'include'), 'v8/include'),
        (os.path.join(path, 'deps', 'v8', 'src'), 'v8/src'),
        (os.path.join(path, 'deps', 'v8', 'base'), 'v8/base'),
        (os.path.join(path, 'deps/v8/testing'), 'v8/testing'),
        (os.path.join(path, 'deps/icu-small'), 'icu-small'),
        (os.path.join(path, 'deps/v8/third_party'), 'v8/third_party'),
        (os.path.join(path, 'out/Debug/obj/gen/generate-bytecode-output-root/builtins-generated'), os.path.join('v8', 'builtins-generated')),
        (os.path.join(path, 'out/Debug/obj/gen/torque-output-root/torque-generated'), os.path.join('v8', 'torque-generated')),
    ]
    dst_path = args.output

    for src_v8_path, dst_stub in src_v8_paths:
        print(src_v8_path)
        dst_base = dst_path
        if dst_stub:
            dst_base = os.path.join(dst_path, dst_stub)
        for dirpath, dirnames, fnames in os.walk(src_v8_path):
            for fname in fnames:
                if fname.endswith('.h') or fname.endswith('.inc'):
                    src_path = os.path.join(dirpath, fname)
                    rel_path = os.path.relpath(src_path, src_v8_path)
                    this_dst_path = os.path.join(dst_base, rel_path)
                    dst_dir = os.path.dirname(this_dst_path)
                    print(src_path, '->', this_dst_path)
                    os.makedirs(dst_dir, exist_ok=True)
                    shutil.copy(src_path, this_dst_path)


if __name__ == '__main__':
    main()
