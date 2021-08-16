#!/usr/bin/env python3

import argparse
from asyncio.events import get_event_loop
import base64
import os
import re
import sys
import subprocess
import asyncio
import asyncio.subprocess
import logging
import logging.handlers
import io
import time
import colored
import ast

import pump
import binsearch_pump

VERSION = 1

l = logging.getLogger('main')

#
# regexps for interpreting fuzzer stdout
#

newmax_pat = re.compile(r'NEW_MAXIMIZING_ENTRY (\d+) .*?word="(.+)" Total=\d+ MaxObservation')
witness_pat = re.compile(r'SUMMARY.+? word="(.+?)" Total=(\d+) MaxObservation')
max_obs_pat = re.compile(r'SUMMARY.+? word=".+?" Total=\d+ MaxObservation=(\d+) ')
max_tot_exceeded_pat = re.compile(r'Maximum Total reached:.*?word="(.+?)" Total=(\d+) MaxObservation')


class ColoredFormatter(logging.Formatter):

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

    def format(self, record: logging.LogRecord) -> str:
        colors = {
            logging.WARN: 214,
            logging.ERROR: 1,
            logging.DEBUG: 117,
            logging.CRITICAL: 1,
            logging.FATAL: 1,
        }

        if record.levelname == 'WARNING':
            record.levelname = 'WARN'
        elif record.levelname == 'CRITICAL':
            record.levelname = 'CRIT'
        record.levelname = record.levelname.ljust(5, ' ')
        if record.levelno in colors:
            style = [colored.fg(colors[record.levelno])]
            record.levelname = colored.stylize(
                record.levelname,
                *style,
            )
        return super().format(record)


def configure_logging(log_level: int = logging.INFO, log_file: str = './log.txt'):
    """
    Setup the logging module
    """
    logger = logging.getLogger()
    if log_file is not None:
        logging.basicConfig(
            level=logging.DEBUG,
        )
        logger.handlers = []
        # set up file handler
        filehandler = logging.FileHandler(
            filename=log_file,
        )
        filehandler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
        logger.addHandler(filehandler)

    # setup colored formatter
    ch = logging.StreamHandler()
    ch.setLevel(log_level)
    formatter = ColoredFormatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    ch.setFormatter(formatter)
    logger.addHandler(ch)

def decode_witness_one_byte(s: str) -> bytes:
    s = s.replace("'", "\\'")
    s = ast.literal_eval("b'" + s + "'")
    return s

def decode_witness_two_byte(s: str) -> bytes:
    b = b''
    i = 0
    while i < len(s):
        c = s[i]
        if c == '\\' and s[i+1] == 'u':
            b1 = int(s[i+2:i+4], 16)
            b2 = int(s[i+4:i+6], 16)
            # load as little-endian
            b += bytes([b2, b1])
            i += 6
        elif c == '\\' and s[i+1] == '\\':
            b += bytes([ord('\\'), 0])
            i += 2
        elif c == '\\' and s[i+1] == 'r':
            b += bytes([ord('\r'), 0])
            i += 2
        elif c == '\\' and s[i+1] == 't':
            b += bytes([ord('\t'), 0])
            i += 2
        elif c == '\\' and s[i+1] == 'n':
            b += bytes([ord('\t'), 0])
            i += 2
        else:
            assert  ' ' <= c <= '~'
            b += bytes([ord(c), 0])
            i += 1
    return b


def main():
    #
    # Parse arguments
    #
    parser = argparse.ArgumentParser()

    parser.add_argument('--verbose', '-v', action='count', default=1, help='Noisier logging to stdout')
    parser.add_argument(
        '--log', '-l',
        type=str,
        help='Path to store log messages -- set to \'none\' for no file output (./log.txt)',
        default='./log.txt',
    )
    parser.add_argument(
        '--fuzzer-binary',
        type=str,
        help='Path to Regulator fuzzer binary (also set by REGULATOR_FUZZER env var)',
    )
    parser.add_argument(
        '--regex',
        type=str,
        help='The target regex (default: read from stdin as base64)'
    )
    parser.add_argument(
        '--flags',
        type=str,
        help='The regex flags (default: read from stdin)'
    )

    parser.add_argument(
        '--ftime',
        type=int,
        help='Maximum milliseconds to spend fuzzing',
        default=((4 * 60) * 1000),
    )

    parser.add_argument(
        '--ptime',
        type=int,
        help='Maximum milliseconds to spend pumping',
        default=((4 * 60) * 1000),
    )

    parser.add_argument(
        '--length',
        type=int,
        help='Subject string length to fuzz',
        default=200,
    )

    parser.add_argument(
        '--width',
        type=int,
        help='Byte width (1 or 2)',
        default=1,
    )

    parser.add_argument(
        '--no-binary-search',
        action='store_false',
        dest='binary_search',
        help='Do not run binary search to find string-length to get 10s slow-down'
    )

    args = parser.parse_args()
    
    #
    # setup logging infrastructure
    #

    log_level = 40 - (10*args.verbose) if args.verbose > 0 else 0
    log_file = args.log
    if log_file is None or log_file.strip().lower() == 'none':
        log_file = None

    configure_logging(log_level, log_file)

    l.debug('Booting regulator driver.')

    #
    # get the fuzzer binary info
    #
    fuzzer_binary = args.fuzzer_binary
    if fuzzer_binary is None:
        fuzzer_binary = os.getenv('REGULATOR_FUZZER', None)
        if fuzzer_binary is None:
            # still didn't figure this out; die
            l.fatal('Could not locate fuzzer binary; use either REGULATOR_FUZZER or --fuzzer-binary')
            exit(1)
    
    # ensure that fuzzer is a file
    original_fuzzer_binary = fuzzer_binary
    fuzzer_binary = os.path.abspath(fuzzer_binary)
    if not os.path.isfile(fuzzer_binary):
        l.fatal(f'Fuzzer binary does not exist: {original_fuzzer_binary} (expanded to {fuzzer_binary})')
        exit(2)
    l.debug(f'Using regulator-fuzzer at {fuzzer_binary}')

    # ensure that we can execute, and get the version number
    try:
        output = subprocess.check_output(
            [
                fuzzer_binary,
                '--version',
            ],
            encoding='utf8',
        )
    except Exception as e:
        l.fatal(f'Could not invoke fuzzer binary {fuzzer_binary}')
        exit(3)
    
    mat = re.match('Regulator v(\d+)', output)
    if not mat:
        l.fatal(f'Could not identify version of regulator fuzzer')
        exit(4)
    version = int(mat.group(1))

    l.info(f'Regulator-fuzzer version {version}')

    #
    # Get the regex & flags
    #

    if args.regex:
        bregex = args.regex.encode('utf8')
        ascii_regex = bregex.decode('ascii', errors='backslashreplace')
    else:
        b64_regex = input('Regex to analyze (as base64)\n')
        try:
            bregex = base64.b64decode(b64_regex.strip(), validate=True)
        except:
            l.fatal(f'Could not decode base64 regex')
            exit(5)
        ascii_regex = bregex.decode('ascii', errors='backslashreplace')
        l.info(f'Using regex \'{ascii_regex}\'')
    
    if args.flags is not None:
        flags = args.flags.strip().lower()
    else:
        flags = input('Flags\n').strip().lower()
        l.info(f'Using flags \'{flags}\'')
    
    #
    # Log timing info
    #

    ftime_sz = f'{(args.ftime / 1000):.2f}'
    ptime_sz = f'{(args.ptime / 1000):.2f}'
    l.info(f'Proceeding to fuzzing ({ftime_sz} s) then to pump ({ptime_sz} s)')

    time.sleep(1)

    b64_regex = base64.b64encode(bregex).decode('ascii')
    fuzzer_flags = []
    if flags.strip():
        fuzzer_flags += ['--flags', flags.strip()]
    
    witness = None
    witness_score = 0
    async def do_fuzz():
        nonlocal witness
        nonlocal witness_score
        fuzz_deadline = time.time() + args.ftime / 1000
        current_length = args.length
        maxtot = 500_000
        n_backoffs = 0
        while True:
            #
            # Start the fuzzer
            p = await asyncio.create_subprocess_exec(
                fuzzer_binary,
                '--bregexp', b64_regex,
                '--lengths', str(current_length),
                '--widths', str(args.width),
                '--timeout', str(int(args.ftime / 1000) + 30),
                '--maxtot', str(maxtot),
                *fuzzer_flags,
                stderr=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
            )
            l.debug(f'spawned fuzzer with PID={p.pid}')

            #
            # read loop over each line, respecting deadline
            # at the end of this loop the process is assumed dead
            my_witness = None
            my_witness_score = 0
            while True:
                time_remaining = fuzz_deadline - time.time()
                if time_remaining <= 0:
                    #
                    # Kill process (its over-time)
                    l.info('Fuzzing completed (time expired)')
                    p.kill()
                    while True:
                        try:
                            await asyncio.wait_for(p.wait(), 10)
                            break
                        except asyncio.TimeoutError:
                            l.debug('Fuzzing still not dead; trying kill again')
                            p.kill()
                            pass # go again
                    break
                try:
                    line: bytes = await asyncio.wait_for(p.stdout.readline(), time_remaining)
                except asyncio.TimeoutError:
                    l.debug('Timed out while waiting for read')
                    continue
                if line is None or len(line) == 0:
                    l.debug('Fuzzing completed')
                    break
                # ok, we have the line now -- decode (as utf8) and match regex
                line = line.decode('utf8')
                
                # see if it matches the early-exit max-total-exceeded
                tot_exceed_mat = max_tot_exceeded_pat.search(line)
                if tot_exceed_mat is not None:
                    # early-quit .. ensure proc is killed
                    try:
                        await asyncio.wait_for(p.wait(), 10)
                    except asyncio.TimeoutError:
                        l.fatal('exceeded shutdown wait time')
                        raise Exception('exceeded shutdown time')
                    my_witness = tot_exceed_mat.group(1)
                    my_witness_score = int(tot_exceed_mat.group(2))
                    # break from read-line loop
                    break
                
                witness_mat = witness_pat.search(line)
                if witness_mat is not None:
                    old_witness_score = my_witness_score
                    my_witness = witness_mat.group(1)
                    my_witness_score = int(witness_mat.group(2))
                    if old_witness_score < my_witness_score:
                        l.debug(f'New witness: {my_witness}')
            
            # if we exceeded max score or 
            if n_backoffs == 0 or my_witness_score >= maxtot * 0.60:
                witness = my_witness
                witness_score = my_witness_score

            # if there's time left and we bumped against the limit, back-off
            time_remaining = fuzz_deadline - time.time()
            if time_remaining > 5 and witness_score >= (maxtot * 0.95):
                old_len = current_length
                current_length = (current_length - 20) // 2 + 20
                if current_length == old_len:
                    break
                else:
                    l.info(f'Backing off [#{n_backoffs}] -- trying length {current_length}')
                    n_backoffs += 1
            else:
                break

    asyncio.run(do_fuzz())

    if witness_score <= 0:
        l.fatal('witness_score should be positive by now')
        exit(7)

    l.info(f'Starting pump with witness {witness} for {ptime_sz}')

    if args.width == 1:
        bwitness = decode_witness_one_byte(witness)
    elif args.width == 2:
        bwitness = decode_witness_two_byte(witness)
    else:
        raise Exception('unreachable')

    deadline = time.time() * 1000 + args.ptime

    pump.fuzzer_binary = fuzzer_binary
    report = pump.get_pump_report(
        bregex,
        flags.strip().encode('ascii'),
        bwitness,
        args.width,
        deadline
    )
    l.info(f'Pump completed, classed as {report["class"]}')
    if args.binary_search and ('pump_pos' in report and 'pump_len' in report):
        l.info(f'Proceeding to binary-search for 10s slow-down length')
        pl = binsearch_pump.find_limit(
            bregex,
            flags.strip().encode('ascii'),
            bwitness,
            args.width,
            report['pump_pos'],
            report['pump_len'],
        )
        print(pl)


if __name__ == '__main__':
    main()
