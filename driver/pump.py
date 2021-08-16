#!/usr/bin/env python3
import json
import argparse
import sys
import os
import ast
import logging
import subprocess
import base64
import time
import typing
import select
import asyncio
import asyncio.subprocess
import numpy as np
from scipy.optimize import curve_fit
import scipy.stats
from sklearn.metrics import r2_score


l = logging.getLogger(__name__)

debug = True
fuzzer_binary = None
SINGLE_SAMPLE_LIMIT = 10
TIMEOUT = 60 * 5

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

class PathLengthSampler:
    bregexp: bytes
    bflags: bytes
    width: int
    sampler: asyncio.subprocess.Process

    def __init__(self, bregexp: bytes, bflags: bytes, width: int):
        assert width in [1, 2]
        assert isinstance(bregexp, bytes)
        assert isinstance(bflags, bytes)
        # ensure there's an event loop in this thread
        try:
            asyncio.get_event_loop()
        except RuntimeError as e:
            if 'There is no current event loop' in str(e):
                l = asyncio.new_event_loop()
                asyncio.set_event_loop(l)
            else:
                raise e
        self.bregexp = bregexp
        self.bflags = bflags
        self.width = width
        self.sampler = None

    async def _open(self):
        """
        (internal) open the path-length counter binary with stdin & stdout connected
        to pipes so we can send sample lines to count path-length
        """
        l.debug('Opening sampler')
        if self.sampler is not None and self.sampler.poll() is not None:
            self.sampler.kill()
        b64regexp = base64.b64encode(self.bregexp).decode('ascii')
        flags = self.bflags.decode('ascii')
        pargs = [
            fuzzer_binary,
            '--bregexp', b64regexp,
            *(['--flags', flags] if flags else []),
            '-w', str(self.width),
            '--maxpath', str(1_000_000_000),
            '--count-paths',
        ]
        sampler = await asyncio.subprocess.create_subprocess_exec(
            *pargs,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        try:
            await sampler.stdout.readuntil(b'feed base64 lines now\n')
            self.sampler = sampler
        except asyncio.IncompleteReadError:
            l.critical('Could not open inscount binary for regexp', self.bregexp)
            sampler.kill()
            raise Exception('Could not open inscount binary')

    async def sample_async(self, bstr: bytes) -> typing.Optional[int]:
        if self.sampler is None:
            await self._open()
        b64str = base64.b64encode(bstr)
        self.sampler.stdin.write(b64str + b'\n')
        await self.sampler.stdin.drain()
        try:
            line = await asyncio.wait_for(self.sampler.stdout.readline(), SINGLE_SAMPLE_LIMIT)
        except asyncio.TimeoutError:
            self.sampler.kill()
            self.sampler = None
            l.debug('sampler timeout')
            return -1
        line: str = line.decode('ascii')
        if not line.startswith('TOTCOUNT'):
            l.critical('not sure what do do with this line: ' + line.strip())
            raise Exception('Not sure what to do with line')
        _, ret = line.strip().split(' ')
        return int(ret)
    
    def sample(self, bstr: bytes) -> typing.Optional[int]:
        asyncio.new_event_loop()
        loop = asyncio.get_event_loop()
        future = asyncio.ensure_future(self.sample_async(bstr))
        return loop.run_until_complete(future)
    
    def kill(self):
        self.sampler.kill()

def pump_witness(witness, pump_pos, pump_len, width, times) -> bytes:
    assert pump_len <= len(witness) // width
    before = witness[: pump_pos * width]
    after = witness[(pump_pos + pump_len) * width:]
    pump = witness[pump_pos * width : (pump_pos + pump_len) * width]
    return before + (pump * times) + after

pump_locs = sorted(map(int, set(np.rint(np.linspace(10, 256, 20)))))
aux_pump_locs = [1,2,3,4]
def report_pump(sampler, width, witness, pump_pos, pump_len, deadline):
    ret = []
    my_pump_locs = list(reversed(pump_locs))
    while len(my_pump_locs) > 0:
        npumps = my_pump_locs.pop()
        if time.time() > deadline:
            return ('PUMP_TIMEOUT', pump_pos, pump_len, ret)
        pumped = pump_witness(witness, pump_pos, pump_len, width, npumps)
        path_length = sampler.sample(pumped)
        if path_length >= 0:
            ret.append((len(pumped), path_length))
        else:
            l.debug(f'Timeout at {npumps} pumps')
            if npumps not in aux_pump_locs:
                my_pump_locs = list(reversed(aux_pump_locs[:len(my_pump_locs)]))
            else:
                return ('PUMP_TIMEOUT', pump_pos, pump_len, ret)
        
    return ('FULL', pump_pos, pump_len, ret)

def pump_full_report(bregexp: bytes, bflags: bytes, witness: bytes, width: int, deadline: float):
    sampler = PathLengthSampler(bregexp, bflags, width)
    l.debug('Establishing baseline')
    baseline = sampler.sample(witness)
    assert baseline is not None
    if baseline < 0:
        l.warn('Pump baseline measurement failed')
        return ('BASELINE_TIMEOUT',)
    l.debug(f'Baseline is {baseline}')
    try:
        profiles = []
        slowest_per_char = 0
        for pump_len in range(1, len(witness) // width):
            l.debug(f'pumping substrs of length {pump_len}')
            for pump_pos in reversed(range(0, len(witness) // width - pump_len)):
                if time.time() > deadline:
                    l.info('deadline TIMEOUT')
                    return ('PARTIAL_TIMEOUT', profiles)
                pumped = pump_witness(witness, pump_pos, pump_len, width, 100)
                path_length = sampler.sample(pumped)
                if path_length < 0:
                    # timeout! report this guy
                    profiles.append(('BASE_PUMP_TIMEOUT', pump_pos, pump_len))
                slowdown = path_length - baseline
                slowdown_per_char = slowdown / pump_len
                if path_length < 0 or slowdown_per_char > slowest_per_char:
                    if path_length > 0:
                        slowest_per_char = slowdown_per_char
                    report = report_pump(sampler, width, witness, pump_pos, pump_len, deadline)
                    l.debug(f'report {report}')
                    _, _, _, pts = report
                    klass = classify([x for x, _ in pts], [y for _, y in pts])
                    profiles.append((klass, pump_pos, pump_len, pts))
                    l.debug(f'classed as {klass}')
                    if klass and ((klass[0] == 'EXPONENTIAL') or (klass[0] == 'POLYNOMIAL' and klass[-1] == True)):
                        l.debug('BREAKING EARLY')
                        l.debug(f'xs={[x for x, _ in pts]}')
                        l.debug(f'ys={[y for _, y in pts]}')
                        return ('FASTBREAK', klass, profiles)
        l.info('Finished pumping exhaustively')
        return ('DONE', profiles)
    finally:
        if sampler is not None:
            sampler.kill()

def classify(xs, ys):
    l.debug(f'xs={xs}')
    l.debug(f'ys={ys}')
    # filter out zeros
    should_break = False
    xs_new = []
    ys_new = []
    for x, y in zip(xs, ys):
        if x != 0 and y != 0:
            xs_new.append(x)
            ys_new.append(y)
    xs = xs_new
    ys = ys_new

    if len(xs) < 4:
        return ('UNKNOWN', None)

    ys_log = np.log(np.array(ys, dtype=float))
    slope, intercept, r_exp, p_exp, _ = scipy.stats.linregress(xs, ys_log)
    ys_pred = [np.exp(x * slope) * np.exp(intercept) for x in xs]
    r_sq_exp = r2_score(ys, ys_pred)
    if np.exp(slope) < 0.001:
        # probably not a great model
        r_sq_exp = 0
    # if args.debug:
    #     for x, y in zip(xs, ys):
    #         print(f'{x}\t{y}')
    #     print(f'yhat = {np.exp(intercept)} * e ^ (x {np.exp(slope)})')
    #     print('r2 = ',r_sq_exp)

    # try to class with power regression
    def func_power(x, a, b):
        return a * (x ** b)
    try:
        model, _ = curve_fit(func_power, xs, ys, p0=[1, 2])
        ys_pred = [func_power(x, model[0], model[1]) for x in xs]
        r_sq_power = r2_score(ys, ys_pred)
        pred_1m = model[0] * (100_000 ** model[1])
        if pred_1m > 1_000_000_000:
            should_break = True
    except RuntimeError as e:
        if 'Optimal parameters not found' in str(e):
            r_sq_power = 0
            model = None
        else:
            raise e

    # if power regression seemed really good, try polynomial fit
    r_sq_poly = 0
    if r_sq_power > 0.95 and round(model[1]):
        deg = round(model[1])
        model = np.polynomial.polynomial.Polynomial.fit(xs, ys, deg)
        model = model.convert()
        # if args.debug:
        #     print('model', model)
        ys_pred = [model(x) for x in xs]
        r_sq_poly = r2_score(ys, ys_pred)

    # try to class with linear regression
    _, _, r, p_lin, _ = scipy.stats.linregress(xs, ys)
    r_sq_lin = r ** 2
    if r_sq_lin > 0.9999:
        return ('LINEAR', p_lin)

    if max(r_sq_lin, r_sq_poly, r_sq_exp) > 0.95:
        if r_sq_exp > 0.95 and r_sq_exp > r_sq_poly and r_sq_exp > r_sq_lin:
            return ('EXPONENTIAL', r_sq_exp)
        if r_sq_poly > 0.95 and deg > 1 and r_sq_poly > r_sq_exp and r_sq_poly > r_sq_lin:
            return ('POLYNOMIAL', r_sq_poly, deg, model.coef[-1], should_break)
        if r_sq_exp > 0.95 and r_sq_lin > r_sq_exp and r_sq_lin > r_sq_poly:
            return ('LINEAR', p_lin)

    return ('UNKNOWN', None)

def get_pump_report(
        pattern: bytes,
        flags: str,
        witness: str, # the witness (as ASCII, will decode in the function)
        width: int,
        deadline: float,
    ):
    assert fuzzer_binary is not None # TODO make this a param
    # regularize the witness
    if width == 1:
        witness = decode_witness_one_byte(witness)
    elif width == 2:
        witness = decode_witness_two_byte(witness)
    else:
        raise Exception('unreachable')


    report = pump_full_report(
        pattern,
        flags,
        witness,
        width,
        deadline / 1000 - 1, # leave 1 second to spare
    )

    #
    # Derive what classification we have for this
    #
    klass = ('UNKNOWN',)
    if report[0] == 'BASELINE_TIMEOUT':
        klass = ('EXPONENTIAL(baseline_fail)',)
    elif report[0] == 'FASTBREAK':
        _, klass, profiles = report
        _, slowest_pump_pos, slowest_pump_len, pts = profiles[-1]
    else:
        profiles = list(report[1])
        # if any had PUMP_TIMEOUT, report that guy
        base_pump_timeout = next((p for p in profiles if p[0] == 'BASE_PUMP_TIMEOUT'), None)
        pump_timeout = next((p for p in profiles if p[0] == 'PUMP_TIMEOUT'), None)
        if base_pump_timeout is not None:
            _, slowest_pump_pos, slowest_pump_len = base_pump_timeout
            klass = ('EXPONENTIAL(pump_timeout)',)
        elif pump_timeout is not None and len(pump_timeout[3]) < 5:
            _, slowest_pump_pos, slowest_pump_len, pts = pump_timeout
            klass = ('EXPONENTIAL(pump_timeout)',)
        else:
            for newklass, _, pump_pos, pump_len, pts in profiles:
                assert newklass[0] != 'EXPONENTIAL', 'should have done fastbreak'
                if newklass[0] == 'POLYNOMIAL':
                    should_replace = (
                        klass[0] != 'POLYNOMIAL' or
                        (klass[2] < newklass[2]) or
                        (klass[2] == newklass[2] and klass[3] < newklass[3])
                    )
                    if should_replace:
                        klass = newklass
                        slowest_pump_pos = pump_pos
                        slowest_pump_len = pump_len
    ret_obj = {
        'regexp': pattern,
        'flags': flags,
        'class': klass[0],
    }
    if klass[0] != 'UNKNOWN' and klass[0] != 'EXPONENTIAL(baseline_fail)':
        ret_obj['prefix'] = witness[0:slowest_pump_pos]
        ret_obj['pump'] = witness[slowest_pump_pos:slowest_pump_pos + slowest_pump_len]
        ret_obj['suffix'] = witness[slowest_pump_pos + slowest_pump_len:]
    return ret_obj


def main():
    global fuzzer_binary
    global debug
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '--fuzzer-binary',
        type=str,
        required=False,
        help='where to find fuzzer binary',
    )
    
    parser.add_argument(
        '--witness',
        type=str,
        required=True,
        help='Seed for pumping'
    )

    parser.add_argument(
        '--bregexp',
        type=str,
        required=True,
        help='base64-encoded regexp',
    )

    parser.add_argument(
        '--flags',
        type=str,
        default='',
        help='regexp flags'
    )

    parser.add_argument(
        '--width',
        type=int,
        required=True,
        help='byte-width (1 or 2)'
    )

    parser.add_argument(
        '--deadline',
        type=int,
        help='Deadline in ms since epoch'
    )

    parser.add_argument(
        '--ptime',
        help='Maximum time to spend (ms)',
        type=int,
    )

    parser.add_argument(
        '-v','--verbose',
        help='More noisy logging',
        action='store_true'
    )

    args = parser.parse_args()

    assert args.width in [1,2]
    assert os.path.isfile(args.fuzzer_binary)

    if args.deadline is not None and args.ptime is not None:
        print('Cannot set both deadline and ptime', file=sys.stderr)
        parser.print_usage()
        exit(1)
    elif args.ptime is not None:
        args.deadline = time.time() * 1000 + args.ptime
    elif args.deadline is None:
        args.deadline = time.time() * 1000 + 30 * 24 * 60 * 60 * 1000 # about 1 month; default

    if args.verbose:
        debug = True
    else:
        debug = False

    if debug:
        print('Deadline in', args.deadline / 1000 - time.time(), 'seconds')

    fuzzer_binary = args.fuzzer_binary
    
    pattern = base64.b64decode(args.bregexp, validate=True)
    flags = args.flags.decode('utf8') if args.flags else b''


if __name__ == '__main__':
    main()

