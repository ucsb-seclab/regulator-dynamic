import ast
import signal
import tempfile
import traceback
import time
import argparse
import base64
import multiprocessing
import typing
from dotenv import load_dotenv
import os
import subprocess
import re
import psycopg2
import threading
import sys
import select
import json
import numpy as np
from scipy.optimize import curve_fit
from scipy.sparse.construct import random
import scipy.stats
from sklearn.metrics import r2_score

PUMPER_VERSION = 2

load_dotenv()

parser = argparse.ArgumentParser()
parser.add_argument('--logdir', type=str, help='Path to pump logs for caching reruns', required=True)
parser.add_argument('--cores', type=str, help='Comma-separated list of cores to use (ranges okay too)')
parser.add_argument('--wait', action='store_true', help='busy-wait for more work rather than exit')
parser.add_argument('--debug', action='store_true')

args = parser.parse_args()

assert os.path.isdir(args.logdir), 'logdir must exist'

print(f'Pumper v{PUMPER_VERSION}')

avail_cpus = list(range(multiprocessing.cpu_count()))[:-2]
if args.cores is not None:
    avail_cpus = set()
    for core_desc in args.cores.split(','):
        if '-' in core_desc:
            (a, b) = core_desc.split('-')
            avail_cpus = avail_cpus.union(range(int(a), int(b)+1))
        else:
            avail_cpus.add(int(core_desc))
    avail_cpus = list(sorted(avail_cpus))

print('[*] Using CPUs:', avail_cpus)

pg_host = os.getenv("PG_HOST")
pg_port = int(os.getenv("PG_PORT").strip())
pg_db = os.getenv("PG_DB")
pg_user = os.getenv("PG_USER")
pg_pass = os.getenv("PG_PASS")

db = psycopg2.connect(
    dbname=pg_db,
    user=pg_user,
    password=pg_pass,
    host=pg_host,
    port=pg_port
)

print('[*] connected to postgresql')

TIMEOUT = 60 * 5
SINGLE_SAMPLE_LIMIT = 1

curr = db.cursor()

global_lock = threading.Lock()

stop = False
def signal_sighup(*_):
    global stop
    print('[*] caught SIGHUP; requesting quit')
    stop = True
signal.signal(signal.SIGHUP, signal_sighup)

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
            b1 = int(s[i+2:i+4], 'hex')
            b2 = int(s[i+4:i+6], 'hex')
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
            i += 2
    return b

def asciify_witness(bs):
    ret = b''
    for b in bs:
        ret += bytes([b & 0x7f])
    return ret

bin_inscount = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'inscount')
if not os.path.isfile(bin_inscount):
    print('Could not find', bin_inscount)

# get the version
v_str = subprocess.check_output([bin_inscount, '--version'])
VERSION = int(v_str.decode('ascii')[len('Regulator v'):])
print(f'[*] Pumping with regulator v{VERSION}')
time.sleep(1)


def open_inscount(core: int, bregexp: bytes, bflags: bytes, width: int) -> subprocess.Popen:
    assert isinstance(bregexp, bytes)
    assert isinstance(bflags, bytes)
    b64regexp = base64.b64encode(bregexp).decode('ascii')
    flags = bflags.decode('ascii')
    pargs = [
        'taskset',
        '-c', str(core),
        bin_inscount,
        '--bregexp', b64regexp,
        *(['--flags', flags] if flags else []),
        '-w', str(width),
        '--maxpath', str(1_000_000_000),
        '--count-paths',
    ]
    ret = subprocess.Popen(
        pargs,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    b = b''
    while b'\n' not in b:
        b += ret.stdout.read(1)
    if b'feed base64 lines now' in b:
        return ret
    else:
        if args.debug:
            print('Could not open inscount binary for regexp', bregexp)
        ret.kill()
        return None

def sample_inscount(
        sampler: typing.Optional[subprocess.Popen],
        core: int,
        bregexp: bytes,
        bflags: bytes,
        bstr: bytes,
        width: int
    ) -> typing.Optional[typing.Tuple[int, subprocess.Popen]]:
    if sampler is None:
        sampler = open_inscount(core, bregexp, bflags, width)
        if sampler is None:
            return None
    b64str = base64.b64encode(bstr)
    sampler.stdin.write(b64str + b'\n')
    sampler.stdin.flush()
    poll_obj = select.poll()
    poll_obj.register(sampler.stdout, select.POLLIN)
    start = time.time()
    line = b''
    while time.time() < start + SINGLE_SAMPLE_LIMIT:
        poll_result = poll_obj.poll(0)
        if poll_result:
            line = sampler.stdout.readline()
            break
        time.sleep(0.0005)
    else:
        sampler.kill()
        return (None, -1)
    line: str = line.decode('ascii')
    if not line.startswith('TOTCOUNT'):
        print('not sure what do do with this line:')
        print('\t' + line)
        return (-1, None)
    _, ret = line.strip().split(' ')
    return (sampler, int(ret))

def pump_witness(witness, pump_pos, pump_len, width, times) -> bytes:
    assert width == 1
    assert pump_len <= len(witness)
    before = witness[: pump_pos]
    after = witness[pump_pos + pump_len:]
    pump = witness[pump_pos : pump_pos + pump_len]
    return before + (pump * times) + after

pump_locs = sorted(map(int, set(np.rint(np.linspace(10, 256, 20)))))
def report_pump(core, sampler, bregexp, bflags, witness, width, pump_pos, pump_len):
    ret = []
    for npumps in pump_locs:
        pumped = pump_witness(witness, pump_pos, pump_len, width, npumps)
        sampler, path_length = sample_inscount(sampler, core, bregexp, bflags, pumped, width)
        if path_length < 0:
            return (sampler, ('PUMP_TIMEOUT', pump_pos, pump_len, ret))
        ret.append((len(pumped), path_length))
    return (sampler, ('FULL', pump_pos, pump_len, ret))

def pump_full_report(core: int, bregexp: bytes, bflags: bytes, witness: bytes, width: int):
    assert width == 1
    if args.debug:
        print('establishing baseline')
    maybe_baseline = sample_inscount(None, core, bregexp, bflags, witness, width)
    if maybe_baseline is None:
        if args.debug:
            print('Could not establish baseline for', bregexp)
        return None
    if maybe_baseline[1] < 0:
        if args.debug:
            print('Baseline failed for', bregexp)
        return ('BASELINE_TIMEOUT',)
    sampler, baseline = maybe_baseline
    try:
        profiles = []
        start = time.time()
        slowest_per_char = 1
        for pump_len in range(1, len(witness)):
            if args.debug:
                if pump_len % 20 == 0:
                    print('pumping substrs of length', pump_len)
            for pump_pos in reversed(range(0, len(witness) - pump_len)):
                pumped = pump_witness(witness, pump_pos, pump_len, width, 100)
                sampler, path_length = sample_inscount(sampler, core, bregexp, bflags, pumped, width)
                if path_length < 0:
                    # timeout! report this guy
                    profiles.append(('BASE_PUMP_TIMEOUT', pump_pos, pump_len))
                slowdown = path_length - baseline
                slowdown_per_char = slowdown / pump_len
                if slowdown_per_char > slowest_per_char:
                    # if args.debug:
                    #     print('path_length', path_length, 'slowdown', slowdown, 'baseline', baseline)
                    #     print('found new slowdown', pump_pos, pump_len, witness[pump_pos:pump_pos+pump_len])
                    slowest_per_char = slowdown_per_char
                    sampler, report = report_pump(core, sampler, bregexp, bflags, witness, width, pump_pos, pump_len)
                    _, _, _, pts = report
                    profiles.append(report)
                    if args.debug:
                        print('start', witness[:pump_pos])
                        print('pump', witness[pump_pos:pump_pos+pump_len])
                        print('end', witness[pump_pos+pump_len:])

                    klass = classify([x for x, _ in pts], [y for _, y in pts])
                    if args.debug:
                        if klass[0] == 'POLYNOMIAL' and klass[-1] == False:
                            print('NOT BREAK EARLY')
                    if klass and ((klass[0] == 'EXPONENTIAL') or (klass[0] == 'POLYNOMIAL' and klass[-1] == True)):
                        if args.debug:
                            print(klass)
                            print('BREAKING EARLY', pump_pos, pump_len, witness[pump_pos:pump_pos+pump_len])
                            for x, y in pts:
                                print(str(x) + '\t' + str(y))
                        return ('FASTBREAK', klass, profiles)
                if time.time() > start + TIMEOUT:
                    return ('PARTIAL_TIMEOUT', profiles)
        return ('DONE', profiles)
    finally:
        if sampler is not None:
            sampler.kill()


def classify(xs, ys):
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

    if len(xs) < 5:
        return ('UNKNOWN', None)

    ys_log = np.log(np.array(ys, dtype=float))
    slope, intercept, r_exp, p_exp, _ = scipy.stats.linregress(xs, ys_log)
    ys_pred = [np.exp(x * slope) * np.exp(intercept) for x in xs]
    r_sq_exp = r2_score(ys, ys_pred)
    if np.exp(slope) < 0.001:
        # probably not a great model
        r_sq_exp = 0
    if args.debug:
        for x, y in zip(xs, ys):
            print(f'{x}\t{y}')
        print(f'yhat = {np.exp(intercept)} * e ^ (x {np.exp(slope)})')
        print('r2 = ',r_sq_exp)

    # try to class with power regression
    def func_power(x, a, b):
        return a * (x ** b)
    model, _ = curve_fit(func_power, xs, ys)
    ys_pred = [func_power(x, model[0], model[1]) for x in xs]
    r_sq_power = r2_score(ys, ys_pred)

    xs_log = np.log(np.array(xs))
    pred_1m = model[0] * (100_000 ** model[1])
    if pred_1m > 1_000_000_000:
        should_break = True
        if args.debug:
            print('Predicted ', pred_1m, 'instructions at 1m chars')
            print('PREDICTION WOULD CAUSE BREAK')
            print(model)

    # if power regression seemed really good, try polynomial fit
    r_sq_poly = 0
    deg = round(model[1])
    if r_sq_power > 0.95 and deg > 1:
        model = np.polynomial.polynomial.Polynomial.fit(xs, ys, deg)
        model = model.convert()
        if args.debug:
            print('model', model)
        ys_pred = [model(x) for x in xs]
        r_sq_poly = r2_score(ys, ys_pred)

    # try to class with linear regression
    _, _, r, p_lin, _ = scipy.stats.linregress(xs, ys)
    r_sq_lin = r ** 2
    if r_sq_lin > 0.9999:
        return ('LINEAR', p_lin)

    # print('r_sq_poly', r_sq_poly)
    # print('r_sq_lin ', r_sq_lin)
    # print('r_sq_exp ', r_sq_exp)
    if max(r_sq_lin, r_sq_poly, r_sq_exp) > 0.95:
        if r_sq_exp > 0.95 and r_sq_exp > r_sq_poly and r_sq_exp > r_sq_lin:
            return ('EXPONENTIAL', r_sq_exp)
        if r_sq_poly > 0.95 and deg > 1 and r_sq_poly > r_sq_exp and r_sq_poly > r_sq_lin:
            return ('POLYNOMIAL', r_sq_poly, deg, model.coef[-1], should_break)
        if r_sq_exp > 0.95 and r_sq_lin > r_sq_exp and r_sq_lin > r_sq_poly:
            return ('LINEAR', p_lin)

    return ('UNKNOWN', None)

def do_work():
    my_curr = db.cursor()

    while not stop:
        must_wait = False
        with global_lock:
            my_curr.execute("""
                SELECT rfr.regexp_id, rfr.id
                FROM regexps_fuzz_results_perffuzz rfr
                JOIN unified_regexps r ON rfr.regexp_id = r.id
                WHERE rfr.length = 200
                    AND rfr.id not in (select fuzz_result_id from regexps_guess_pump_from_fuzz2_perffuzz where classifier_version = %s)
                order by RANDOM()
            """, (PUMPER_VERSION,))

            l = my_curr.fetchone()
            if l is None:
                # queue done
                if not args.wait:
                    print('[*] pumps all finished')
                    return
                else:
                    print('[*] waiting for work')
                    must_wait = True
            else:
                id_, rfr_id = l
                my_cpu = avail_cpus.pop()
        if must_wait:
            time.sleep(120)
            continue

        print('id =', id_, 'rfr_id =', rfr_id)
        out_log_fname = os.path.join(os.path.abspath(args.logdir), f'{rfr_id}.perffuzz.v{PUMPER_VERSION}.out')
        klass = ('UNKNOWN', None)
        slowest_pump = None
        slowest_pump_pos = None
        slowest_pump_len = None
        fail_reason = None
        baseline = -1.0
        performed_baseline = False
        witness = None
        try:
            my_curr.execute("SELECT pattern, flags FROM unified_regexps WHERE id = %s LIMIT 1", (id_,))
            pattern, flags = my_curr.fetchone()
            pattern = pattern.tobytes()
            flags = flags.tobytes()
            my_curr.execute("SELECT witness, char_width, length FROM regexps_fuzz_results_perffuzz WHERE id = %s LIMIT 1", (rfr_id,))
            (witness, char_width, l) = my_curr.fetchone()
            assert char_width in [1]

            # regularize the witness)
            witness = asciify_witness(witness.tobytes())
            assert len(witness) <= l
            if args.debug:
                print('pumping', pattern, flags)
                print('witness', witness)
            if not os.path.exists(out_log_fname + '.tar.gz'):

                # encode everything b64
                start = time.time()
                report = pump_full_report(
                    my_cpu,
                    pattern,
                    flags,
                    witness,
                    char_width
                )
                end = time.time()
                elapsed = end - start

                json_report = json.dumps({"elapsed": end - start, "report": report}, ensure_ascii=True)

                with tempfile.TemporaryDirectory() as tmpd:
                    fname = os.path.join(tmpd, os.path.basename(out_log_fname))
                    with open(os.path.join(tmpd, fname), mode='wb') as tmpf:
                        tmpf.write(json_report.encode('ascii'))
                    subprocess.check_call(
                        ['tar', '-czf', out_log_fname + '.tar.gz', os.path.basename(out_log_fname)],
                        cwd=tmpd,
                    )
            else:
                with tempfile.TemporaryDirectory() as tmpd:
                    subprocess.check_call(
                        ['tar', '-xzf', out_log_fname + '.tar.gz'],
                        cwd=tmpd,
                    )
                    fname = os.path.join(tmpd, os.path.basename(out_log_fname))
                    with open(fname, mode='rb') as fin:
                        json_report = fin.read()
                        report_obj = json.loads(json_report)
                        report = report_obj['report']
                        elapsed = report_obj['elapsed']

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
                    slowest_xs = []
                    slowest_ys = []
                    for status, pump_pos, pump_len, pts in profiles:
                        xs = []
                        ys = []
                        for x, y in pts:
                            xs.append(x)
                            ys.append(y)
                        newklass = classify(xs, ys)
                        if newklass[0] == 'EXPONENTIAL':
                            klass = newklass
                            slowest_pump_pos = pump_pos
                            slowest_pump_len = pump_len
                            slowest_xs = xs
                            slowest_ys = ys
                            break
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
                                slowest_xs = xs
                                slowest_ys = ys
                    for x, y in zip(slowest_xs, slowest_ys):
                        print(str(x) + '\t' + str(y))
            print('classed as', klass)
            if args.debug and klass[0] != 'UNKNOWN':
                print('pump string:', witness[slowest_pump_pos:slowest_pump_pos + slowest_pump_len])
            if not performed_baseline:
                fail_reason = 'no_baseline'
        except Exception as e:
            traceback.print_exc()
            fail_reason = 'exception'

        with global_lock:
            if args.debug:
                return
            else:
                if witness is not None and slowest_pump_pos is not None:
                    slowest_pump = witness[slowest_pump_pos:slowest_pump_pos + slowest_pump_len]
                else:
                    slowest_pump = None
                my_curr.execute(
                    "SELECT 1 FROM regexps_fuzz_results_perffuzz WHERE id=%s FOR UPDATE",
                    (rfr_id,)
                )
                # see if someone got to us first (if so, idk, discard us)
                my_curr.execute(
                    "SELECT 1 FROM regexps_guess_pump_from_fuzz2_perffuzz WHERE classifier_version = %s and fuzz_result_id = %s limit 1",
                    (PUMPER_VERSION, rfr_id,)
                )
                if my_curr.fetchone() is None:
                    my_curr.execute(
                        """
                            INSERT INTO regexps_guess_pump_from_fuzz2_perffuzz (
                                fuzz_result_id,
                                time_pumping_secs,
                                pump_string,
                                pump_pos,
                                pump_len,
                                poly_deg,
                                klass,
                                fail_reason,
                                inscount_version,
                                classifier_version,
                                used_witness
                            )
                            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                        """,
                        (rfr_id, elapsed, slowest_pump, slowest_pump_pos, slowest_pump_len, None if klass[0] != 'POLYNOMIAL' else klass[2], klass[0], fail_reason, VERSION, PUMPER_VERSION, witness),
                    )
                db.commit()
            avail_cpus.append(my_cpu)

threads = []
for i in range(len(avail_cpus)):
    print('[*] spawning thread', i+1)
    t = threading.Thread(target=do_work)
    t.start()
    threads.append(t)

for t in threads:
    try:
        t.join()
    except KeyboardInterrupt as e:
        stop = True

print('[*] done')
