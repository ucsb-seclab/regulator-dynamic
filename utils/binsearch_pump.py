"""
Binary-search for 10s slow-down
"""

import ast
import math
import traceback
import time
import argparse
import base64
import multiprocessing
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
import scipy.stats
from sklearn.metrics import r2_score

load_dotenv()

parser = argparse.ArgumentParser()
parser.add_argument('--cores', type=str, help='Comma-separated list of cores to use (ranges okay too)')
parser.add_argument('--debug', action='store_true')

args = parser.parse_args()

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


curr = db.cursor()

# do pump results 
curr.execute(
    """
select rgf.id
from unified_regexps r
join regexps_fuzz_results rfr on rfr.regexp_id = r.id and rfr.length = 200
join regexps_guess_pump_from_fuzz3 rgf ON rgf.fuzz_result_id = rfr.id and rgf.pump_string is not null
where rgf.id not in (select guess_pump_id from regexps_guess_pump_length_results3)
    AND rgf.classifier_version = 1
order by r.id desc
""")

work_queue = curr.fetchall()
print(f'[*] {len(work_queue)} items in work queue')
global_lock = threading.Lock()

single_exec_tester = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'time_exec.js')

pat_witness_one_byte_helper = re.compile(r'\\x([0-9a-fA-F]{2})|\\\\|\\t|\\r|\\n')
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

def test_pump(
        pattern: bytes,
        flags: bytes,
        witness: str,
        char_width: int,
        pump_pos: int,
        pump_len: int,
        num_pumps: int,
        core: int
    ) -> float:
    assert pump_len > 0
    assert isinstance(num_pumps, int)
    assert num_pumps > 0

    p = subprocess.Popen(
        [
            'taskset',
            '-c', str(core),
            'node',
            single_exec_tester
        ],
        stdin = subprocess.PIPE,
        stdout = subprocess.PIPE,
    )

    obj = {
        'pattern': base64.b64encode(pattern).decode('ascii'),
        'flags': base64.b64encode(flags).decode('ascii'),
        'witness': base64.b64encode(witness).decode('ascii'),
        'char_encoding': 'latin1' if char_width == 1 else 'utf16le',
        'pump_pos': pump_pos,
        'pump_len': pump_len,
        'num_pumps': num_pumps,
        'times': 1,
    }

    json_msg = json.dumps(obj)

    p.stdin.write(json_msg.encode('ascii') + b'\n')
    p.stdin.flush()

    try:
        stdout, stderr = p.communicate(timeout=30)
        if p.poll() == -2:
            exit()
        assert stdout is not None
        if args.debug:
            print(stdout.decode('utf8'))
        for line in stdout.split(b'\n'):
            if line.startswith(b'RESULT'):
                ret = float(line[len('RESULT('):-1])
                return ret
        raise Exception('should not be reachable')
    except subprocess.TimeoutExpired as e:
        return None
    finally:
        while p.poll() is None:
            p.kill()
            time.sleep(0.1)

def test_pump_by_target_len(
        pattern: bytes,
        flags: bytes,
        witness: str,
        pump_pos: int,
        pump_len: int,
        target_len,
        core: int
    ) -> float:
    # figure out how many pumps we need to hit that target len, approximately
    approx_pumps = math.floor((target_len - len(witness) - pump_len) / pump_len)
    return test_pump(pattern, flags, witness, pump_pos, pump_len, approx_pumps, core)

def do_work():
    my_curr = db.cursor()

    while True:
        with global_lock:
            if len(work_queue) == 0:
                print('[*] work finished')
                break
            (rgf_id,) = work_queue.pop()
            my_cpu = avail_cpus.pop()

        my_curr.execute(
            """
                SELECT r.pattern, r.flags, rfr.witness, rfr.char_width, rgf.pump_string, rgf.pump_pos, rgf.pump_len
                FROM unified_regexps r
                JOIN regexps_fuzz_results rfr on rfr.regexp_id = r.id
                JOIN regexps_guess_pump_from_fuzz3 rgf on rgf.fuzz_result_id = rfr.id
                WHERE rgf.id = %s
                LIMIT 1
            """,
            (rgf_id,)
        )
        pattern, flags, witness, char_width, pump_string, pump_pos, pump_len = my_curr.fetchone()
        pattern: bytes = pattern.tobytes()
        flags: bytes = flags.tobytes()
        pump_string: bytes = pump_string.tobytes()
        foundpumps = None
        fail_reason = None
        length_for_10s = None
        exceeded_max = False
        try:
            if char_width == 1:
                witness = decode_witness_one_byte(witness)
            elif char_width == 2:
                raise NotImplementedError()
                witness = decode_witness_two_byte(witness)

            if args.debug:
                print('witness', repr(witness))
                print('pump_len', pump_len)

            tester = lambda x: test_pump(
                pattern,
                flags,
                witness,
                char_width,
                pump_pos,
                pump_len,
                x,
                my_cpu
            )
            # initial boundary setting
            MAX_LENGTH = 1_000_000
            MAX_PUMPS = math.floor((MAX_LENGTH - len(witness) - pump_len) / pump_len)
            lo = (tester(1), 1)
            hi = (tester(MAX_PUMPS), MAX_PUMPS)
            if hi[0] is not None and hi[0] < 9_900:
                exceeded_max = True
            # npumps = 100
            # hi = (tester(npumps), npumps)
            # while hi[0] is not None and hi[0] < 10_000:
            #     if args.debug:
            #         print('searching for hi, current hi =', hi)
            #     lo = hi
            #     npumps = max(npumps + 1, round(npumps * 1.5))
            #     if npumps > 200_000:
            #         exceeded_max = True
            #         break

            #     hi = (tester(npumps), npumps)

            if lo[0] is None or lo[0] > 9_900:
                length_for_10s = 200
                foundpumps = 1
            elif not exceeded_max:
                if args.debug:
                    print('begin binary search, lo =', lo, 'hi =', hi)
                foundpumps = None
                # binary search
                while hi[0] is None or lo[0] < hi[0]:
                    if args.debug:
                        print('lo', lo, 'hi', hi)
                    next_pumps = round((lo[1] + hi[1]) / 2)
                    if next_pumps == lo[1] or next_pumps == hi[1]:
                        foundpumps = next_pumps
                        break
                    nxt = tester(next_pumps)
                    if nxt is not None and abs(nxt - 10000) < 100:
                        foundpumps = next_pumps
                        break
                    if nxt is not None and nxt < 10000:
                        lo = (nxt, next_pumps)
                    else:
                        hi = (nxt, next_pumps)
                length_for_10s = 200 + (pump_len * (foundpumps - 1))
        except Exception as e:
            if isinstance(e, SystemExit):
                raise e
            traceback.print_exc()
            fail_reason = 'exception'        
        with global_lock:
            my_curr.execute(
                """
                INSERT INTO regexps_guess_pump_length_results3 (guess_pump_id, length_for_ten_s, num_pumps, fail_reason, exceeded_max_pumps)
                VALUES (%s,%s,%s,%s,%s)
                """,
                (rgf_id, length_for_10s, foundpumps, fail_reason, exceeded_max)
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
