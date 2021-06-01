import argparse
import base64
import multiprocessing
import time
from dotenv import load_dotenv
import os
import signal
import subprocess
import re
import psycopg2
import threading
import sys

load_dotenv()

parser = argparse.ArgumentParser()
parser.add_argument('--cores', type=str, help='Comma-separated list of cores to use (ranges okay too)')
parser.add_argument('--logdir', type=str, help='where to store afl output dir tarballs')
parser.add_argument('--debug', action='store_true')

args = parser.parse_args()

if not os.path.isdir(args.logdir):
    print(args.logdir, 'is not a directory', file=sys.stderr)
    exit(1)
logdir: str = args.logdir

stop = False
def sighup_handler(*_):
    global stop
    print('[*] caught SIGHUP; shutting down')
    stop = True
signal.signal(signal.SIGHUP, sighup_handler)

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

fuzzer_bin_loc = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'fuzzer_stripped')

if not os.path.isfile(fuzzer_bin_loc):
    print('Could not find fuzzer at', fuzzer_bin_loc, file=sys.stderr)

# get the version
v_str = subprocess.check_output([fuzzer_bin_loc, '--version'])
VERSION = int(v_str.decode('ascii')[len('Regulator v'):])
print(f'[*] Fuzzing with regulator v{VERSION}')
time.sleep(1)

global_lock = threading.Lock()

curr1 = db.cursor()
newmax_pat = re.compile(r'NEW_MAXIMIZING_ENTRY (\d+) .*?word="(.+)" Total=\d+ MaxObservation')
tot_pat = re.compile(r'SUMMARY.+Total=(\d+) MaxObservation')
witness_pat = re.compile(r'SUMMARY.+? word="(.+?)" Total=\d+ MaxObservation')
max_obs_pat = re.compile(r'SUMMARY.+? word=".+?" Total=\d+ MaxObservation=(\d+) ')
max_tot_exceeded_witness_pat = re.compile(r'Maximum Total reached:.*?word="(.+?)" Total=\d+ MaxObservation')
max_tot_exceeded_max_obs_pat = re.compile(r'Maximum Total reached:.*?word=".+?" Total=\d+ MaxObservation=(\d+) ')
max_tot_exceeded_tot_pat = re.compile(r'Maximum Total reached:.+?Total=(\d+) MaxObservation')

def do_work():
    global stop
    print('[*] booting worker')
    my_curr = db.cursor()

    while not stop:
        with global_lock:
            my_curr.execute("""
                SELECT id, regexp_id, length, char_width, seed, fuzz_time_sec
                FROM fuzz_work_queue
                WHERE ts_taken IS NULL
                ORDER BY priority desc, RANDOM()
                LIMIT 1
                FOR UPDATE
            """)

            l = my_curr.fetchall()
            if len(l) == 0:
                # queue done
                print('[*] queue finished')
                return
            id_, regexp_id, length, char_width, seed, fuzz_time_sec = l[0]
            print('[*] working on id =', id_)
            if not args.debug:
                my_curr.execute("""
                        UPDATE fuzz_work_queue SET ts_taken = NOW()::timestamp WHERE id = %s
                    """,
                    (id_,)
                )
            db.commit()

            my_cpu = avail_cpus.pop()

        my_curr.execute("SELECT pattern, flags FROM unified_regexps WHERE id = %s", (regexp_id,))
        (pattern, flags) = my_curr.fetchone()

        sz_pattern = pattern.tobytes().decode('utf8')
        sz_flags = flags.tobytes().decode('utf8').strip()
        b64_pattern = base64.b64encode(pattern.tobytes()).decode('ascii')

        if args.debug:
            fuzz_time_sec = 10

        tot = None
        witness = None
        max_obs = None
        success = False
        reason = None
        exceeded = None
        fout_log_name = os.path.join(logdir, f'{id_}.regulator.txt')
        fout_log = open(fout_log_name + '.tmp', mode='w')
        try:
            pargs = [
                'taskset',
                '-c', str(my_cpu),
                fuzzer_bin_loc,
                '--widths',  str(char_width),
                '--lengths', str(length),
                '--timeout', str(fuzz_time_sec),
                '--seed',    str(seed),
                '--maxtot',  str(10_000_000), # four million for no reason
                '--bregexp', b64_pattern,
            ]
            if len(sz_flags) > 0:
                pargs += [
                    '--flags', sz_flags,
                ]
            if args.debug:
                print(pargs)

            stdout = None
            ts_done = None
            try:
                p1 = subprocess.run(
                    pargs,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=fuzz_time_sec + 20,
                )
                ts_done = time.time_ns()
                if p1.returncode != 0:
                    if p1.returncode == -2:
                        exit(-2)
                    reason = f'nonzero return({p1.returncode})'
                    print('returned', p1.returncode)
                    print(p1.stderr.decode('utf8'))
                else:
                    stdout = p1.stdout
            except subprocess.TimeoutExpired as e:
                ts_done = time.time_ns()
                reason = f'timeout({fuzz_time_sec + 20})'
                stdout = e.stdout

            if stdout is not None:
                success = True
                lines = stdout.decode('ascii').splitlines()
                # write to the log
                for line in lines:
                    if line.startswith('NEW_MAXIMIZING_ENTRY'):
                        mat = newmax_pat.search(line)
                        ns = int(mat.group(1))
                        word = mat.group(2)
                        fout_log.write(str(ns) + ' ' + word + '\n')
                if len(lines) > 0:
                    # see if we exceeded max total
                    exceed_max_tot_mat = max_tot_exceeded_witness_pat.search(lines[-1])
                    if exceed_max_tot_mat is not None:
                        exceeded = True
                        witness = exceed_max_tot_mat.group(1)
                        mat2 = max_tot_exceeded_tot_pat.search(lines[-1])
                        tot = int(mat2.group(1))
                        mat3 = max_tot_exceeded_max_obs_pat.search(lines[-1])
                        max_obs = int(mat3.group(1))
                        fout_log.write(str(ts_done) + ' ' + witness + '\n')
                    else:
                        exceeded = False
                        for l in lines:
                            tot_mat = tot_pat.search(l)
                            if tot_mat is not None:
                                tot = int(tot_mat.group(1))
                            witness_mat = witness_pat.search(l)
                            if witness_mat is not None:
                                witness = witness_mat.group(1)
                            max_obs_mat = max_obs_pat.search(l)
                            if max_obs_mat is not None:
                                max_obs = int(max_obs_mat.group(1))
            fout_log.write(f'# REGULATOR_VERSION {VERSION}\n')
            fout_log.close()
            os.rename(fout_log_name + '.tmp', fout_log_name)
        except Exception as e:
            fout_log.close()
            if isinstance(e, KeyboardInterrupt):
                stop = True
            else:
                if reason is None:
                    reason = 'exception'
                print('got exception', e)
        with global_lock:
            if not args.debug:
                my_curr.execute("""
                        UPDATE fuzz_work_queue SET ts_completed = NOW()::timestamp WHERE id = %s
                    """,
                    (id_,)
                )
                if success == False:
                    witness = None
                    score = None
                my_curr.execute("""
                        INSERT INTO regexps_fuzz_results
                            (regexp_id, length, char_width, fuzz_time_sec, score, witness, max_observations, fail_reason, seed, max_total_exceeded, fuzzer_version, fuzz_queue_id)
                        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                        RETURNING id
                    """,
                    (regexp_id, length, char_width, fuzz_time_sec, tot, witness, max_obs, reason, seed, exceeded, VERSION, id_),
                )
                (rfr_id,) = my_curr.fetchone()
                with open(fout_log_name, mode='a') as fout2:
                    fout2.write(f'# FUZZ_RESULT_ID {rfr_id}\n')
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

