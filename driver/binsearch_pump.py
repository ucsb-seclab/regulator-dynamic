"""
Binary-search for 10s slow-down
"""

import signal
import ast
import math
import traceback
import time
import argparse
import base64
import multiprocessing
import os
import subprocess
import re
import threading
import sys
import select
import asyncio
import asyncio.subprocess
import logging
import json
import numpy as np
import scipy.stats
from sklearn.metrics import r2_score

l = logging.getLogger(__name__)

# do pump results 
global_lock = threading.Lock()

single_exec_tester = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    'time_exec.js'
)

assert os.path.isfile(single_exec_tester)

class WallTimeSampler:
    sampler: asyncio.subprocess.Process
    pattern: bytes
    flags: bytes
    witness: bytes
    char_width: int
    pump_pos: int
    pump_len: int
    
    def __init__(self, pattern: bytes, flags: bytes, witness: bytes, char_width: int, pump_pos: int, pump_len: int) -> None:
        # ensure there's an event loop in this thread
        try:
            asyncio.get_event_loop()
        except RuntimeError as e:
            if 'There is no current event loop' in str(e):
                l.debug('Spawning new event loop')
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
            else:
                raise e

        assert char_width in [1,2]
        assert isinstance(witness, bytes)
        assert isinstance(pattern, bytes)
        assert isinstance(flags, bytes)

        self.sampler = None
        self.pattern = pattern
        self.flags = flags
        self.witness = witness
        self.char_width = char_width
        self.pump_pos = pump_pos
        self.pump_len = pump_len


    async def _open(self) -> None:
        """
        Open the sampler
        """
        l.debug('Opening sampler')
        if self.sampler is not None:
            l.debug('Closing existing sampler')
            self.sampler.kill()
            self.sampler = None

        p = await asyncio.subprocess.create_subprocess_exec(
            'node',
            single_exec_tester,
            stdin = subprocess.PIPE,
            stdout = subprocess.PIPE,
        )
        l.debug(f'Spawned sampler with PID={p.pid}')

        try:
            await asyncio.wait_for(p.stdout.readuntil(b'READY\n'), timeout=5)
            self.sampler = p
        except asyncio.TimeoutError:
            l.critical('Could not open sampler')
            p.kill()
            raise Exception('Could not open sampler')

    async def time_pump_async(
            self,
            num_pumps: int
        ) -> float:
        l.debug(f'Testing {num_pumps} pumps')
        if self.sampler is None:
            await self._open()
        
        assert num_pumps > 0

        obj = {
            'pattern': base64.b64encode(self.pattern).decode('ascii'),
            'flags': base64.b64encode(self.flags).decode('ascii'),
            'witness': base64.b64encode(self.witness).decode('ascii'),
            'char_encoding': 'latin1' if self.char_width == 1 else 'utf16le',
            'pump_pos': self.pump_pos,
            'pump_len': self.pump_len,
            'num_pumps': num_pumps,
            'times': 1,
        }

        json_msg = json.dumps(obj)
        self.sampler.stdin.write(json_msg.encode('ascii') + b'\n')
        await self.sampler.stdin.drain()

        try:
            await asyncio.wait_for(self.sampler.stdout.readuntil(b'WARMING_UP'), timeout=5)
            l.debug('starting warmup')
            lines = await asyncio.wait_for(self.sampler.stdout.readuntil(b'ENDRESULT'), timeout=15)
            for line in lines.decode('ascii').splitlines():
                if line.startswith('RESULT'):
                    idx_end_paren = line.index(')')
                    ret = float(line[len('RESULT('):idx_end_paren])
                    return ret
        except asyncio.TimeoutError:
            l.debug('sampler timeout')
            self.sampler.kill()
            self.sampler = None
            return float('inf')
        except asyncio.IncompleteReadError as e:
            self.sampler.kill()
            self.sampler = None
            l.critical('Sampler died')
            raise e

    async def test_pump_by_target_len_async(self, target_len: int) -> float:
        # TODO may be broken for 2-char width
        approx_pumps = math.floor((target_len - len(self.witness) // self.char_width) / self.pump_len)
        return await self.time_pump_async(approx_pumps)

    def kill(self):
        if self.sampler is not None:
            self.sampler.kill()


async def nodejs_version() -> str:
    p = await asyncio.subprocess.create_subprocess_exec(
        'node',
        '--version',
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL
    )
    stdout, _ = await p.communicate()
    return stdout.strip()


async def find_limit_async(pattern: bytes, flags: bytes, witness: bytes, char_width: int, pump_pos: int, pump_len: int) -> int:
    """
    Find the number of pumps to achieve 10s slow-down
    """
    sampler = WallTimeSampler(pattern, flags, witness, char_width, pump_pos, pump_len)
    l.debug(f'NodeJS Version = {await nodejs_version()}')
    try:
        # initial boundary setting
        MAX_LENGTH = 1_000_000
        MAX_PUMPS = math.floor((MAX_LENGTH - len(witness) - pump_len) / pump_len)
        lo = (await sampler.time_pump_async(1), 1)
        hi = (await sampler.time_pump_async(MAX_PUMPS), MAX_PUMPS)

        if lo[0] > 9_900:
            length_for_10s = len(witness) // char_width
            foundpumps = 1
        else:
            l.debug(f'begin binary search, lo = {lo}, hi= {hi}')
            foundpumps = None
            # binary search
            while hi[0] is None or lo[0] < hi[0]:
                l.debug(f'binary search lo = {lo}, hi = {hi}')
                next_pumps = round((lo[1] + hi[1]) / 2)
                if next_pumps == lo[1] or next_pumps == hi[1]:
                    foundpumps = next_pumps
                    break
                nxt = await sampler.time_pump_async(next_pumps)
                if nxt is not None and abs(nxt - 10000) < 100:
                    foundpumps = next_pumps
                    break
                if nxt is not None and nxt < 10000:
                    lo = (nxt, next_pumps)
                else:
                    hi = (nxt, next_pumps)
            length_for_10s = 200 + (pump_len * (foundpumps - 1))

        l.debug(f'Found length for 10s slow-down = {length_for_10s}')
        return length_for_10s
    finally:
        sampler.kill()

def find_limit(pattern: bytes, flags: bytes, witness: bytes, char_width: int, pump_pos: int, pump_len: int) -> int:
    loop = asyncio.get_event_loop()
    future = asyncio.ensure_future(find_limit_async(pattern, flags, witness, char_width, pump_pos, pump_len))
    return loop.run_until_complete(future)
