#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import zlib
import base64
import itertools
from pwn import *
from solpow import solve_pow

def recv_msg():
    """
    接收 server 發送的消息。
    格式：
      base64( [4-byte length (big-endian)] + zlib.compress(message) )
    如果解壓后内容為文本，則返回字符串；
    如果反饋數據（格式：4-byte a + b'A' + 4-byte b + b'B'），返回 bytes。
    """
    raw = r.recvline().strip()
    # 如果消息带有 server 的包圍標記 ">>> ... <<<"，則去除
    if raw.startswith(b'>>>') and raw.endswith(b'<<<'):
        raw = raw[4:-4].strip()
    try:
        decoded = base64.b64decode(raw)
        msg_len = int.from_bytes(decoded[:4], 'big')
        if len(decoded[4:]) != msg_len:
            print("[-] ERROR: Received truncated data!")
            return None
        data = zlib.decompress(decoded[4:])
        try:
            text = data.decode()
            # 如果數據長度為9或10且存在不可打印字符，則視為反饋數據，返回原始 bytes
            if (len(data) in (9, 10)) and not all(32 <= b < 127 for b in data):
                return data
            return text
        except UnicodeDecodeError:
            return data
    except Exception as e:
        print(f"[-] ERROR in recv_msg(): {e}")
        return None

def send_msg(message):
    """
    發送消息给 server。
    客户端發送時，將消息先使用 zlib.compress() 壓缩，
    然後在前面附加 4 字節的長度（little-endian），再 base64 编碼後發送。
    """
    zm = zlib.compress(message.encode())
    mlen = len(zm)
    encoded = base64.b64encode(mlen.to_bytes(4, 'little') + zm).decode()
    r.sendline(encoded)

def compute_feedback(guess, candidate):
    """
    根據 server 規則計算反饋：
      a：位置與數字均正確的個數；
      b：數字正確但位置錯誤的個數。
    """
    a = sum(1 for i in range(4) if guess[i] == candidate[i])
    b = sum(1 for c in guess if c in candidate) - a
    return a, b

def filter_candidates(candidates, guess, a_target, b_target):
    """
    根據本次猜測獲得的反饋過濾候選集合，
    只保留與該反饋匹配的候選答案。
    """
    return [cand for cand in candidates if compute_feedback(guess, cand) == (a_target, b_target)]

# 連接 server：
# 若傳入參數 "remote"，則連接遠端 server；否則使用本地進程（guess.dist.py）
if len(sys.argv) > 1 and sys.argv[1] == "remote":
    r = remote('up.zoolab.org', 10155)
    solve_pow(r)
else:
    r = process('./guess.dist.py', shell=False)

# 接收並顯示歡迎消息（MSG0）
welcome = recv_msg()
print("[Server]:", welcome)

# 初始化候選集合：所有 4 位不重複數字
candidates = [''.join(p) for p in itertools.permutations("0123456789", 4)]
attempt = 0

while attempt < 10 and candidates:
    # 首先接收 server 發来的提示訊息（例如 "#1 Enter your input (4 digits): "）
    prompt = recv_msg()
    print(f"[DEBUG] Prompt: {prompt!r}")
    
    # 从候選集合中選擇一个猜測（此處簡單取第一個，可改進策略）
    guess = candidates[0]
    attempt += 1
    print(f"[*] Attempt {attempt}: Guessing {guess}")
    
    # 發送猜測
    send_msg(guess)
    
    # 接收 server 返回的反饋（反饋为二進制數據：4-byte a + 'A' + 4-byte b + 'B'）
    fb = recv_msg()
    if isinstance(fb, bytes) and len(fb) >= 9:
        try:
            a_val = int.from_bytes(fb[0:4], 'big')
            b_val = int.from_bytes(fb[5:9], 'big')
        except Exception as e:
            print("[-] Error parsing feedback:", e)
            break
        print(f"[DEBUG] Feedback: {a_val}A, {b_val}B")
        if a_val == 4:
            print("[+] Correct guess!")
            follow = recv_msg()
            print(f"[DEBUG] Followup: {follow}")
            break
    else:
        print("[-] Unexpected feedback format:", fb)
        break
    
    # 接收 server 跟進消息，可能為 MSG1/MSG2/MSG3，或其他附加訊息（如遠端的 ASCII 藝術横幅）
    follow = recv_msg()
    print(f"[DEBUG] Followup: {follow}")
    
    # 如果跟進消息以 "MSG" 開頭，則按協議處理；否则打印後忽略
    if isinstance(follow, str) and follow.startswith("MSG"):
        if follow.startswith("MSG1"):
            print("[+] Server indicates correct answer!")
            break
        elif follow.startswith("MSG2"):
            # 繼續猜測，根據反饋過濾候選集合
            candidates = filter_candidates(candidates, guess, a_val, b_val)
            print(f"[DEBUG] Candidates remaining: {len(candidates)}")
        elif follow.startswith("MSG3"):
            print("[-] Game over, no more attempts!")
            break
        else:
            print("[-] Unknown followup message:", follow)
            break
    else:
        # 對於遠端返回的附加 ASCII 藝術横幅等，直接打印並繼續過濾後選
        print("[DEBUG] Followup message not in expected format, ignoring.")
        candidates = filter_candidates(candidates, guess, a_val, b_val)
        print(f"[DEBUG] Candidates remaining: {len(candidates)}")

r.close()