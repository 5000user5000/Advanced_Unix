#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pwn import *
import re

context.terminal = ['tmux', 'splitw', '-h']

# --------[ addsub1 f1]-------- #
def f1(ptr):
    """
    ptr[0] : address of eax
    ptr[1] : add value
    ptr[2] : sub value
    """

    code = f"""
    mov eax, {ptr[0]}
    add eax, {ptr[1]}
    sub eax, {ptr[2]}
    """
    return code

# --------[ addsub2 f2]-------- #
def f2(ptr):
    """
    ptr[2] : val1 address
    ptr[3] : val2 address
    ptr[4] : val3 address
    ptr[5] : result address
    """

    code = f"""
    mov eax, [""" + ptr[ 2] + """]
    add eax, [""" + ptr[ 3] + """]
    sub eax, [""" + ptr[ 4] + """]
    mov [""" + ptr[5] + """], eax
    """
    return code


# --------[ Bubble Sort Solver f3]-------- #
def f3(ptr):
    """
    ptr[2] : address of a[0] (start boundary)
    ptr[11] : address of a[9] (end boundary)
    """
    code = f"""
    mov edi, {ptr[2]}    
    mov esi, {ptr[11]}  

loop_outer:
    mov ecx, edi            

    loop_inner:
        mov eax, [ecx]           
        mov ebx, [ecx + 4]     
        cmp eax, ebx
        jle no_swap
        mov [ecx], ebx
        mov [ecx + 4], eax

    no_swap:
        add ecx, 4
        cmp ecx, esi
        jl loop_inner

    sub esi, 4
    cmp edi, esi
    jl loop_outer
    """
    return code

def f4(ptr):
    code = f""" 
    mov ebx, 1
    shl ebx, 17        ; ebx = 1 << 17 = 0x00020000
    not ebx            ; ebx = 0xFFFDFFFF
    and eax, ebx       ; eax &= ~ (1 << 17)
    """
    return code

# --------[ Entry ]-------- #
if __name__ == "__main__":
    host = "up.zoolab.org"
    port = 2500

    io = remote(host, port)

    # Get the full problem description until prompt
    problem = io.recvuntil(b"Enter").decode() # problem description is before "Enter"
    print(problem)

    # Parse all 0x... addresses
    ptr = re.findall(r'0x[0-9a-fA-F]+', problem) # get all hex addresses
    # print(f"problem: {problem}")
    print(f"ptr: {ptr}")
    print(f"[+] Parsed {len(ptr)} pointers")

    # Solve and send
    #asm_code = bubble_sort_solver(ptr)
    asm_code = f1(ptr)
    
    # print(f"[+] Sending payload:\n{asm_code}")
    payload = asm_code.encode() + b"done:"

    # io.sendline(payload)
    io.sendlineafter(b'done)', payload)

    # Print response
    response = io.recvall(timeout=10).decode()
    print(response)

    io.close()
