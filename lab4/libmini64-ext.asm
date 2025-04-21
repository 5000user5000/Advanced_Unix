%include "libmini.inc"

section .data
    align 8
lc_rand_const:    dq 6364136223846793005    ; LCG multiplier constant

section .bss
    align 8
seed:   resq 1                       ; global seed

section .text
    global time, srand, grand, rand
    global sigemptyset, sigfillset, sigaddset, sigdelset, sigismember, sigprocmask
    global setjmp, longjmp

; time
time:
    sub     rsp, 24
    lea     rdi, [rsp+8]
    xor     rsi, rsi
    call    sys_gettimeofday    wrt ..plt
    mov     rax, [rsp+8]
    add     rsp, 24
    ret

; srand
srand:
    mov     rax, rdi
    sub     rax, 1
    mov     [rel seed], rax
    ret

; grand
grand:
    mov     rax, [rel seed]
    ret

; rand
rand:
    mov     rax, [rel seed]
    mov     rcx, [rel lc_rand_const]
    mul     rcx
    add     rax, 1
    mov     [rel seed], rax
    shr     rax, 33
    ret

; sigemptyset
sigemptyset:
    mov     qword [rdi], 0
    xor     eax, eax
    ret

; sigfillset
sigfillset:
    mov     rax, 0xffffffff
    mov     [rdi], rax
    xor     eax, eax
    ret

; sigaddset
sigaddset:
    cmp     rsi, 1
    jl      sigadd_err
    cmp     rsi, 32
    jg      sigadd_err
    mov     rax, [rdi]
    mov     rcx, rsi
    dec     rcx
    bts     rax, rcx
    mov     [rdi], rax
    xor     eax, eax
    ret
sigadd_err:
    mov     eax, -1
    ret

; sigdelset
sigdelset:
    cmp     rsi, 1
    jl      sigdel_err
    cmp     rsi, 32
    jg      sigdel_err
    mov     rax, [rdi]
    mov     rcx, rsi
    dec     rcx
    btr     rax, rcx
    mov     [rdi], rax
    xor     eax, eax
    ret
sigdel_err:
    mov     eax, -1
    ret

; sigismember
sigismember:
    cmp     rsi, 1
    jl      sigism_err
    cmp     rsi, 32
    jg      sigism_err
    mov     rax, [rdi]
    mov     rcx, rsi
    dec     rcx
    bt      rax, rcx
    setc    al
    movzx   eax, al
    ret
sigism_err:
    mov     eax, -1
    ret

; sigprocmask
sigprocmask:
    mov     rax, 14
    mov     rdi, rdi
    mov     rsi, rsi
    mov     rdx, rdx
    mov     r10, 8
    syscall
    ret

; setjmp
setjmp:
    mov     rdx, rdi               ; env pointer
    mov     qword [rdx    ], rbx     ; reg[0] = rbx
    mov     qword [rdx+  8], rsp   ; reg[1] = RSP
    mov     qword [rdx+ 16], rbp   ; reg[2] = RBP
    mov     qword [rdx+ 24], r12   ; reg[3] = R12
    mov     qword [rdx+ 32], r13   ; reg[4] = R13
    mov     qword [rdx+ 40], r14   ; reg[5] = R14
    mov     qword [rdx+ 48], r15   ; reg[6] = R15
    ; mov     rcx, [rsp]
    ; mov     [rdx+56], rcx
    call    .Lsj_ret
.Lsj_ret:
    ; pop     rcx
    mov     qword [rdx+ 56], rcx   ; reg[7] = RIP
    ; save signal mask
    mov     rax, 14                 ; rt_sigprocmask
    mov     rdi, 0                  ; SIG_SETMASK
    xor     rsi, rsi                ; newset = NULL
    lea     rdx, [rdx+64]           ; oldset = &env->mask
    mov     r10, 8                  ; sigset size
    syscall
    xor     eax, eax                ; return 0
    ret

; longjmp
longjmp:
    mov     r8, rdi                 ; env pointer
    mov     rax, rsi                ; val
    test    rax, rax
    jnz     .Llj_val
    mov     rax, 1
.Llj_val:
    mov     qword [r8    ], rax     ; env->reg[0]
    ; restore signal mask
    mov     rax, 14
    mov     rdi, 2                  ; SIG_SETMASK
    lea     rsi, [r8+64]            ; newset = &env->mask
    xor     rdx, rdx                ; oldset = NULL
    mov     r10, 8                  ; sigset size
    syscall
    ; restore stack pointer and callee-saved registers
    mov     rsp, [r8+  8]
    mov     rbp, [r8+ 16]
    mov     r12, [r8+ 24]
    mov     r13, [r8+ 32]
    mov     r14, [r8+ 40]
    mov     r15, [r8+ 48]
    mov     rcx, [r8+ 56]           ; RIP
    jmp     rcx                     ; jump back

