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

setjmp:
    mov     rdx, rdi               ; env pointer

    ; 存 callee‑saved registers
    mov     [rdx+0 ], rbx
    mov     [rdx+8 ], rbp
    lea     rax,  [rsp]            ; current rsp
    mov     [rdx+16], rax
    mov     [rdx+24], r12
    mov     [rdx+32], r13
    mov     [rdx+40], r14
    mov     [rdx+48], r15

    ; 存 caller RIP (= stack top)
    mov     rax,  [rsp]
    mov     [rdx+56], rax

    ; 存目前 signal mask → env+64
    mov     eax, 14                ; SYS_rt_sigprocmask
    xor     edi, edi               ; how = SIG_SETMASK (查詢)
    xor     esi, esi               ; newset = NULL
    lea     rdx,  [rdx+64]         ; oldset
    mov     r10, 8                 ; sigsetsize
    syscall

    xor     eax, eax               ; 第一次回傳 0
    ret

; ------------------------------------------
;   void longjmp(jmp_buf env, int val)
; ------------------------------------------
longjmp:
    mov     r8,  rdi               ; env*
    mov     eax, esi               ; val → eax (32 位即可)
    test    eax, eax
    jne     .val_ok
    mov     eax, 1
.val_ok:
    mov     r9d, eax               ; 保留待會要回傳的值

    ; 恢復 signal mask
    mov     eax, 14                ; SYS_rt_sigprocmask
    mov     edi, 2                 ; how = SIG_SETMASK
    lea     rsi, [r8+64]           ; newset = &env->mask
    xor     edx, edx               ; oldset = NULL
    mov     r10, 8                 ; sigsetsize
    syscall

    ; 恢復 callee‑saved registers
    mov     rbx, [r8+0 ]
    mov     rbp, [r8+8 ]
    mov     r12, [r8+24]
    mov     r13, [r8+32]
    mov     r14, [r8+40]
    mov     r15, [r8+48]
    mov     rsp, [r8+16]           ; **最後** 再改 rsp

    ; 設定回傳值並跳回
    mov     rax, r9
    mov     rcx, [r8+56]           ; saved rip
    jmp     rcx                    ; 不會回來

