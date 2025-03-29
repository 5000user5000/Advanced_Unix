#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pwn import *
import re

context.terminal = ['tmux', 'splitw', '-h']

# --------[ addsub1 f0]-------- #
def f0(ptr):
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

# --------[ addsub2 f1]-------- #
def f1(ptr):
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


# --------[ Bubble Sort Solver f2]-------- #
def f2(ptr):
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

def f3(ptr):
    code = f""" 
    mov ebx, 1
    shl ebx, 17        ; ebx = 1 << 17 = 0x00020000
    not ebx            ; ebx = 0xFFFDFFFF
    and eax, ebx       ; eax &= ~ (1 << 17)
    """
    return code

# --------[ dec2ascii f4]-------- #
def f4(ptr):
    """ 
    convert the value (0-9) in AL to its ASCII character
    by adding '0'.
    """
    code = f"""
    add al, '0'
    """
    return code

# --------[ dispbin f5]-------- #
def f5(ptr):
    """
    given a number in AX, store the corresponding bit string in str1.
    """
    code = f"""
    mov rdi, {ptr[3]}
    mov cx, 16
    .next_bit:
        shl ax, 1
        jc .write_bit
        mov BYTE PTR [rdi], '0'
        jmp .next
    .write_bit:
        mov BYTE PTR [rdi], '1'
    .next:
        inc rdi
        loop .next_bit
    """
    return code

# --------[eval1 f6]-------- #
def f6(ptr):
    """
    Rval = -Xval + (Yval – Zval)
    """
    code = f"""
    mov eax, 0
    sub eax, [{ptr[2]}]   ; eax = -Xval
    add eax, [{ptr[3]}]   ; eax += Yval
    sub eax, [{ptr[4]}]   ; eax -= Zval
    mov [{ptr[5]}], eax   ; store the result
    """
    return code

# --------[ isolatebit f7]-------- #
def f7(ptr):
    """
    get the value bit-11 ~ bit-5 in AX and store the result in val1
    """
    code = f"""
    mov rdi, {ptr[2]}      ; rdi = val1 
    mov bx, ax
    shr bx, 5             ; shift right 5 bits
    and bx, 0x7F         ; isolate bit-11 ~ bit-5
    mov byte ptr [rdi], bl         ; store the result in val1 
    """
    return code

# --------[leax f8 ]-------- #
def f8(ptr):
    """
    leax:
        eax = edi * 2
        ebx = edi * 3
        ecx = edi * 5
        edx = edi * 9
    """
    code = f"""
    mov eax, edi
    mov ebx, edi
    mov ecx, edi
    mov edx, edi

    imul eax, 2
    imul ebx, 3
    imul ecx, 5
    imul edx, 9
    """
    return code

# --------[loop15 f9 ]-------- #
def f9(ptr):
    """
    str1 is a string contains 15 lowercase and uppercase alphbets.
    implement a loop to convert all alplabets to lowercase,
    and store the result in str2.
    """
    code = f"""
    mov     rsi, {ptr[2]}      ; str1 address in rsi
    mov     rdi, {ptr[3]} 
    mov     rcx, 15                    ; loop counter

    .loop15:
        mov     al, byte ptr [rsi]             ; load character from str1
        cmp     al, 0x41
        jb      .store                      ; if al < 'A', store
        cmp     al, 0x5A 
        ja      .store                      ; if al > 'Z', store
        or      al, 0x20                   ; convert to lowercase
    .store:
        mov     byte ptr [rdi], al             ; store in str2
        inc     rsi                        
        inc     rdi   
        dec     rcx                     
        jnz    .loop15
    """
    return code

# --------[ math1 f10]-------- #
def f10(ptr):
    """
    math1: unsigned arithmetic
        var4 = (var1 + var2) * var3
    """
    code = f"""
    mov     rsi, {ptr[2]}          ; rsi = &var1

    mov     eax, dword ptr [rsi]          ; eax = var1 and it is uint32_t
    mov     edx, dword ptr [rsi + 4]      ; edx = var2
    add     eax, edx                      ; eax = var1 + var2

    mov     ecx, dword ptr [rsi + 8]      ; ecx = var3
    mul     ecx                           ; unsigned eax *= ecx → result in edx:eax

    ; store lower 32 bits (eax) to var4
    mov     dword ptr [rsi + 12], eax
    """
    return code

# --------[ math2 f11]-------- #
def f11(ptr):
    """
    math2: signed arithmetic
        eax = (-var1 * var2) + var3
    """
    code = f"""
    mov     rsi, {ptr[2]}              ; rsi = &var1

    ; eax = var1
    mov     eax, dword ptr [rsi]
    neg     eax                        ; eax = -var1

    ; edx = var2
    mov     edx, dword ptr [rsi + 4]
    imul    eax, edx                   ; eax = -var1 * var2

    ; ecx = var3
    mov     ecx, dword ptr [rsi + 8]
    add     eax, ecx                   ; eax = (-var1 * var2) + var3
    """
    return code

# --------[ math3 f12]-------- #
def f12(ptr):
    """
    math3: 32-bit unsigned arithmetic
        var4 = (var1 * 5) / (var2 - 3)
        note: overflowed part should be truncated
    """
    code = f"""
    mov     rsi, {ptr[2]}              ; rsi = &var1

    ; Step 1: eax = var1
    mov     eax, dword ptr [rsi]

    ; Step 2: eax = var1 * 5
    imul    eax, eax, 5                ; multiply by 5 (overflow OK)

    ; Step 3: ecx = var2 - 3
    mov     ecx, dword ptr [rsi + 4]
    sub     ecx, 3

    ; Step 4: perform unsigned division: edx:eax / ecx
    xor     edx, edx                   ; clear edx for unsigned div
    div     ecx                        ; eax = eax / ecx

    ; Step 5: store result to var4
    mov     dword ptr [rsi + 8], eax
    """
    return code

# --------[ math4 f13]-------- #
def f13(ptr):
    """
    math4: 32-bit signed arithmetic
        var4 = (var1 * -5) / (-var2 % var3)
        note: overflowed part should be truncated
    """
    code = f"""
    mov     rsi, {ptr[2]}              ; rsi = &var1

    ; Step 1: eax = var1 * -5
    mov     eax, dword ptr [rsi]
    imul    eax, eax, -5               ; eax = var1 * -5

    ; Step 2: edx = -var2
    mov     edx, dword ptr [rsi + 4]
    neg     edx                        ; edx = -var2

    ; Step 3: ecx = var3
    mov     ecx, dword ptr [rsi + 8]

    ; Step 4: edx:eax = (-var2 % var3)
    ; → put -var2 in eax, 0 in edx, then idiv var3
    mov     eax, edx                   ; eax = -var2
    cdq                                 ; sign-extend eax into edx:eax
    idiv    ecx                        ; eax = -var2 / var3, edx = remainder

    ; Step 5: now edx = (-var2 % var3)
    ; divide (var1 * -5) / edx
    ; → move earlier result of var1*-5 into eax again
    mov     eax, dword ptr [rsi]       
    imul    eax, eax, -5               ; eax = var1 * -5

    mov     ecx, edx                   ; ecx = (-var2 % var3)
    cdq                                 ; sign-extend eax into edx:eax
    idiv    ecx                        ; eax = final result

    ; Step 6: store to var4
    mov     dword ptr [rsi + 12], eax
    """
    return code

def f14(ptr):
    """
    math5: 32-bit signed arithmetic
        var3 = (var1 * -var2) / (var3 - ebx)
        note: overflowed part should be truncated
    """
    code = f"""
    mov     rsi, {ptr[2]}              ; rsi = &var1

    ; Step 1: load var1 into eax
    mov     eax, dword ptr [rsi]

    ; Step 2: load var2, negate, multiply: eax = var1 * -var2
    mov     ecx, dword ptr [rsi + 4]   ; ecx = var2
    neg     ecx                        ; ecx = -var2
    imul    eax, ecx                   ; eax = var1 * -var2

    ; Step 3: load var3 and subtract ebx to get denominator
    mov     ecx, dword ptr [rsi + 8]   ; ecx = var3
    sub     ecx, ebx                   ; ecx = var3 - ebx

    ; Step 4: signed division: (eax / ecx)
    cdq                                 ; sign-extend eax into edx:eax
    idiv    ecx                        ; eax = eax / ecx

    ; Step 5: store result back to var3
    mov     dword ptr [rsi + 8], eax
    """
    return code

def f15(ptr):
    """
    minicall: implement a minimal function call in the emulator
    """
    code = f"""
    call a
    a:
       pop rax
    """
    return code

def f16(ptr):
    """
    mulbyshift: multiply val1 by 26 and store the result in val2
    """
    code = f"""
    mov     rsi, {ptr[2]}              ; rsi = address of val1
    mov     eax, dword ptr [rsi]       ; load val1 into eax

    mov     ecx, eax                   ; temp = val1
    shl     eax, 4                     ; eax = val1 << 4 (val1 * 16)
    shl     ecx, 3                     ; ecx = val1 << 3 (val1 * 8)
    add     eax, ecx                   ; eax += val1 * 8
    mov     ecx, dword ptr [rsi]       ; reload val1
    shl     ecx, 1                     ; ecx = val1 << 1 (val1 * 2)
    add     eax, ecx                   ; eax += val1 * 2 → eax = val1 * 26

    mov     dword ptr [rsi + 4], eax   ; store result in val2
    """
    return code

def f17(ptr):
    """
    posneg: test if registers are positive or negative.
    """
    code = f"""
    mov     rsi, {ptr[2]}          ; base address = DATAADDR = 0x776000

        ; --- test eax ---
        test    eax, eax
        mov     eax, 1
        jns     .store1
        mov     eax, -1
    .store1:
        mov     dword ptr [rsi], eax

        ; --- test ebx ---
        test    ebx, ebx
        mov     eax, 1
        jns     .store2
        mov     eax, -1
    .store2:
        mov     dword ptr [rsi + 4], eax

        ; --- test ecx ---
        test    ecx, ecx
        mov     eax, 1
        jns     .store3
        mov     eax, -1
    .store3:
        mov     dword ptr [rsi + 8], eax

        ; --- test edx ---
        test    edx, edx
        mov     eax, 1
        jns     .store4
        mov     eax, -1
    .store4:
        mov     dword ptr [rsi + 12], eax
    """
    return code

def f18(ptr):
    """
    recur: implement a recursive function
    """
    code = f"""
     _start:
        mov rdi, {ptr[2]}      ; n value
        call r
        jmp exit

    r:
        cmp rdi, 1
        jl ZERO
        je ONE

        dec rdi
        push rdi
        call r
        pop rdi
        mov rcx, 2
        mul rcx                ; rax = 2 * r(n-1)
        mov rcx, rax           ; rcx = 2*r(n-1)

        dec rdi
        push rdi
        push rcx
        call r
        pop rcx
        pop rdi
        mov rbx, 3
        mul rbx                ; rax = 3 * r(n-2)

        add rax, rcx           ; rax = 2*r(n-1) + 3*r(n-2)
        ret

    ZERO:
        mov rax, 0
        ret

    ONE:
        mov rax, 1
        ret

    exit:
        nop
    """
    return code

def f19(ptr):
    """
    swapmem: swap the values in val1 and val2
    """
    code = f"""
    mov     rsi, {ptr[2]}

    ; load val1 into rax
    mov     rax, qword ptr [rsi]        ; rax = val1

    ; load val2 into rbx
    mov     rbx, qword ptr [rsi + 8]    ; rbx = val2

    ; store val2 into val1
    mov     qword ptr [rsi], rbx

    ; store val1 into val2
    mov     qword ptr [rsi + 8], rax
    """
    return code

def f20(ptr):
    """
    swapreg: swap the values in RAX and RBX
    """
    code = f"""
    mov     rcx, rax
    mov     rax, rbx
    mov     rbx, rcx
    """
    return code

def f21(ptr):
    """"
    tolower: convert the single character in val1 to uppercase and store in val2
    """
    code = f"""
    mov     rsi, {ptr[2]}

    ; load val1 char
    mov     al, byte ptr [rsi]

    ; check if it is lowercase a~z
    cmp     al, 'a'
    jb      .store       ; if < 'a'，save
    cmp     al, 'z'
    ja      .store       ; if  > 'z'，save

    ; lowercase convert to uppercase（clear bit 5）
    and     al, 0xDF      ; 'a' → 'A', 'b' → 'B', etc.

    .store:
        ; wrtie val2（DATAADDR + 1）
        mov     byte ptr [rsi + 1], al
    """
    return code

def f22(ptr):
    """
    ul+lu: convert the alphabet in CH from upper to lower or from lower to upper
    """
    code = f"""
    _start:
        xor ch, 0x20
    """
    return code


# --------[ Entry ]-------- #
if __name__ == "__main__":
    host = "up.zoolab.org"
    #port = 2522

    funcs = {
        f'{2500 + i}': eval(f'f{i}') # port: func, ex: "2500": f1 
        for i in range(23)
    }

    flags = []


    for port, solver in funcs.items():
        io = remote(host, int(port))
        # Get the full problem description until prompt
        problem = io.recvuntil(b"Enter").decode() # problem description is before "Enter"
        #print(problem)

        # Parse all 0x... addresses
        ptr = re.findall(r'0x[0-9a-fA-F]+', problem) # get all hex addresses
        # print(f"problem: {problem}")
        
        # need to get recur number need to get
        if port == "2518":
            recur_num = 0
            for line in problem.split("\n"):
                if line.find("please call") != -1:
                    recur_num = re.findall(r'\d+', line)[0]
                    # print(recur_num)
                    break
            ptr.append(recur_num)


        #print(f"ptr: {ptr}")
        #print(f"[+] Parsed {len(ptr)} pointers")

        # Solve and send
        #asm_code = f22(ptr)
        asm_code = solver(ptr)
        
        # print(f"[+] Sending payload:\n{asm_code}")
        payload = asm_code.encode() + b"done:"

        # io.sendline(payload)
        io.sendlineafter(b'done)', payload)

        # Print response
        response = io.recvall(timeout=10).decode()
        #print(response)

        # catch flag
        start_idx = response.find("FLAG: ")
        end_idx = response.find("}\n")
        flag = response[ start_idx: end_idx + 1]
        flags.append( port + ": " + flag)

        

        io.close()

for flag in flags:
        if flag.find("FLAG") == -1:
            exit( -1)
        print(flag)
