#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <dis-asm.h>
#include <sched.h>
#include <dlfcn.h>

/* --------------------
   SUPPLEMENTAL 部分（可選） 
-------------------- */
#ifdef SUPPLEMENTAL__REWRITTEN_ADDR_CHECK
#define BM_SIZE ((1UL << 48) >> 3)
static char *bm_mem = NULL;

static void bitmap_set(char bm[], unsigned long val)
{
    bm[val >> 3] |= (1 << (val & 7));
}

static bool is_bitmap_set(char bm[], unsigned long val)
{
    return (bm[val >> 3] & (1 << (val & 7)) ? true : false);
}

static void record_replaced_instruction_addr(uintptr_t addr)
{
    assert(addr < (1UL << 48));
    bitmap_set(bm_mem, addr);
}

static bool is_replaced_instruction_addr(uintptr_t addr)
{
    assert(addr < (1UL << 48));
    return is_bitmap_set(bm_mem, addr);
}
#endif

extern void syscall_addr(void);
extern long enter_syscall(int64_t, int64_t, int64_t, int64_t, int64_t, int64_t, int64_t);
extern void asm_syscall_hook(void);

void ____asm_impl(void)
{
    asm volatile (
    ".globl enter_syscall \n\t"
    "enter_syscall: \n\t"
    "movq %rdi, %rax \n\t"
    "movq %rsi, %rdi \n\t"
    "movq %rdx, %rsi \n\t"
    "movq %rcx, %rdx \n\t"
    "movq %r8, %r10 \n\t"
    "movq %r9, %r8 \n\t"
    "movq 8(%rsp),%r9 \n\t"
    ".globl syscall_addr \n\t"
    "syscall_addr: \n\t"
    "syscall \n\t"
    "ret \n\t"
    );

    asm volatile (
    ".globl asm_syscall_hook \n\t"
    "asm_syscall_hook: \n\t"
    "cmpq $15, %rax \n\t" // rt_sigreturn
    "je do_rt_sigreturn \n\t"
    "pushq %rbp \n\t"
    "movq %rsp, %rbp \n\t"
    "andq $-16, %rsp \n\t"
    "pushq %r11 \n\t"
    "pushq %r9 \n\t"
    "pushq %r8 \n\t"
    "pushq %rdi \n\t"
    "pushq %rsi \n\t"
    "pushq %rdx \n\t"
    "pushq %rcx \n\t"
    "pushq 136(%rbp) \n\t"	// return address
    "pushq %rax \n\t"
    "pushq %r10 \n\t"
    "callq syscall_hook@plt \n\t"
    "popq %r10 \n\t"
    "addq $16, %rsp \n\t"
    "popq %rcx \n\t"
    "popq %rdx \n\t"
    "popq %rsi \n\t"
    "popq %rdi \n\t"
    "popq %r8 \n\t"
    "popq %r9 \n\t"
    "popq %r11 \n\t"
    "leaveq \n\t"
    "addq $128, %rsp \n\t"
    "retq \n\t"
    "do_rt_sigreturn:"
    "addq $136, %rsp \n\t"
    "jmp syscall_addr \n\t"
    );
}

static long (*hook_fn)(int64_t a1, int64_t a2, int64_t a3,
               int64_t a4, int64_t a5, int64_t a6,
               int64_t a7) = enter_syscall;

/* ============================================================
   以下為 ex2-1 需求：針對 write() 系統呼叫進行 leet 解碼
   ============================================================ */

// leet 轉換規則：'0'->'o', '1'->'i', '2'->'z', '3'->'e', '4'->'a', '5'->'s', '6'->'g', '7'->'t'
static void leet_decode(char *dst, const char *src, size_t n) {
    for (size_t i = 0; i < n; i++) {
        char c = src[i];
        switch(c) {
            case '0': dst[i] = 'o'; break;
            case '1': dst[i] = 'i'; break;
            case '2': dst[i] = 'z'; break;
            case '3': dst[i] = 'e'; break;
            case '4': dst[i] = 'a'; break;
            case '5': dst[i] = 's'; break;
            case '6': dst[i] = 'g'; break;
            case '7': dst[i] = 't'; break;
            default:   dst[i] = c;    break;
        }
    }
}

// 當系統呼叫為 write (syscall 編號 1) 且目標檔案描述字為 1 時，進行 leet 解碼
static long my_hook_fn(int64_t syscall_num, int64_t rdi, int64_t rsi, int64_t rdx,
                       int64_t r10, int64_t r8, int64_t r9) {
    if (syscall_num == 1 && rdi == 1) {
        size_t n = (size_t) rdx;
        char *newbuf = malloc(n);
        if (!newbuf) {
            return enter_syscall(syscall_num, rdi, rsi, rdx, r10, r8, r9);
        }
        leet_decode(newbuf, (const char *)rsi, n);
        int64_t ret = enter_syscall(syscall_num, rdi, (int64_t)newbuf, rdx, r10, r8, r9);
        free(newbuf);
        return ret;
    }
    return enter_syscall(syscall_num, rdi, rsi, rdx, r10, r8, r9);
}

/*
 * 修改 syscall_hook 以使用 hook_fn 呼叫。
 * 如果環境變數 LIBZPHOOK 未設定，則將 hook_fn 設為 my_hook_fn。
 */
long syscall_hook(int64_t rdi, int64_t rsi,
          int64_t rdx, int64_t __rcx __attribute__((unused)),
          int64_t r8, int64_t r9,
          int64_t r10_on_stack, /* 4th arg for syscall */
          int64_t rax_on_stack,
          int64_t retptr)
{
#ifdef SUPPLEMENTAL__REWRITTEN_ADDR_CHECK
    if (!is_replaced_instruction_addr(retptr - 2)) {
        asm volatile ("int3");
    }
#endif
    if (rax_on_stack == 435 /* __NR_clone3 */) {
        uint64_t *ca = (uint64_t *) rdi;
        if (ca[0] & CLONE_VM) {
            ca[6] -= sizeof(uint64_t);
            *((uint64_t *) (ca[5] + ca[6])) = retptr;
        }
    }

    if (rax_on_stack == __NR_clone) {
        if (rdi & CLONE_VM) { // pthread creation
            rsi -= sizeof(uint64_t);
            *((uint64_t *) rsi) = retptr;
        }
    }

    return hook_fn(rax_on_stack, rdi, rsi, rdx, r10_on_stack, r8, r9);
}

/* ============================================================
   以下是原始 zpoline 的反組譯與 code rewriting 部分 
   ============================================================ */
struct disassembly_state {
    char *code;
    size_t off;
};

#if defined(DIS_ASM_VER_239)
static int do_rewrite(void *data, enum disassembler_style style ATTRIBUTE_UNUSED, const char *fmt, ...)
#else
static int do_rewrite(void *data, const char *fmt, ...)
#endif
{
    struct disassembly_state *s = (struct disassembly_state *) data;
    char buf[4096];
    va_list arg;
    va_start(arg, fmt);
    vsprintf(buf, fmt, arg);
    if (strstr(buf, "(%rsp)") && !strncmp(buf, "-", 1)) {
        int32_t off;
        sscanf(buf, "%x(%%rsp)", &off);
        if (-0x78 > off && off >= -0x80) {
            //printf("\x1b[41mthis cannot be handled: %s\x1b[39m\n", buf);
            return 0;
            //assert(0);
        } else if (off < -0x80) {
            return 0;
            /* this is skipped */
        } else {
            off &= 0xff;
            {
                uint8_t *ptr = (uint8_t *)(((uintptr_t) s->code) + s->off);
                {
                    int i;
                    for (i = 0; i < 16; i++) {
                        if (ptr[i] == 0x24 && ptr[i + 1] == off) {
                            ptr[i + 1] -= 8;
                            break;
                        }
                    }
                }
            }
        }
    } else if (!strncmp(buf, "syscall", 7) || !strncmp(buf, "sysenter", 8)) {
        uint8_t *ptr = (uint8_t *)(((uintptr_t) s->code) + s->off);
        if ((uintptr_t) ptr == (uintptr_t) syscall_addr)
            goto skip;
        ptr[0] = 0xff; // callq
        ptr[1] = 0xd0; // *%rax
#ifdef SUPPLEMENTAL__REWRITTEN_ADDR_CHECK
        record_replaced_instruction_addr((uintptr_t) ptr);
#endif
    }
skip:
    va_end(arg);
    return 0;
}

static void disassemble_and_rewrite(char *code, size_t code_size, int mem_prot)
{
    struct disassembly_state s = { 0 };
    assert(!mprotect(code, code_size, PROT_WRITE | PROT_READ | PROT_EXEC));
    disassemble_info disasm_info = { 0 };
#if defined(DIS_ASM_VER_239)
    init_disassemble_info(&disasm_info, &s, (fprintf_ftype) printf, do_rewrite);
#else
    init_disassemble_info(&disasm_info, &s, do_rewrite);
#endif
    disasm_info.arch = bfd_arch_i386;
    disasm_info.mach = bfd_mach_x86_64;
    disasm_info.buffer = (bfd_byte *) code;
    disasm_info.buffer_length = code_size;
    disassemble_init_for_target(&disasm_info);
    // 修改此處：直接使用正確參數呼叫 disassembler()
    {
        disassembler_ftype disasm;
        disasm = disassembler(bfd_arch_i386, false, bfd_mach_x86_64, NULL);
        s.code = code;
        while (s.off < code_size)
            s.off += disasm(s.off, &disasm_info);
    }
    assert(!mprotect(code, code_size, mem_prot));
}

static void rewrite_code(void)
{
    FILE *fp;
    assert((fp = fopen("/proc/self/maps", "r")) != NULL);
    {
        char buf[4096];
        while (fgets(buf, sizeof(buf), fp) != NULL) {
            if (((strstr(buf, "[stack]\n") == NULL) && (strstr(buf, "[vsyscall]\n") == NULL))) {
                int i = 0;
                char addr[65] = { 0 };
                char *c = strtok(buf, " ");
                while (c != NULL) {
                    switch (i) {
                    case 0:
                        strncpy(addr, c, sizeof(addr) - 1);
                        break;
                    case 1:
                        {
                            int mem_prot = 0;
                            {
                                size_t j;
                                for (j = 0; j < strlen(c); j++) {
                                    if (c[j] == 'r')
                                        mem_prot |= PROT_READ;
                                    if (c[j] == 'w')
                                        mem_prot |= PROT_WRITE;
                                    if (c[j] == 'x')
                                        mem_prot |= PROT_EXEC;
                                }
                            }
                            if (mem_prot & PROT_EXEC) {
                                size_t k;
                                for (k = 0; k < strlen(addr); k++) {
                                    if (addr[k] == '-') {
                                        addr[k] = '\0';
                                        break;
                                    }
                                }
                                {
                                    int64_t from, to;
                                    from = strtol(&addr[0], NULL, 16);
                                    if (from == 0) {
                                        break;
                                    }
                                    to = strtol(&addr[k + 1], NULL, 16);
                                    disassemble_and_rewrite((char *) from,
                                            (size_t) to - from,
                                            mem_prot);
                                }
                            }
                        }
                        break;
                    }
                    if (i == 1)
                        break;
                    c = strtok(NULL, " ");
                    i++;
                }
            }
        }
    }
    fclose(fp);
}

#define NR_syscalls (512)

static void setup_trampoline(void)
{
    void *mem;
    mem = mmap(0, 0x1000,
            PROT_READ | PROT_WRITE | PROT_EXEC,
            MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED,
            -1, 0);
    if (mem == MAP_FAILED) {
        fprintf(stderr, "map failed\n");
        fprintf(stderr, "NOTE: /proc/sys/vm/mmap_min_addr should be set 0\n");
        exit(1);
    }

    {
        int i;
        for (i = 0; i < NR_syscalls; i++)
            ((uint8_t *) mem)[i] = 0x90;
    }

    ((uint8_t *) mem)[214] = 0xeb;
    ((uint8_t *) mem)[215] = 127;

    ((uint8_t *) mem)[NR_syscalls + 0x00] = 0x48;
    ((uint8_t *) mem)[NR_syscalls + 0x01] = 0x81;
    ((uint8_t *) mem)[NR_syscalls + 0x02] = 0xec;
    ((uint8_t *) mem)[NR_syscalls + 0x03] = 0x80;
    ((uint8_t *) mem)[NR_syscalls + 0x04] = 0x00;
    ((uint8_t *) mem)[NR_syscalls + 0x05] = 0x00;
    ((uint8_t *) mem)[NR_syscalls + 0x06] = 0x00;

    ((uint8_t *) mem)[NR_syscalls + 0x07] = 0x49;
    ((uint8_t *) mem)[NR_syscalls + 0x08] = 0xbb;
    ((uint8_t *) mem)[NR_syscalls + 0x09] = ((uint64_t) asm_syscall_hook >> 0) & 0xff;
    ((uint8_t *) mem)[NR_syscalls + 0x0a] = ((uint64_t) asm_syscall_hook >> 8) & 0xff;
    ((uint8_t *) mem)[NR_syscalls + 0x0b] = ((uint64_t) asm_syscall_hook >> 16) & 0xff;
    ((uint8_t *) mem)[NR_syscalls + 0x0c] = ((uint64_t) asm_syscall_hook >> 24) & 0xff;
    ((uint8_t *) mem)[NR_syscalls + 0x0d] = ((uint64_t) asm_syscall_hook >> 32) & 0xff;
    ((uint8_t *) mem)[NR_syscalls + 0x0e] = ((uint64_t) asm_syscall_hook >> 40) & 0xff;
    ((uint8_t *) mem)[NR_syscalls + 0x0f] = ((uint64_t) asm_syscall_hook >> 48) & 0xff;
    ((uint8_t *) mem)[NR_syscalls + 0x10] = ((uint64_t) asm_syscall_hook >> 56) & 0xff;

    ((uint8_t *) mem)[NR_syscalls + 0x11] = 0x41;
    ((uint8_t *) mem)[NR_syscalls + 0x12] = 0xff;
    ((uint8_t *) mem)[NR_syscalls + 0x13] = 0xe3;

    assert(!mprotect(0, 0x1000, PROT_EXEC));
}

static void load_hook_lib(void)
{
    const char *filename = getenv("LIBZPHOOK");
    if (!filename) {
        // 若 LIBZPHOOK 未設定，則採用內建 leet hook
        hook_fn = my_hook_fn;
        return;
    }

    void *handle;
    handle = dlmopen(LM_ID_NEWLM, filename, RTLD_NOW | RTLD_LOCAL);
    if (!handle) {
        fprintf(stderr, "dlmopen failed: %s\n\n", dlerror());
        fprintf(stderr, "NOTE: 如果使用 C++ 編譯器，請檢查是否加入 extern \"C\"。\n");
        exit(1);
    }
    {
        int (*hook_init)(long, ...);
        hook_init = dlsym(handle, "__hook_init");
        assert(hook_init);
#ifdef SUPPLEMENTAL__REWRITTEN_ADDR_CHECK
        assert(hook_init(0, &hook_fn, bm_mem) == 0);
#else
        assert(hook_init(0, &hook_fn) == 0);
#endif
    }
}

__attribute__((constructor(0xffff))) static void __zpoline_init(void)
{
#ifdef SUPPLEMENTAL__REWRITTEN_ADDR_CHECK
    assert((bm_mem = mmap(NULL, BM_SIZE,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE,
            -1, 0)) != MAP_FAILED);
#endif
    setup_trampoline();
    rewrite_code();
    load_hook_lib();
}
