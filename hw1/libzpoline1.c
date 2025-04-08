#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/mman.h>
#include <unistd.h>

#define TRAMPOLINE_SIZE 4096
#define TRAMPOLINE_ADDR ((void *)0x0)

__attribute__((constructor)) void init() {
    // Step 1: mmap address 0x0
    void *addr = mmap(TRAMPOLINE_ADDR, TRAMPOLINE_SIZE,
                      PROT_READ | PROT_WRITE | PROT_EXEC,
                      MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED,
                      -1, 0);

    if (addr == MAP_FAILED) {
        perror("mmap");
        exit(1);
    }

    // Step 2: fill first 512 bytes with NOPs
    memset(addr, 0x90, 512);

    // Step 3: Write raw trampoline code to addr + 512
    unsigned char *code = (unsigned char *)addr + 512;
    int i = 0;

    // === trampoline ===
    // mov rax, 1           ; syscall number for write
    code[i++] = 0x48; code[i++] = 0xc7; code[i++] = 0xc0; code[i++] = 0x01; code[i++] = 0x00; code[i++] = 0x00; code[i++] = 0x00;

    // mov rdi, 2           ; fd = stderr
    code[i++] = 0x48; code[i++] = 0xc7; code[i++] = 0xc7; code[i++] = 0x02; code[i++] = 0x00; code[i++] = 0x00; code[i++] = 0x00;

    // lea rsi, [rip+msg]   ; load address of msg into rsi
    code[i++] = 0x48; code[i++] = 0x8d; code[i++] = 0x35;
    int rel_offset_pos = i;
    i += 4; // placeholder for relative offset

    // mov rdx, len         ; message length
    const char *msg = "Hello from trampoline!\n";
    size_t msg_len = strlen(msg);
    code[i++] = 0x48; code[i++] = 0xc7; code[i++] = 0xc2;
    code[i++] = (unsigned char)(msg_len & 0xff);
    code[i++] = (unsigned char)((msg_len >> 8) & 0xff);
    code[i++] = 0x00;
    code[i++] = 0x00;

    // syscall
    code[i++] = 0x0f; code[i++] = 0x05;

    // ret
    code[i++] = 0xc3;

    // Step 4: place message string after the code
    unsigned char *msg_addr = code + i;
    strcpy((char *)msg_addr, msg);

    // Step 5: fix the relative offset in lea rsi, [rip+msg]
    int32_t rel = (int32_t)(msg_addr - (code + rel_offset_pos + 4));
    memcpy(code + rel_offset_pos, &rel, sizeof(int32_t));

    // Step 6: test trampoline
    int offsets[] = {0, 177, 285, 326, 511};
    for (int j = 0; j < sizeof(offsets)/sizeof(int); j++) {
        int offset = offsets[j];
        printf("Trying to call function at address: %d\n", offset);
        void (*fptr)() = (void (*)())((char *)addr + offset);
        fptr(); // should print message
        //printf("\n");
    }
}
