from pwn import *

elf = ELF("./gotoku")  # 或者是 gotoku binary
print("main =", hex(elf.symbols['main']))

print(f"{'Func':<12s} {'GOT Offset':<10s} {'Symbol Offset':<10s}")
for i in range(1200):
    name = f"gop_{i+1}"
    if name in elf.got:
        print(f"{name:<12s} {elf.got[name]:<10x} {elf.symbols[name]:<10x}")
