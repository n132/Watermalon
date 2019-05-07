import lief
from pwn import *
def patch_call(file,where,aim,arch = "amd64"):
	aim = p32((end - (where + 5 )) & 0xffffffff)
	order = '\xe8'+aim#call aim
	file.patch_address(where,[ord(i) for i in order])
	binary.write("new")
binary=lief.parse("./main")
lib=lief.parse("./hook")	
segment_add = binary.add(lib.segments[0])
binary.write("new")
#raw_address=
#aim_address=
#patch_call(binary,raw_address,aim_address)
