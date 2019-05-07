# @n132
import lief
import os
name="./main"
binary=lief.parse(name)
for x in binary.imported_symbols:
	if x.name=="printf":
		x.name="puts"
		print "[+]:printf fixed"
binary.write("patched_file")
os.system("chmod +x patched_file")
