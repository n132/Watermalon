touch exp.py
echo "from pwn import *" >> exp.py
echo "#libc=ELF('/lib/x86_64-linux-gun/libc-2.23.so')">> exp.py
echo "#log.warning(hex(base))">> exp.py
echo "context.log_level='debug'" >> exp.py
echo "p=process('./')" >> exp.py
echo "gdb.attach(p,'')">> exp.py
echo "p.interactive()" >> exp.py
gedit exp.py&

