touch exp.py
echo "from pwn import *" >> exp.py
echo "context.log_level='debug'" >> exp.py
echo "p=process('./')" >> exp.py
echo "gdb.attach(p,'')">> exp.py
echo "p.interactive()" >> exp.py
gedit exp.py&

