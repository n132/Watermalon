import os,sys
binary=sys.argv[1]
port  =sys.argv[2]
print binary+":"+port
os.system("cp -rf ~/Desktop/env .")
os.system("touch ./env/bin/flag")
os.system("cp ./flag ./env/bin/flag")
os.system("cp {} ./env/bin/vul".format(binary))
os.system("cd env")
os.system('''sudo docker build -t "problem_{}" ./env/'''.format(port))
cmd='''sudo docker run -p "0.0.0.0:{}:6999" -h nier --name="problem_{}" problem_{} &'''.format(port,port,port)
print cmd
os.system(cmd)
print "======================================"
print "nc 0.0.0.0 "+port
print "======================================"


""""
os.system('''echo "#!/bin/sh" > ./env/start.sh''')
os.system('''echo "ncat -vc /home/ctf/vul -kl 6999" >> ./env/start.sh''')
os.system('''echo "/etc/init.d/xinetd start"        >> ./env/start.sh''')
os.system('''echo " sleep infinity"                 >> ./env/start.sh''')

"""
