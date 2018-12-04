#!/bin/sh
# Add your startup script
ncat -vc /home/ctf/vul -kl 6999
# DO NOT DELETE
/etc/init.d/xinetd start;
sleep infinity;
