# -*- coding=utf-8-*-

from Crypto.Cipher import AES
import os
from Crypto import Random
import base64


class AESUtil:

    __BLOCK_SIZE_16 = BLOCK_SIZE_16 = AES.block_size

    @staticmethod
    def encryt(str, key):
        cipher = AES.new(key, AES.MODE_ECB)
        x = AESUtil.__BLOCK_SIZE_16 - (len(str) % AESUtil.__BLOCK_SIZE_16)
        if x != 0:
            str = str + chr(0)*x
        msg = cipher.encrypt(str)
        #msg = base64.urlsafe_b64encode(msg).replace('=', '')
        return msg

    @staticmethod
    def decrypt(enStr, key):
        cipher = AES.new(key, AES.MODE_ECB)
        #enStr += (len(enStr) % 4)*"\x00"
        decryptByts = enStr
        msg = cipher.decrypt(decryptByts)
        return msg
#        paddingLen = ord(msg[len(msg)-1])
#        return msg[0:-paddingLen]

if __name__ != "__main__":
    f=open("./nier",'r').read()
    enc=AESUtil.encryt(f,"nier".ljust(16,'\x00'))
    data= AESUtil.decrypt(enc,"nier".ljust(16,'\x00'))
    L=len(f)
    data=data[:L]
    p=open("./flag",'w')
    p.write(enc)
    p.close()
if __name__ != "__main__":
    K="@ZJGSU{}I2is2016"
    payload='ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    payload+=payload.lower()
    payload+="0123456789"
    if(1):
                    f=open("N.dat",'r')
                    data=f.read()
                    nier=K.format("fb")
                    data=AESUtil.decrypt(data,nier)
                    if (1):
                        p=open("{}.pdf".format(nier),"w")
                        p.write(data)
                        p.close()
                    print "_______{}________".format(nier)
                    f.close()


def burp(K):
    for x in range(0,256):
        for y in range(0,256):
                    nier=K.format(chr(x)+chr(y))
                    f=open("N.dat",'r')
                    data=f.read()
                    data=AESUtil.decrypt(data,nier)
                    if ("\x25\x50" in data[:2]):
                        p=open("{}.pdf".format(str(x)+str((y))),"w")
                        p.write(data)
                        p.close()
                    print "[info]====={}=====".format(nier)
                    f.close()

if __name__ == "__main__":
    burp("I2is2016@ZJGSU{}")
    #burp("I2is2016{}@ZJGSU")
    #burp("I2{}is2016@ZJGSU")
    #burp("I{}2is2016@ZJGSU")
    #burp("{}I2is2016@ZJGSU")
    #burp("I2is2016@ZJGSU{}")
    #burp("I2is{}2016@ZJGSU")
    burp("ZJGSU{}I2is2016@")
    #burp("{}ZJGSUI2is2016@")
    
if __name__ != "__main__":
    K="I2is2016@ZJGSU"
    i=0;
    payload='ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
    nier=K+"SCIE"
    nier=nier.ljust(24,'\x00')
    f=open("N.dat",'r')
    data=f.read()
    data=AESUtil.decrypt(data,nier)
    p=open("{}.docx".format("nier"),"w")
    p.write(data)
    p.close()
    raw_input()
    f.close()
