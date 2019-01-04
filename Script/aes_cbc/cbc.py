# -*- encoding: utf-8 -*-
from Crypto.Cipher import AES
import base64
import re
import time
def exp(l):
    BS = AES.block_size  # 这个等于16
    mode = AES.MODE_CBC
    pad = lambda s: s + (BS-len(s))*"\x00"  # 用于补全key
    pad_txt = lambda s: s + (BS - len(s) % BS) * '\x00'
    unpad = lambda s : s[0:-ord(s[-1])]
    text = open("./odt-IV-8c7f55ae74a259558701876a468909df.dat",'r').read() # 加密文本
    vi = "\x8c\x7f\x55\xae\x74\xa2\x59\x55\x87\x01\x87\x6a\x46\x89\x09\xdf"   # 偏移量
    fname="./{}-{}".format(str(l*1000),str(l*1000+1000))
    def get_data_true():
        f=open(fname,"r")
        data=f.read()
        p=r'[0-9a-fA-f]{2}'
        table= re.findall(p,data)
        ntable=[]
        handle=''
        ct=0
        idx=0;
        for x in table:
            if(ct==32):
                ct=0
                ntable.append(handle)
                idx+=1;
                handle=''
            num=int("0x"+x,16)
            handle=chr(num)+handle
            ct+=1
        f.close()
        return ntable
    def get_data():
        f=open(fname,"r")
        data=f.read()
        p=r'[0-9a-fA-f]{2}'
        table= re.findall(p,data)
        ntable=[]
        handle=''
        ct=0
        idx=0;
        for x in table:
            if(ct==32):
                ct=0
                ntable.append(handle)
                idx+=1;
                handle=''
            num=int("0x"+x,16)
            handle+=chr(num)
            ct+=1
        f.close()
        return ntable

    table=get_data()
    all= len(table)
    i=0
    for x in table:
        key=x
        i+=1
        print("{}%".format(i*1.0/all*100.0))
        cryptor=AES.new(pad(key),mode, vi)
        plain_text  = cryptor.decrypt(text)
        if "\x25\x50\x44\x46" in plain_text[:5]:
            flag=open("./flag","w")
            flag.write(plain_text)
            flag.close()
            print "oopppppppppps!"
            break;
if __name__ == "__main__":
    for x in range(21,40):
        exp(x)