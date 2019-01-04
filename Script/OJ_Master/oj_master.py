#encode=utf8

from urllib import urlencode
import time
import requests
table=[]
url= "http://10.21.11.101/JudgeOnline/submit.php"
cookies={'lastlang':'1','PHPSESSID':'d4badc1e9f96a6839d62c6b6d58d2e57'}
for x in range(1063,2600):
    
    if str(x) not in table:
        try:
            f=None
            f=open("./source/"+str(x),'r')
            nice=f.read()
            payload={'s':nice}
            pay=urlencode(payload)
            id=str(x)
            data={'id':id,'language':1,'source':nice}
            newurl=url+"?"
            res=requests.post(url=url,data=data,cookies=cookies,timeout=10)
            time.sleep(3)
            print "id:" +str(id)+" is over now"
        except Exception:
            pass
        finally :
            if f: 
                f.close()
